//! This device's WireGuard port opened on the router (PCP, NAT-PMP or UPnP)
//! when its user allows it, so devices on other networks reach it directly
//! instead of through the relay. A device hosting the network opens it with
//! the server's ports already.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use retail_proto::api::PortState;
use tokio::sync::watch;

use crate::portmap::{self, Proto};

/// A router that refused is asked again this often
const RETRY: Duration = Duration::from_secs(300);

pub struct DevicePort {
    wanted: watch::Sender<bool>,
    state: Arc<Mutex<Option<PortState>>>,
    /// The mapped public address, a candidate for peers
    pub public: watch::Sender<Option<SocketAddr>>,
}

impl Default for DevicePort {
    fn default() -> Self {
        DevicePort {
            wanted: watch::channel(false).0,
            state: Arc::default(),
            public: watch::channel(None).0,
        }
    }
}

impl DevicePort {
    pub fn set_wanted(&self, on: bool) {
        self.wanted
            .send_if_modified(|w| std::mem::replace(w, on) != on);
    }

    pub fn state(&self) -> Option<PortState> {
        self.state.lock().unwrap().clone()
    }

    /// For one session, whose engine listens on `port`
    pub fn run(
        &self,
        port: u16,
        hosting: watch::Receiver<bool>,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let (wanted, state, public) = (
            self.wanted.subscribe(),
            self.state.clone(),
            self.public.clone(),
        );
        keep_open(port, wanted, hosting, state, public)
    }
}

/// Undoes the mapping when the session's task ends, however it ends
struct Mapped {
    outcome: Option<portmap::Outcome>,
    state: Arc<Mutex<Option<PortState>>>,
    public: watch::Sender<Option<SocketAddr>>,
}

impl Mapped {
    fn clear(&mut self) {
        *self.state.lock().unwrap() = None;
        self.public.send_replace(None);
        if let Some(o) = self.outcome.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            rt.spawn(async move { portmap::close(&o).await });
        }
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        self.clear();
    }
}

async fn keep_open(
    port: u16,
    mut wanted: watch::Receiver<bool>,
    mut hosting: watch::Receiver<bool>,
    state: Arc<Mutex<Option<PortState>>>,
    public: watch::Sender<Option<SocketAddr>>,
) {
    // Tests, or a machine with a public address, leave the router alone
    if std::env::var_os("RETAIL_NO_PORTMAP").is_some() {
        return;
    }
    let mut m = Mapped {
        outcome: None,
        state,
        public,
    };
    loop {
        if !*wanted.borrow_and_update() || *hosting.borrow_and_update() {
            m.clear();
            tokio::select! {
                r = wanted.changed() => if r.is_err() { return },
                r = hosting.changed() => if r.is_err() { return },
            }
            continue;
        }
        let result = match &m.outcome {
            Some(o) => portmap::renew(o, 1).await,
            None => portmap::open(&[(Proto::Udp, port)], 1).await,
        };
        let wait = match result {
            Ok(o) => {
                let external = o.external(Proto::Udp, port);
                if m.outcome.is_none() {
                    tracing::info!(method = o.method_name(), external_ip = ?o.external_ip, ?external, "router port opened for direct connections");
                }
                let addr = o
                    .external_ip
                    .filter(|ip| !portmap::is_private(*ip))
                    .zip(external)
                    .map(|(ip, p)| SocketAddr::new(ip, p));
                *m.state.lock().unwrap() = Some(PortState::Opened {
                    method: o.method_name().to_string(),
                    port: external.unwrap_or(port),
                });
                m.public.send_replace(addr);
                m.outcome = Some(o);
                portmap::LEASE / 2
            }
            Err(e) => {
                tracing::info!("router port for direct connections: {e:#}");
                m.outcome = None;
                *m.state.lock().unwrap() = Some(PortState::Unavailable { port });
                m.public.send_replace(None);
                RETRY
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            r = wanted.changed() => if r.is_err() { return },
            r = hosting.changed() => if r.is_err() { return },
        }
    }
}
