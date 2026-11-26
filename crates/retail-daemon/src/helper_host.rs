//! This device as a helper node for a server elsewhere (`retail helper
//! start`, usually on a VPS). Started again at boot until stopped.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result};
use retail_proto::DEFAULT_STUN_PORT;
use retail_proto::api::{HelperStartRequest, HelperStatus};
use retail_proto::invite::{HelperCode, encode_pin};
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Config {
    enabled: bool,
    port: Option<u16>,
    public: Option<String>,
}

pub struct HelperHost {
    dir: PathBuf,
    running: tokio::sync::Mutex<Option<(retail_control::helper::Helper, Config)>>,
    last_error: Mutex<Option<String>>,
}

impl HelperHost {
    pub fn new(state_dir: &std::path::Path) -> Self {
        HelperHost { dir: state_dir.join("helper"), running: Default::default(), last_error: Mutex::default() }
    }

    fn config(&self) -> Config {
        std::fs::read(self.dir.join("helper.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, c: &Config) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        crate::state::secure_dir(&self.dir);
        std::fs::write(self.dir.join("helper.json"), serde_json::to_vec_pretty(c)?)?;
        Ok(())
    }

    pub async fn resume(&self) {
        let c = self.config();
        if c.enabled
            && let Err(e) = self.start(&HelperStartRequest { port: c.port, public: c.public.clone() }).await
        {
            tracing::error!("could not resume the helper node: {e:#}");
            *self.last_error.lock().unwrap() = Some(format!("{e:#}"));
        }
    }

    pub async fn start(&self, req: &HelperStartRequest) -> Result<()> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
        crate::state::secure_dir(&self.dir);
        let port = req.port.unwrap_or(DEFAULT_PORT);
        let any = |p| SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, p));
        let helper = retail_control::helper::Helper::start(retail_control::helper::HelperConfig {
            data_dir: self.dir.clone(),
            listen: any(port),
            extra_listen: if port == HTTP_PORT { Vec::new() } else { vec![any(HTTP_PORT)] },
            stun_listen: any(DEFAULT_STUN_PORT),
        })
        .await
        .context("starting the helper node")?;
        let firewall = crate::firewall::allow_inbound();
        if !firewall {
            tracing::debug!("no firewall rule added for the helper node");
        }
        let config = Config { enabled: true, port: Some(port), public: req.public.clone().filter(|p| !p.trim().is_empty()) };
        self.save(&config)?;
        *running = Some((helper, config));
        *self.last_error.lock().unwrap() = None;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut c = self.config();
        c.enabled = false;
        self.save(&c)?;
        self.halt().await;
        // A server given the old code must not link again once this helps another
        let _ = std::fs::remove_dir_all(self.dir.join("tls"));
        let _ = std::fs::remove_file(self.dir.join("helper-secret"));
        Ok(())
    }

    /// Stops the helper node but keeps it enabled, for the daemon's own shutdown
    pub async fn halt(&self) {
        if let Some((h, _)) = self.running.lock().await.take() {
            h.stop().await;
            crate::firewall::release_inbound();
        }
    }

    pub async fn status(&self) -> HelperStatus {
        let running = self.running.lock().await;
        let last_error = self.last_error.lock().unwrap().clone();
        let Some((h, c)) = running.as_ref() else {
            return HelperStatus { last_error, ..Default::default() };
        };
        HelperStatus {
            running: true,
            port: Some(h.port()),
            code: Some(code(h, c)),
            linked: h.linked(),
            last_error,
        }
    }
}

/// The given public name first, then this machine's public addresses, then
/// the rest
fn code(h: &retail_control::helper::Helper, c: &Config) -> String {
    let port = h.port();
    let mut addrs: Vec<String> = Vec::new();
    if let Some(p) = &c.public {
        addrs.push(if p.contains(':') && !p.starts_with('[') && p.parse::<std::net::Ipv6Addr>().is_err() {
            p.clone()
        } else {
            match p.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, port).to_string(),
                Err(_) => format!("{}:{port}", p.trim_matches(['[', ']'])),
            }
        });
    }
    let mut ips = crate::host::lan_ips();
    ips.sort_by_key(|ip| crate::portmap::is_private(*ip));
    for ip in ips {
        let a = SocketAddr::new(ip, port).to_string();
        if !addrs.contains(&a) {
            addrs.push(a);
        }
    }
    HelperCode { addrs, pin: encode_pin(&h.pin()), secret: h.secret().to_string() }.encode()
}
