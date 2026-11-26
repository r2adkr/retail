//! This device as its network's helper node, when the server cannot be
//! reached from other networks (CGNAT) and an administrator picked this
//! device for it. The server asks through the netmap; this device listens,
//! opens its router's ports, and sends its helper code back over the control
//! connection. The server then links to it as it would to `retail helper
//! start` on a VPS. Stops when the server stops asking or the session ends,
//! closing the router's ports either way.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use retail_proto::DEFAULT_STUN_PORT;
use retail_proto::invite::{HelperCode, encode_pin};

use crate::engine::Engine;
use crate::portmap::{self, Proto};

/// Tried in order: the first that is free
const PORTS: [u16; 2] = [443, 8443];

/// Until `stop` turns true (the session ends)
pub async fn run(engine: Arc<Engine>, data_dir: PathBuf, mut stop: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let mut wanted = engine.subscribe_helper_role();
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        if *wanted.borrow_and_update() {
            match Role::start(&data_dir).await {
                Ok(mut role) => {
                    tracing::info!(code_addrs = ?role.addrs, "this device is the network's helper node");
                    engine.set_helper_code(Some(role.code.clone()));
                    role.serve(&mut wanted, &mut stop).await;
                    engine.set_helper_code(None);
                    role.stop().await;
                    tracing::info!("no longer the network's helper node");
                    continue;
                }
                Err(e) => {
                    tracing::warn!("cannot be the network's helper node: {e:#}");
                    engine.set_helper_code(None);
                    // Ask again later: the router may come around
                    tokio::select! {
                        r = wanted.changed() => r?,
                        _ = stop.changed() => {}
                        _ = tokio::time::sleep(Duration::from_secs(300)) => {}
                    }
                    continue;
                }
            }
        }
        tokio::select! {
            r = wanted.changed() => r?,
            _ = stop.changed() => {}
        }
    }
}

struct Role {
    helper: retail_control::helper::Helper,
    mapping: Option<portmap::Outcome>,
    code: String,
    addrs: Vec<String>,
    /// Released however the role ends, even when its task is aborted
    _inbound: crate::firewall::Inbound,
}

impl Role {
    async fn start(data_dir: &std::path::Path) -> Result<Role> {
        let any = |p| SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, p));
        let mut last = None;
        let mut helper = None;
        for port in PORTS {
            match retail_control::helper::Helper::start(retail_control::helper::HelperConfig {
                data_dir: data_dir.to_path_buf(),
                listen: any(port),
                extra_listen: Vec::new(),
                stun_listen: any(DEFAULT_STUN_PORT),
            })
            .await
            {
                Ok(h) => {
                    helper = Some(h);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let helper = match helper {
            Some(h) => h,
            None => return Err(last.unwrap_or_else(|| anyhow::anyhow!("no port"))).context("listening for the helper node"),
        };
        let port = helper.port();
        let inbound = crate::firewall::Inbound::take();
        // Ports on this device's own router, unless told to leave it alone
        let mapping = if std::env::var_os("RETAIL_NO_PORTMAP").is_none() {
            portmap::open(&[(Proto::Tcp, port), (Proto::Udp, DEFAULT_STUN_PORT)], 1).await.ok()
        } else {
            None
        };
        let mut addrs: Vec<String> = Vec::new();
        if let Some(m) = &mapping
            && let (Some(ip), Some(tcp)) = (m.external_ip, m.external(Proto::Tcp, port))
            && !portmap::is_private(ip)
        {
            addrs.push(SocketAddr::new(ip, tcp).to_string());
        }
        // Public addresses of this machine itself (a VPS, IPv6)
        for ip in crate::host::lan_ips() {
            if !portmap::is_private(ip) {
                let a = SocketAddr::new(ip, port).to_string();
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        }
        if addrs.is_empty() {
            helper.stop().await;
            if let Some(m) = &mapping {
                portmap::close(m).await;
            }
            bail!("this device has no address other networks can reach (its router opened nothing)");
        }
        let code = HelperCode { addrs: addrs.clone(), pin: encode_pin(&helper.pin()), secret: helper.secret().to_string() }.encode();
        Ok(Role { helper, mapping, code, addrs, _inbound: inbound })
    }

    /// Until the server stops asking or the session ends: keeps the router's ports open
    async fn serve(&mut self, wanted: &mut tokio::sync::watch::Receiver<bool>, stop: &mut tokio::sync::watch::Receiver<bool>) {
        loop {
            if *stop.borrow() {
                return;
            }
            tokio::select! {
                r = wanted.changed() => {
                    if r.is_err() || !*wanted.borrow_and_update() {
                        return;
                    }
                }
                _ = stop.changed() => return,
                _ = tokio::time::sleep(portmap::LEASE / 2) => {
                    if let Some(m) = &self.mapping
                        && let Ok(renewed) = portmap::renew(m, 1).await
                    {
                        // What is closed at the end is what the router has now
                        self.mapping = Some(renewed);
                    }
                }
            }
        }
    }

    async fn stop(self) {
        self.helper.stop().await;
        if let Some(m) = &self.mapping {
            portmap::close(m).await;
        }
    }
}
