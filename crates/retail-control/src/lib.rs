//! Coordination server embedded in `retaild`, which runs it when the user
//! hosts a network. There is no web console, the host administers it through
//! the daemon's local API. Devices trust its certificate through the key hash
//! in invite codes, so no domain or certificate authority is involved.

mod db;
mod net;
pub mod reality;
mod server;
mod stun;
mod tls;
mod tunnel;
pub mod helper;

pub use tls::{BoxIo, Injector, Prefixed};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub use db::now_unix;

pub enum Tls {
    /// Plain HTTP, for tests only
    Off,
    /// Generated once and kept in the data directory. Clients pin its key
    /// through invite codes.
    SelfSigned,
}

pub struct Config {
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    /// More TCP ports served like `listen`, bound if free (port 80 for
    /// networks that let only web ports out)
    pub extra_listen: Vec<SocketAddr>,
    pub stun_listen: SocketAddr,
    /// `host:port` entries advertised to nodes. Empty means this server's host
    /// name on port 3478.
    pub stun_advertise: Vec<String>,
    pub tls: Tls,
    /// Accepted on the HTTPS port
    pub reality: Option<reality::ServerConfig>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct NodeInfo {
    pub id: i64,
    pub hostname: String,
    pub os: String,
    pub ip: std::net::Ipv4Addr,
    pub online: bool,
    pub exit_node: bool,
    pub last_seen: Option<i64>,
}

pub use db::PreauthRow as KeyInfo;

#[derive(Clone)]
pub struct StunAdvertiser(server::AppState);

impl StunAdvertiser {
    pub fn set(&self, servers: Vec<String>) {
        self.0.set_stun_servers(servers);
    }
}

/// Dropping it without [`Server::stop`] aborts the tasks without saving
/// last-seen times.
pub struct Server {
    state: server::AppState,
    pin: Option<[u8; 32]>,
    port: u16,
    stun_port: u16,
    extra_ports: Vec<u16>,
    injector: Option<Injector>,
    shutdown: Option<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Server {
    pub async fn start(cfg: Config) -> Result<Server> {
        std::fs::create_dir_all(&cfg.data_dir)
            .with_context(|| format!("creating {}", cfg.data_dir.display()))?;
        let db = db::Db::open(&cfg.data_dir.join("retail.json")).await?;
        let (tls_config, pin) = match cfg.tls {
            Tls::Off => (None, None),
            Tls::SelfSigned => {
                let (config, pin) = tls::self_signed(&cfg.data_dir.join("tls"))?;
                (Some(config), Some(pin))
            }
        };

        let state = server::AppState::new(db, cfg.stun_advertise);
        let app = server::router(state.clone()).into_make_service_with_connect_info::<tls::PeerAddr>();
        let tcp = tokio::net::TcpListener::from_std(
            net::bind_tcp(cfg.listen).with_context(|| format!("binding tcp/{}", cfg.listen))?,
        )?;
        let port = tcp.local_addr()?.port();
        let mut extra = Vec::new();
        for addr in &cfg.extra_listen {
            match net::bind_tcp(*addr).and_then(tokio::net::TcpListener::from_std) {
                Ok(l) => extra.push(l),
                Err(e) => tracing::info!("server: not listening on tcp/{addr}: {e}"),
            }
        }
        let extra_ports = extra.iter().filter_map(|l| l.local_addr().ok()).map(|a| a.port()).collect();
        let stun_sock = net::bind_udp(cfg.stun_listen).with_context(|| format!("binding udp/{}", cfg.stun_listen))?;
        let stun_port = stun_sock.local_addr()?.port();

        let (shutdown, stopped) = oneshot::channel::<()>();
        let mut tasks = Vec::new();
        let mut injector = None;
        let graceful = async move {
            let _ = stopped.await;
        };
        tasks.push(match tls_config {
            Some(config) => {
                tracing::info!("server: HTTPS on tcp/{}", cfg.listen);
                let listeners = std::iter::once(tcp).chain(extra).collect();
                let listener = tls::TlsListener::new(listeners, config, cfg.reality.map(std::sync::Arc::new))?;
                let _ = state.inject.set(listener.injector());
                injector = Some(listener.injector());
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(graceful).await {
                        tracing::error!("server stopped: {e}");
                    }
                })
            }
            None => {
                tracing::warn!("server: plain HTTP on tcp/{} (testing only)", cfg.listen);
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(tcp, app).with_graceful_shutdown(graceful).await {
                        tracing::error!("server stopped: {e}");
                    }
                })
            }
        });
        tasks.push(tokio::spawn(async move {
            if let Err(e) = stun::run(stun_sock).await {
                tracing::error!("STUN stopped: {e:#}");
            }
        }));
        Ok(Server { state, pin, port, stun_port, extra_ports, injector, shutdown: Some(shutdown), tasks })
    }

    /// Ports from [`Config::extra_listen`] that could be bound
    pub fn extra_ports(&self) -> &[u16] {
        &self.extra_ports
    }

    /// Feeds connections from elsewhere (a helper node) to the listener.
    /// `None` without TLS.
    pub fn injector(&self) -> Option<Injector> {
        self.injector.clone()
    }

    /// SHA-256 of the certificate's SPKI, which clients pin. `None` without TLS.
    pub fn pin(&self) -> Option<[u8; 32]> {
        self.pin
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stun_port(&self) -> u16 {
        self.stun_port
    }

    /// Changes the advertised STUN servers, for example once the router has
    /// reported the public address.
    pub fn stun_advertiser(&self) -> StunAdvertiser {
        StunAdvertiser(self.state.clone())
    }

    /// The key is returned once and stored only as a hash
    pub async fn create_key(&self, reusable: bool, ttl: Duration) -> Result<String> {
        self.state.db.create_preauth(reusable, ttl).await
    }

    /// Creates the named invite or gives it a new code, voiding the old one
    pub async fn set_named_key(&self, name: &str, ttl: Option<Duration>) -> Result<(i64, String)> {
        self.state.db.set_named(name, ttl).await
    }

    /// The live code of a named invite
    pub async fn named_key(&self, id: i64) -> Result<Option<String>> {
        self.state.db.named_secret(id).await
    }

    pub async fn keys(&self) -> Result<Vec<KeyInfo>> {
        self.state.db.list_preauth().await
    }

    pub async fn revoke_key(&self, id: i64) -> Result<bool> {
        self.state.db.delete_preauth(id).await
    }

    pub async fn nodes(&self) -> Result<Vec<NodeInfo>> {
        let rows = self.state.db.all_nodes().await?;
        Ok(rows
            .into_iter()
            .map(|n| NodeInfo {
                online: self.state.is_online(n.id),
                exit_node: self.state.is_exit_node(n.id),
                id: n.id,
                hostname: n.hostname,
                os: n.os,
                ip: n.ip,
                last_seen: n.last_seen,
            })
            .collect())
    }

    /// Closes the device's connection. It needs a new invite to return.
    pub async fn delete_node(&self, id: i64) -> Result<bool> {
        let deleted = self.state.db.delete_node(id).await?;
        if deleted {
            self.state.notify();
        }
        Ok(deleted)
    }

    pub async fn stop(mut self) {
        self.state.shut_down();
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Long-lived poll connections would hold a graceful shutdown open
        tokio::time::sleep(Duration::from_millis(200)).await;
        for t in &self.tasks {
            t.abort();
        }
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        self.state.db.close().await;
        tracing::info!("server stopped");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
