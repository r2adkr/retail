//! Helper node: a public machine (a VPS) that makes a server behind CGNAT
//! reachable. The server keeps a link to it, and the helper hands every
//! connection it receives to the server over a fresh connection the server
//! opens on request, bytes untouched. TLS, REALITY and tunnels still end at
//! the server, so the helper never sees inside. It also answers STUN.
//!
//! The server's own connections name [`LINK_NAME`] as SNI and authenticate
//! with the helper's secret inside the helper's TLS:
//! - `CTRL <secret>`: the link. The helper writes `OPEN <id> <client addr>` per
//!   client and `PING` now and then.
//! - `WORK <secret> <id>`: the connection that carries client `id`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::tls::BoxIo;

/// SNI of the server's own connections to its helper
pub const LINK_NAME: &str = "link.retail.invalid";
/// How long a client waits for the server to pick it up
const PICKUP: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(20);
const MAX_PENDING: usize = 256;

pub struct HelperConfig {
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    pub extra_listen: Vec<SocketAddr>,
    pub stun_listen: SocketAddr,
}

#[derive(Default)]
struct Shared {
    /// The server's link: new clients to announce
    link: Mutex<Option<mpsc::Sender<(u64, SocketAddr)>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<BoxIo>>>,
    next: AtomicU64,
    linked: AtomicBool,
}

pub struct Helper {
    pin: [u8; 32],
    secret: String,
    port: u16,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Helper {
    pub async fn start(cfg: HelperConfig) -> Result<Helper> {
        std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("creating {}", cfg.data_dir.display()))?;
        let (tls, pin) = crate::tls::self_signed(&cfg.data_dir.join("tls"))?;
        let secret = load_secret(&cfg.data_dir.join("helper-secret"))?;
        let mut listeners = vec![tokio::net::TcpListener::from_std(
            crate::net::bind_tcp(cfg.listen).with_context(|| format!("binding tcp/{}", cfg.listen))?,
        )?];
        for addr in &cfg.extra_listen {
            match crate::net::bind_tcp(*addr).and_then(tokio::net::TcpListener::from_std) {
                Ok(l) => listeners.push(l),
                Err(e) => tracing::info!("helper: not listening on tcp/{addr}: {e}"),
            }
        }
        let port = listeners[0].local_addr()?.port();
        let stun = crate::net::bind_udp(cfg.stun_listen).with_context(|| format!("binding udp/{}", cfg.stun_listen))?;
        let shared = Arc::new(Shared::default());
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        let mut tasks = Vec::new();
        for l in listeners {
            let (shared, acceptor, secret) = (shared.clone(), acceptor.clone(), secret.clone());
            tasks.push(tokio::spawn(async move {
                loop {
                    let Ok((tcp, peer)) = l.accept().await else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let _ = tcp.set_nodelay(true);
                    let (shared, acceptor, secret) = (shared.clone(), acceptor.clone(), secret.clone());
                    tokio::spawn(async move {
                        if let Err(e) = handle(tcp, peer, &shared, &acceptor, &secret).await {
                            tracing::debug!(%peer, "helper: {e:#}");
                        }
                    });
                }
            }));
        }
        tasks.push(tokio::spawn(async move {
            if let Err(e) = crate::stun::run(stun).await {
                tracing::error!("STUN stopped: {e:#}");
            }
        }));
        tracing::info!("helper: listening on tcp/{port}");
        Ok(Helper { pin, secret, port, shared, tasks })
    }

    pub fn pin(&self) -> [u8; 32] {
        self.pin
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether a server is linked right now
    pub fn linked(&self) -> bool {
        self.shared.linked.load(Ordering::Relaxed)
    }

    pub async fn stop(mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn load_secret(path: &std::path::Path) -> Result<String> {
    if let Ok(s) = std::fs::read_to_string(path) {
        let s = s.trim().to_string();
        if s.len() >= 32 {
            return Ok(s);
        }
    }
    let mut b = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::fs::write(path, &s).with_context(|| format!("writing {}", path.display()))?;
    Ok(s)
}

async fn handle(
    mut tcp: TcpStream,
    peer: SocketAddr,
    shared: &Shared,
    acceptor: &tokio_rustls::TlsAcceptor,
    secret: &str,
) -> Result<()> {
    let (prefix, hello) = tokio::time::timeout(PICKUP, crate::tls::read_client_hello(&mut tcp))
        .await
        .context("no data")??;
    let sni = hello.as_deref().and_then(crate::reality::parse_client_hello).and_then(|h| h.server_name);
    let io = crate::tls::Prefixed::new(prefix, Box::new(tcp));
    if sni.as_deref() == Some(LINK_NAME) {
        let tls = tokio::time::timeout(PICKUP, acceptor.accept(io)).await.context("link handshake timed out")??;
        return link(tls, shared, secret).await;
    }
    // Anyone else is a client of the server
    let Some(announce) = shared.link.lock().unwrap().clone() else {
        anyhow::bail!("no server linked");
    };
    let id = shared.next.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    {
        let mut pending = shared.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING {
            anyhow::bail!("too many clients waiting");
        }
        pending.insert(id, tx);
    }
    let picked = async {
        announce.send((id, peer)).await.ok()?;
        tokio::time::timeout(PICKUP, rx).await.ok()?.ok()
    };
    let work = picked.await;
    shared.pending.lock().unwrap().remove(&id);
    let mut work = work.context("the server did not pick up the connection")?;
    let mut io = io;
    tokio::io::copy_bidirectional(&mut io, &mut work).await?;
    Ok(())
}

async fn link<S>(tls: S, shared: &Shared, secret: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut reader = BufReader::new(tls);
    let mut line = String::new();
    (&mut reader).take(256).read_line(&mut line).await?;
    let mut words = line.split_whitespace();
    let (kind, given) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
    if !constant_time_eq(given.as_bytes(), secret.as_bytes()) {
        anyhow::bail!("wrong helper secret");
    }
    match kind {
        "WORK" => {
            let id: u64 = words.next().and_then(|w| w.parse().ok()).context("malformed WORK")?;
            let waiting = shared.pending.lock().unwrap().remove(&id);
            if let Some(tx) = waiting {
                // Bytes the server sent early stay in the reader's buffer
                let _ = tx.send(Box::new(reader));
            }
            Ok(())
        }
        "CTRL" => {
            let (tx, mut rx) = mpsc::channel(64);
            *shared.link.lock().unwrap() = Some(tx.clone());
            shared.linked.store(true, Ordering::Relaxed);
            tracing::info!("helper: server linked");
            let (r, mut w) = tokio::io::split(reader);
            let mut lines = BufReader::new(r).lines();
            let mut ping = tokio::time::interval(PING);
            let mut last_heard = tokio::time::Instant::now();
            let result: Result<()> = loop {
                tokio::select! {
                    Some((id, peer)) = rx.recv() => {
                        if let Err(e) = w.write_all(format!("OPEN {id} {peer}\n").as_bytes()).await {
                            break Err(e.into());
                        }
                    }
                    l = lines.next_line() => match l {
                        Ok(Some(_)) => last_heard = tokio::time::Instant::now(),
                        Ok(None) => break Ok(()),
                        Err(e) => break Err(e.into()),
                    },
                    _ = ping.tick() => {
                        if last_heard.elapsed() > PING * 3 {
                            break Err(anyhow::anyhow!("link went silent"));
                        }
                        if let Err(e) = w.write_all(b"PING\n").await {
                            break Err(e.into());
                        }
                    }
                }
            };
            let mut link = shared.link.lock().unwrap();
            // A newer link may have replaced this one already
            if link.as_ref().is_some_and(|l| l.same_channel(&tx)) {
                *link = None;
                shared.linked.store(false, Ordering::Relaxed);
                tracing::info!("helper: server link closed");
            }
            result
        }
        _ => anyhow::bail!("unknown request"),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
