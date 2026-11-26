//! This server's side of a helper node (see `retail_control::helper`): keeps
//! the link up and, for every client the helper announces, opens the
//! connection that carries it and hands that to the server's listener.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use retail_control::Injector;
use retail_control::helper::LINK_NAME;
use retail_proto::invite::{HelperCode, decode_pin};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// The helper pings every 20 s
const SILENCE: Duration = Duration::from_secs(60);
/// Longest line the helper sends ("OPEN id address")
const MAX_LINE: u64 = 512;
/// Connections being picked up at once
const MAX_PICKUPS: usize = 64;

pub async fn run(code: HelperCode, inject: Injector, linked: Arc<AtomicBool>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = tokio::time::Instant::now();
        if let Err(e) = link(&code, &inject, &linked).await {
            tracing::warn!("helper link: {e:#}");
        }
        linked.store(false, Ordering::Relaxed);
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn connect(code: &HelperCode) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let (first, rest) = code.addrs.split_first().context("the helper code has no address")?;
    let (host, port) = first.rsplit_once(':').context("malformed helper address")?;
    let host = host.trim_matches(['[', ']']);
    let tcp = crate::happy::connect_many(host, port.parse()?, rest).await?;
    tcp.set_nodelay(true)?;
    retail_proto::relay::tune(&tcp);
    let pin = decode_pin(&code.pin).context("the helper code is damaged")?;
    let target = crate::http::Target { pin: Some(pin), ..Default::default() };
    let name = rustls::pki_types::ServerName::try_from(LINK_NAME)?;
    let mut tls = tokio_rustls::TlsConnector::from(target.tls()).connect(name, tcp).await?;
    tls.get_mut().1.set_buffer_limit(Some(retail_proto::relay::TLS_BUFFER));
    Ok(tls)
}

async fn link(code: &HelperCode, inject: &Injector, linked: &AtomicBool) -> Result<()> {
    let mut tls = tokio::time::timeout(Duration::from_secs(15), connect(code)).await.context("timed out")??;
    tls.write_all(format!("CTRL {}\n", code.secret).as_bytes()).await?;
    let (r, mut w) = tokio::io::split(tls);
    let mut reader = BufReader::new(r);
    let pickups = Arc::new(tokio::sync::Semaphore::new(MAX_PICKUPS));
    loop {
        let mut line = String::new();
        let mut limited = (&mut reader).take(MAX_LINE);
        match tokio::time::timeout(SILENCE, limited.read_line(&mut line)).await {
            Ok(Ok(0)) => bail!("the helper closed the link (wrong code?)"),
            Ok(Ok(_)) if !line.ends_with('\n') => bail!("the helper sent an overlong line"),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => bail!("the helper went silent"),
        }
        if !linked.swap(true, Ordering::Relaxed) {
            tracing::info!(helper = %code.addrs[0], "linked to the helper node");
        }
        let mut words = line.split_whitespace();
        match words.next() {
            Some("OPEN") => {
                let id: u64 = words.next().and_then(|w| w.parse().ok()).context("malformed OPEN")?;
                let client: SocketAddr = words.next().and_then(|w| w.parse().ok()).context("malformed OPEN")?;
                let Ok(permit) = pickups.clone().try_acquire_owned() else {
                    tracing::debug!("helper: too many connections being picked up; dropping one");
                    continue;
                };
                let (code, inject) = (code.clone(), inject.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = pick_up(&code, &inject, id, client).await {
                        tracing::debug!(%client, "helper connection: {e:#}");
                    }
                });
            }
            Some("PING") => w.write_all(b"PONG\n").await?,
            _ => {}
        }
    }
}

async fn pick_up(code: &HelperCode, inject: &Injector, id: u64, client: SocketAddr) -> Result<()> {
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connect(code)).await.context("timed out")??;
    tls.write_all(format!("WORK {} {id}\n", code.secret).as_bytes()).await?;
    inject.send((Box::new(tls), client)).await.ok().context("the server stopped")?;
    Ok(())
}
