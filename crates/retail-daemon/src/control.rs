use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures_util::{Sink, SinkExt, StreamExt};
use retail_proto::DEFAULT_STUN_PORT;
use retail_proto::api::{ApiError, ClientMessage, RegisterRequest, RegisterResponse, ServerMessage};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::engine::Engine;
use crate::http::Target;

/// Returns the URL trimmed and without a trailing slash
pub fn normalize_server(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!("server URL must start with http:// or https://");
    }
    if host_of(url).is_empty() {
        bail!("server URL has no host");
    }
    Ok(url.to_string())
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or("");
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("");
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

/// Fallback for when the control server advertises no STUN server
pub fn default_stun_server(server: &str) -> String {
    let host = host_of(server);
    if host.contains(':') {
        format!("[{host}]:{DEFAULT_STUN_PORT}")
    } else {
        format!("{host}:{DEFAULT_STUN_PORT}")
    }
}

/// The server's other addresses: the ones it reports now first, then those
/// known before, without its main address and at most 16
pub fn merge_alts(server: &str, fresh: &[String], known: &[String]) -> Vec<String> {
    let main = server.split_once("://").map_or(server, |(_, r)| r);
    let mut out: Vec<String> = Vec::new();
    for a in fresh.iter().chain(known) {
        let a = a.trim();
        if !a.is_empty() && a != main && !a.contains(['/', ' ']) && !out.iter().any(|x| x == a) {
            out.push(a.to_string());
        }
    }
    out.truncate(16);
    out
}

fn poll_url(server: &str) -> Result<String> {
    let ws = if let Some(r) = server.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = server.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        bail!("server URL must start with http:// or https://");
    };
    Ok(format!("{ws}/api/v1/poll"))
}

pub async fn register(target: &Target, req: &RegisterRequest) -> Result<RegisterResponse> {
    let body = serde_json::to_vec(req)?;
    let resp = crate::http::post_json(target, "/api/v1/register", &body)
        .await
        .with_context(|| format!("contacting {}", target.url))?;
    if !(200..300).contains(&resp.status) {
        let msg = serde_json::from_slice::<ApiError>(&resp.body).map(|e| e.error).unwrap_or_default();
        bail!("registration rejected (HTTP {}): {msg}", resp.status);
    }
    serde_json::from_slice(&resp.body).context("parsing registration response")
}

pub async fn control_loop(engine: Arc<Engine>, target: Target, token: String) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    let mut relay_out = engine.take_relay_out().context("control loop already running")?;
    loop {
        let started = Instant::now();
        // Where the server said it is now, except inside networks routed
        // through the mesh, which need this connection to work first
        let mut target = target.clone();
        let fresh = engine.subscribe_server_addrs().borrow().clone();
        let routed = engine.subscribe_routes().borrow().accepted.clone();
        target.alts = merge_alts(&target.url, &fresh, &target.alts)
            .into_iter()
            .filter(|a| match a.parse::<std::net::SocketAddr>() {
                Ok(std::net::SocketAddr::V4(v4)) => !routed.iter().any(|r| r.contains(*v4.ip())),
                _ => true,
            })
            .collect();
        match run_once(&engine, &target, &token, &mut relay_out).await {
            Ok(()) => tracing::info!("control connection closed by server"),
            Err(e) => tracing::warn!("control connection: {e:#}"),
        }
        engine.control_connected.store(false, Ordering::Relaxed);
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
const PING_INTERVAL: Duration = Duration::from_secs(10);
/// Both sides ping, so silence this long means a NAT or middlebox dropped the
/// connection. Reconnecting beats waiting for TCP to give up.
const DEAD_AFTER: Duration = Duration::from_secs(30);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Relay frames written before one flush
const RELAY_BATCH_BYTES: usize = 128 * 1024;
/// Covers the WebSocket handshake once a way to the server is found
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

async fn send<S>(tx: &mut S, msg: Message) -> Result<()>
where
    S: Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    tokio::time::timeout(SEND_TIMEOUT, tx.send(msg))
        .await
        .context("control connection stalled")??;
    Ok(())
}

/// Message limits leave room for netmaps that grow with the mesh. Writes are
/// buffered so relayed frames share TLS records and system calls.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(64 * 1024)
        .max_write_buffer_size(512 * 1024)
        .max_message_size(Some(4 << 20))
        .max_frame_size(Some(4 << 20))
}

async fn run_once(
    engine: &Engine,
    target: &Target,
    token: &str,
    relay_out: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let server = target.url.as_str();
    let mut req = poll_url(server)?.into_client_request()?;
    req.headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
    let dialed = crate::transport::dial(target).await?;
    if let Some(addr) = dialed.server_addr {
        engine.set_control_addr(addr);
    }
    tracing::info!(via = %dialed.via, "control connection established");
    engine.set_control_via(Some(dialed.via));
    let handshake = tokio_tungstenite::client_async_with_config(req, dialed.io, Some(ws_config()));
    let ws = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {server} within {}s", HANDSHAKE_TIMEOUT.as_secs()))?
        .with_context(|| format!("connecting to {server}"))?
        .0;
    let result = session(engine, ws, relay_out).await;
    engine.set_control_via(None);
    result
}
async fn session<S>(
    engine: &Engine,
    ws: tokio_tungstenite::WebSocketStream<S>,
    relay_out: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Frames queued while disconnected are stale and WireGuard retries on its own
    while relay_out.try_recv().is_ok() {}
    engine.control_connected.store(true, Ordering::Relaxed);
    tracing::info!("connected to control server");

    let (mut tx, mut rx) = ws.split();
    let mut endpoints = engine.subscribe_endpoints();
    let send_endpoints = |eps| -> Result<Message> {
        Ok(Message::text(serde_json::to_string(&ClientMessage::Endpoints { endpoints: eps })?))
    };
    let current = endpoints.borrow_and_update().clone();
    send(&mut tx, send_endpoints(current)?).await?;
    let mut advertise = engine.subscribe_advertise_exit();
    let mut advertise_routes = engine.subscribe_advertise_routes();
    let hostinfo = |exit_node, routes| -> Result<Message> {
        Ok(Message::text(serde_json::to_string(&ClientMessage::Hostinfo { exit_node, routes })?))
    };
    let offer = *advertise.borrow_and_update();
    let routes = advertise_routes.borrow_and_update().clone();
    send(&mut tx, hostinfo(offer, routes)?).await?;
    let mut helper_code = engine.subscribe_helper_code();
    let helper_msg = |code| -> Result<Message> {
        Ok(Message::text(serde_json::to_string(&ClientMessage::HelperCode { code })?))
    };
    let code = helper_code.borrow_and_update().clone();
    if code.is_some() {
        send(&mut tx, helper_msg(code)?).await?;
    }
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_inbound = Instant::now();

    let mut relay_rx = crate::engine::RelayRx::new();
    // Biased so a relay frame delays control traffic by at most the frame being written
    loop {
        tokio::select! {
            biased;
            msg = rx.next() => {
                last_inbound = Instant::now();
                match msg {
                    Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
                        Ok(ServerMessage::NetMap(nm)) => {
                            tracing::debug!(peers = nm.peers.len(), "netmap received");
                            engine.apply_netmap(nm);
                        }
                        Err(e) => tracing::warn!("bad server message: {e}"),
                    },
                    Some(Ok(Message::Binary(frame))) => engine.receive_relay(&frame, &mut relay_rx).await,
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                }
            }
            changed = endpoints.changed() => {
                changed?;
                let eps = endpoints.borrow_and_update().clone();
                tracing::debug!(?eps, "reporting endpoints");
                send(&mut tx, send_endpoints(eps)?).await?;
            }
            changed = advertise.changed() => {
                changed?;
                let offer = *advertise.borrow_and_update();
                let routes = advertise_routes.borrow().clone();
                send(&mut tx, hostinfo(offer, routes)?).await?;
            }
            changed = advertise_routes.changed() => {
                changed?;
                let routes = advertise_routes.borrow_and_update().clone();
                let offer = *advertise.borrow();
                send(&mut tx, hostinfo(offer, routes)?).await?;
            }
            changed = helper_code.changed() => {
                changed?;
                let code = helper_code.borrow_and_update().clone();
                send(&mut tx, helper_msg(code)?).await?;
            }
            () = engine.control_reset.notified() => {
                bail!("reconnecting: routes changed");
            }
            _ = ping.tick() => {
                if last_inbound.elapsed() > DEAD_AFTER {
                    bail!("no word from the server for {}s", last_inbound.elapsed().as_secs());
                }
                send(&mut tx, Message::Ping(Vec::new().into())).await?;
            }
            Some(frame) = relay_out.recv() => {
                // Frames already queued go out with it, flushed (and encrypted) together
                let batch = async {
                    let mut bytes = frame.len();
                    tx.feed(Message::binary(frame)).await?;
                    while bytes < RELAY_BATCH_BYTES {
                        let Ok(next) = relay_out.try_recv() else { break };
                        bytes += next.len();
                        tx.feed(Message::binary(next)).await?;
                    }
                    tx.flush().await
                };
                tokio::time::timeout(SEND_TIMEOUT, batch).await.context("control connection stalled")??;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_helpers() {
        assert_eq!(normalize_server(" https://vpn.example.com/ ").unwrap(), "https://vpn.example.com");
        assert!(normalize_server("vpn.example.com").is_err());
        assert_eq!(poll_url("https://a.b:8443").unwrap(), "wss://a.b:8443/api/v1/poll");
        assert_eq!(poll_url("http://10.0.0.1:8080").unwrap(), "ws://10.0.0.1:8080/api/v1/poll");
        assert_eq!(default_stun_server("http://10.0.0.1:8080"), "10.0.0.1:3478");
        assert_eq!(default_stun_server("https://vpn.example.com/x"), "vpn.example.com:3478");
        assert_eq!(default_stun_server("http://[2001:db8::1]:8080"), "[2001:db8::1]:3478");
    }
}
