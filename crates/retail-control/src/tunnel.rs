//! Tunnels for networks where only HTTP gets through: a proxy that decrypts
//! TLS and refuses self-signed servers, or a CDN in front of the server. The
//! client runs its usual pinned TLS inside, so whatever terminates the outer
//! connection sees only ciphertext. Each tunnel becomes one more connection
//! on the server's listener.
//!
//! - `GET /api/v1/tunnel`: a WebSocket whose binary messages carry the stream
//! - `/api/v1/tunnel/poll`: for middleboxes that strip `Upgrade`. `POST` opens
//!   a session and returns its id, `POST /{id}` sends, and `GET /{id}` waits up
//!   to [`POLL_HOLD`] for data to receive.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

use crate::server::AppState;
use crate::tls::PeerAddr;

/// Buffered per direction inside each tunnel
const PIPE: usize = 64 * 1024;
const MAX_MESSAGE: usize = 256 * 1024;
/// Under the 30 s or so after which proxies tend to cut idle requests
pub const POLL_HOLD: Duration = Duration::from_secs(15);
/// How long an answer to a poll waits for more data after the first bytes
const POLL_GATHER: Duration = Duration::from_millis(2);
/// A session nobody polled for this long is closed
const POLL_IDLE: Duration = Duration::from_secs(60);
const MAX_POLL_SESSIONS: usize = 256;
/// Per client address (IPv6: per /64), so one source cannot take them all
const MAX_POLL_SESSIONS_PER_IP: usize = 16;

pub struct PollSession {
    ip: std::net::IpAddr,
    reader: tokio::sync::Mutex<ReadHalf<DuplexStream>>,
    writer: tokio::sync::Mutex<WriteHalf<DuplexStream>>,
    touched: Mutex<Instant>,
}

/// The server's half of a new tunnel, already handed to the listener
async fn open(state: &AppState, peer: PeerAddr) -> Option<DuplexStream> {
    let inject = state.inject.get()?.clone();
    let (ours, theirs) = tokio::io::duplex(PIPE);
    inject.send((Box::new(theirs), peer.0)).await.ok()?;
    Some(ours)
}

/// The device behind a tunnel that ends on this machine (the internet
/// tunnel's cloudflared): Cloudflare names it in `Cf-Connecting-IP`. Trusted
/// from loopback only, so the per-address limits apply per device and not to
/// all of them at once; from elsewhere the header is anyone's to write.
fn real_peer(peer: PeerAddr, headers: &HeaderMap) -> PeerAddr {
    if !peer.0.ip().is_loopback() {
        return peer;
    }
    match headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<std::net::IpAddr>().ok()) {
        Some(ip) => PeerAddr(std::net::SocketAddr::new(ip.to_canonical(), peer.0.port()), peer.1),
        None => peer,
    }
}

use crate::net::same_network;

/// WebSocket tunnels open at once, in all and per client address: each
/// holds buffers and a connection on the listener
const MAX_WEBSOCKETS: usize = 1024;
const MAX_WEBSOCKETS_PER_IP: usize = 32;
/// A tunnel that carries nothing either way for this long is closed (the
/// node poll inside pings every 30 s)
const WEBSOCKET_IDLE: Duration = Duration::from_secs(120);
static WEBSOCKETS: Mutex<Option<Websockets>> = Mutex::new(None);

/// Open tunnels by source network, oldest first, each with what closes it
#[derive(Default)]
struct Websockets {
    by_ip: std::collections::HashMap<std::net::IpAddr, Vec<(u64, Arc<tokio::sync::Notify>)>>,
    next: u64,
}

impl Websockets {
    /// When full, a source holding fewer than the largest holder takes the
    /// oldest tunnel of that holder, so a few networks cannot keep the rest out
    fn admit(&mut self, ip: std::net::IpAddr) -> Option<(u64, Arc<tokio::sync::Notify>)> {
        let mine = self.by_ip.get(&ip).map_or(0, Vec::len);
        if mine >= MAX_WEBSOCKETS_PER_IP {
            return None;
        }
        if self.by_ip.values().map(Vec::len).sum::<usize>() >= MAX_WEBSOCKETS {
            let (_, largest) = self.by_ip.iter_mut().max_by_key(|(_, v)| v.len())?;
            if largest.len() <= mine + 1 {
                return None;
            }
            largest.remove(0).1.notify_one();
        }
        self.next += 1;
        let close = Arc::new(tokio::sync::Notify::new());
        self.by_ip.entry(ip).or_default().push((self.next, close.clone()));
        Some((self.next, close))
    }

    fn release(&mut self, ip: std::net::IpAddr, id: u64) {
        if let Some(v) = self.by_ip.get_mut(&ip) {
            v.retain(|(i, _)| *i != id);
            if v.is_empty() {
                self.by_ip.remove(&ip);
            }
        }
    }
}

/// One open WebSocket tunnel, counted until dropped
struct WebsocketSlot(std::net::IpAddr, u64);

impl WebsocketSlot {
    fn take(ip: std::net::IpAddr) -> Option<(Self, Arc<tokio::sync::Notify>)> {
        let ip = same_network(ip);
        let (id, close) = WEBSOCKETS.lock().unwrap().get_or_insert_with(Default::default).admit(ip)?;
        Some((WebsocketSlot(ip, id), close))
    }
}

impl Drop for WebsocketSlot {
    fn drop(&mut self) {
        if let Some(w) = WEBSOCKETS.lock().unwrap().as_mut() {
            w.release(self.0, self.1);
        }
    }
}
fn no_store(status: StatusCode, body: impl IntoResponse) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
}

pub async fn websocket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let peer = real_peer(peer, &headers);
    let Some((slot, close)) = WebsocketSlot::take(peer.0.ip()) else {
        return no_store(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let ws = ws.max_message_size(MAX_MESSAGE).max_frame_size(MAX_MESSAGE).read_buffer_size(PIPE);
    ws.on_upgrade(move |socket| async move {
        let _slot = slot;
        if let Some(pipe) = open(&state, peer).await {
            tokio::select! {
                _ = pump(socket, pipe) => {}
                _ = close.notified() => {}
            }
        }
    })
}

async fn pump(socket: WebSocket, pipe: DuplexStream) {
    let (mut tx, mut rx) = socket.split();
    let (mut pipe_rx, mut pipe_tx) = tokio::io::split(pipe);
    let up = async {
        let mut idle = tokio::time::Instant::now() + WEBSOCKET_IDLE;
        while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(idle, rx.next()).await {
            match msg {
                Message::Binary(data) => {
                    idle = tokio::time::Instant::now() + WEBSOCKET_IDLE;
                    if pipe_tx.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = pipe_tx.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; PIPE];
        loop {
            match tokio::time::timeout(WEBSOCKET_IDLE, pipe_rx.read(&mut buf)).await {
                Ok(Ok(0) | Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if tx.send(Message::Binary(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(Message::Close(None)).await;
    };
    // Either direction ending ends the tunnel
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

pub async fn poll_open(State(state): State<AppState>, ConnectInfo(peer): ConnectInfo<PeerAddr>, headers: HeaderMap) -> Response {
    let peer = real_peer(peer, &headers);
    let mine = same_network(peer.0.ip());
    let full = |polls: &mut std::collections::HashMap<String, Arc<PollSession>>| {
        polls.retain(|_, s| s.touched.lock().unwrap().elapsed() < POLL_IDLE);
        polls.len() >= MAX_POLL_SESSIONS || polls.values().filter(|s| same_network(s.ip) == mine).count() >= MAX_POLL_SESSIONS_PER_IP
    };
    if full(&mut state.polls().lock().unwrap()) {
        return no_store(StatusCode::SERVICE_UNAVAILABLE, "busy");
    }
    let Some(pipe) = open(&state, peer).await else {
        return no_store(StatusCode::SERVICE_UNAVAILABLE, "not ready");
    };
    let (reader, writer) = tokio::io::split(pipe);
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let session = PollSession {
        ip: peer.0.ip(),
        reader: tokio::sync::Mutex::new(reader),
        writer: tokio::sync::Mutex::new(writer),
        touched: Mutex::new(Instant::now()),
    };
    // Checked again: other opens may have filled it while this one waited
    let mut polls = state.polls().lock().unwrap();
    if full(&mut polls) {
        return no_store(StatusCode::SERVICE_UNAVAILABLE, "busy");
    }
    polls.insert(id.clone(), Arc::new(session));
    no_store(StatusCode::OK, id)
}

fn session(state: &AppState, id: &str) -> Option<Arc<PollSession>> {
    let s = state.polls().lock().unwrap().get(id).cloned()?;
    *s.touched.lock().unwrap() = Instant::now();
    Some(s)
}

/// 200 with the bytes received, empty if none arrived in time; 410 once the
/// connection inside has closed
pub async fn poll_down(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(s) = session(&state, &id) else {
        return no_store(StatusCode::NOT_FOUND, "");
    };
    // A second concurrent poll waits behind the first rather than splitting the stream
    let mut reader = s.reader.lock().await;
    let mut buf = vec![0u8; PIPE];
    match tokio::time::timeout(POLL_HOLD, reader.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {
            state.polls().lock().unwrap().remove(&id);
            no_store(StatusCode::GONE, "")
        }
        Ok(Ok(mut n)) => {
            // Gather what follows within a moment: every poll costs a round
            // trip, so fuller answers raise throughput
            let until = tokio::time::Instant::now() + POLL_GATHER;
            while n < buf.len() {
                match tokio::time::timeout_at(until, reader.read(&mut buf[n..])).await {
                    Ok(Ok(m)) if m > 0 => n += m,
                    _ => break,
                }
            }
            buf.truncate(n);
            no_store(StatusCode::OK, buf)
        }
        Err(_) => no_store(StatusCode::OK, Vec::new()),
    }
}

pub async fn poll_up(State(state): State<AppState>, Path(id): Path<String>, body: Bytes) -> Response {
    let Some(s) = session(&state, &id) else {
        return no_store(StatusCode::NOT_FOUND, "");
    };
    if body.len() > MAX_MESSAGE {
        return no_store(StatusCode::PAYLOAD_TOO_LARGE, "");
    }
    let mut writer = s.writer.lock().await;
    match writer.write_all(&body).await {
        Ok(()) => no_store(StatusCode::OK, ""),
        Err(_) => {
            state.polls().lock().unwrap().remove(&id);
            no_store(StatusCode::GONE, "")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_tunnels_are_capped_per_network() {
        let ip = |i: u16| std::net::IpAddr::from([0x2001, 0xdb8, 0, 7, 0, 0, 0, i]);
        let held: Vec<_> = (0..MAX_WEBSOCKETS_PER_IP).map(|i| WebsocketSlot::take(ip(i as u16)).unwrap()).collect();
        assert_eq!(held.len(), MAX_WEBSOCKETS_PER_IP);
        assert!(WebsocketSlot::take(ip(999)).is_none(), "the rest of the /64 is the same source");
        let other = WebsocketSlot::take("198.51.100.1".parse().unwrap());
        assert!(other.is_some());
        drop(held);
        assert!(WebsocketSlot::take(ip(1)).is_some(), "slots come back");
    }

    #[test]
    fn a_full_table_makes_room_for_a_new_network() {
        let mut w = Websockets::default();
        let net = |n: u16| std::net::IpAddr::from([0x2001, 0xdb8, n, 0, 0, 0, 0, 0]);
        let mut handles = std::collections::HashMap::new();
        for n in 0..(MAX_WEBSOCKETS / MAX_WEBSOCKETS_PER_IP) as u16 {
            for _ in 0..MAX_WEBSOCKETS_PER_IP {
                let got = w.admit(net(n)).unwrap();
                handles.entry(net(n)).or_insert(got);
            }
        }
        assert!(w.admit(net(0)).is_none());
        let honest = "198.51.100.1".parse().unwrap();
        assert!(w.admit(honest).is_some(), "takes the oldest tunnel of a large holder");
        let (&holder, _) = w.by_ip.iter().find(|(_, v)| v.len() == MAX_WEBSOCKETS_PER_IP - 1).unwrap();
        let evicted = handles[&holder].1.clone();
        assert!(tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
            tokio::time::timeout(Duration::from_millis(10), evicted.notified()).await.is_ok()
        }));
        assert!(w.admit(holder).is_none(), "the holder cannot take it back");
        assert_eq!(w.by_ip.values().map(Vec::len).sum::<usize>(), MAX_WEBSOCKETS);
    }

    #[test]
    fn the_device_behind_cloudflared_is_trusted_from_loopback_only() {
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        let local = PeerAddr("127.0.0.1:5000".parse().unwrap(), false);
        assert_eq!(real_peer(local, &h).0, "198.51.100.7:5000".parse().unwrap());
        // Anyone else may write the header
        let remote = PeerAddr("203.0.113.9:5000".parse().unwrap(), true);
        assert_eq!(real_peer(remote, &h).0, "203.0.113.9:5000".parse().unwrap());
        // Missing or malformed: the peer as it is
        let local = PeerAddr("127.0.0.1:5000".parse().unwrap(), false);
        assert_eq!(real_peer(local, &HeaderMap::new()).0.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        h.insert("cf-connecting-ip", "nonsense".parse().unwrap());
        let local = PeerAddr("[::1]:5000".parse().unwrap(), false);
        assert!(real_peer(local, &h).0.ip().is_loopback());
    }
}
