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
use axum::http::{StatusCode, header};
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
/// Per client address, so one source cannot take them all
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

fn no_store(status: StatusCode, body: impl IntoResponse) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
}

pub async fn websocket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<PeerAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    let ws = ws.max_message_size(MAX_MESSAGE).max_frame_size(MAX_MESSAGE).read_buffer_size(PIPE);
    ws.on_upgrade(move |socket| async move {
        if let Some(pipe) = open(&state, peer).await {
            pump(socket, pipe).await;
        }
    })
}

async fn pump(socket: WebSocket, pipe: DuplexStream) {
    let (mut tx, mut rx) = socket.split();
    let (mut pipe_rx, mut pipe_tx) = tokio::io::split(pipe);
    let up = async {
        while let Some(Ok(msg)) = rx.next().await {
            match msg {
                Message::Binary(data) => {
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
            match pipe_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
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

pub async fn poll_open(State(state): State<AppState>, ConnectInfo(peer): ConnectInfo<PeerAddr>) -> Response {
    {
        let mut polls = state.polls().lock().unwrap();
        polls.retain(|_, s| s.touched.lock().unwrap().elapsed() < POLL_IDLE);
        if polls.len() >= MAX_POLL_SESSIONS || polls.values().filter(|s| s.ip == peer.0.ip()).count() >= MAX_POLL_SESSIONS_PER_IP {
            return no_store(StatusCode::SERVICE_UNAVAILABLE, "busy");
        }
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
    state.polls().lock().unwrap().insert(id.clone(), Arc::new(session));
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
