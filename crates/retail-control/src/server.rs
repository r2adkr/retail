use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum::body::Bytes;
use retail_proto::Key;
use retail_proto::api::{
    ApiError, ClientMessage, NetMap, Node, RegisterRequest, RegisterResponse, ServerMessage,
};
use retail_proto::relay;
use futures_util::SinkExt;
use tokio::sync::{mpsc, watch};

use crate::db::{Db, NodeRow, RegisterError};
use retail_proto::route::Ipv4Net;

/// Keeps netmaps small
const MAX_ENDPOINTS: usize = 16;
/// Endpoint updates from one connection cost every node a netmap. A device
/// sends a few in quick succession while it finds its addresses, and those go
/// through at once; beyond `ENDPOINTS_BURST` within `ENDPOINTS_WINDOW` they
/// wait, and only the newest is applied.
const ENDPOINTS_BURST: usize = 5;
const ENDPOINTS_WINDOW: Duration = Duration::from_secs(5);
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// Per client address
const REGISTER_PER_MINUTE: u32 = 10;
/// Frames (up to 64 KiB each) queued towards one node before further ones are
/// dropped. WireGuard and TCP inside it recover from loss, and a stuck reader
/// must not grow the server without bound. A longer queue only added delay.
const RELAY_QUEUE: usize = 48;
const MAX_CLIENT_MESSAGE: usize = relay::MAX_FRAME;
/// Relay frames written before one flush
const RELAY_BATCH_BYTES: usize = 128 * 1024;

/// Inbox of the newest poll connection per node key, tagged with its connection id
#[derive(Default)]
struct Relays {
    by_key: HashMap<Key, (u64, mpsc::Sender<Bytes>)>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) db: Db,
    /// Bumped on every change that may alter some node's netmap
    changes: Arc<watch::Sender<u64>>,
    /// Open poll connections per node id
    online: Arc<Mutex<HashMap<i64, usize>>>,
    stun_servers: Arc<Mutex<Vec<String>>>,
    /// (count, window start) per client address
    register_attempts: Arc<Mutex<HashMap<std::net::IpAddr, (u32, std::time::Instant)>>>,
    relays: Arc<Mutex<Relays>>,
    next_conn: Arc<AtomicU64>,
    /// Reported on connect, forgotten on disconnect
    exit_nodes: Arc<Mutex<std::collections::HashSet<i64>>>,
    /// Networks each connected node offers to route
    offered_routes: Arc<Mutex<HashMap<i64, Vec<Ipv4Net>>>>,
    /// Where the server is reachable now, sent to nodes
    server_addrs: Arc<Mutex<Vec<String>>>,
    /// HTTPS URLs forwarding to the server, sent to nodes once set
    server_fronts: Arc<Mutex<Option<Vec<String>>>>,
    /// Helper codes of member devices acting as helper nodes, while connected
    helper_codes: Arc<Mutex<HashMap<i64, String>>>,
    /// The chosen helper device's code, for the hosting daemon to link to
    pub(crate) helper_code: Arc<watch::Sender<Option<String>>>,
    /// Upgraded WebSockets live outside the HTTP server's graceful shutdown,
    /// so they watch this.
    shutdown: Arc<watch::Sender<bool>>,
    /// Where tunnels hand over the connections they carry
    pub(crate) inject: Arc<std::sync::OnceLock<crate::tls::Injector>>,
    polls: Arc<Mutex<HashMap<String, Arc<crate::tunnel::PollSession>>>>,
}

impl AppState {
    pub fn new(db: Db, stun_servers: Vec<String>) -> Self {
        let (tx, _) = watch::channel(0);
        AppState {
            db,
            changes: Arc::new(tx),
            online: Arc::default(),
            stun_servers: Arc::new(Mutex::new(stun_servers)),
            register_attempts: Arc::default(),
            relays: Arc::default(),
            next_conn: Arc::default(),
            exit_nodes: Arc::default(),
            offered_routes: Arc::default(),
            server_addrs: Arc::default(),
            server_fronts: Arc::default(),
            helper_codes: Arc::default(),
            helper_code: Arc::new(watch::channel(None).0),
            shutdown: Arc::new(watch::channel(false).0),
            inject: Arc::default(),
            polls: Arc::default(),
        }
    }

    /// Closes every poll connection
    pub fn shut_down(&self) {
        self.shutdown.send_replace(true);
    }

    pub fn set_stun_servers(&self, servers: Vec<String>) {
        *self.stun_servers.lock().unwrap() = servers;
        self.notify();
    }

    fn register_allowed(&self, ip: std::net::IpAddr) -> bool {
        let mut attempts = self.register_attempts.lock().unwrap();
        let now = std::time::Instant::now();
        if attempts.len() > 10_000 {
            attempts.retain(|_, (_, since)| now.duration_since(*since) < Duration::from_secs(60));
        }
        let entry = attempts.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= Duration::from_secs(60) {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 <= REGISTER_PER_MINUTE
    }

    pub fn notify(&self) {
        self.changes.send_modify(|v| *v += 1);
    }

    /// Publishes the chosen helper device's code, if it has sent one
    pub(crate) fn refresh_helper_code(&self) {
        let code = self.db.helper_device().and_then(|id| self.helper_codes.lock().unwrap().get(&id).cloned());
        self.helper_code.send_if_modified(|c| {
            let changed = *c != code;
            *c = code;
            changed
        });
    }

    pub(crate) fn set_server_addrs(&self, addrs: Vec<String>) {
        let changed = {
            let mut cur = self.server_addrs.lock().unwrap();
            let changed = *cur != addrs;
            *cur = addrs;
            changed
        };
        if changed {
            self.notify();
        }
    }

    pub(crate) fn set_server_fronts(&self, fronts: Vec<String>) {
        let changed = {
            let mut cur = self.server_fronts.lock().unwrap();
            let changed = cur.as_ref() != Some(&fronts);
            *cur = Some(fronts);
            changed
        };
        if changed {
            self.notify();
        }
    }

    pub(crate) fn offered_routes(&self, id: i64) -> Vec<Ipv4Net> {
        self.offered_routes.lock().unwrap().get(&id).cloned().unwrap_or_default()
    }

    /// Who routes each network: of the connected nodes offering an approved
    /// network, the oldest, so the choice does not flap
    fn route_owners(&self, nodes: &[NodeRow], now: i64) -> HashMap<Ipv4Net, i64> {
        let offered = self.offered_routes.lock().unwrap();
        let online = self.online.lock().unwrap();
        let mut owners: HashMap<Ipv4Net, i64> = HashMap::new();
        for n in nodes.iter().filter(|n| online.contains_key(&n.id) && !n.expired(now)) {
            for r in offered.get(&n.id).into_iter().flatten().filter(|r| n.approved_routes.contains(r)) {
                owners.entry(*r).and_modify(|o| *o = (*o).min(n.id)).or_insert(n.id);
            }
        }
        owners
    }

    /// Runs the clock-driven work: expiring keys (by sending new netmaps),
    /// removing inactive devices, and saving last-seen times
    pub(crate) async fn maintain(self) {
        let period = Duration::from_secs(crate::db::day_secs().clamp(1, 60) as u64);
        let mut expired: std::collections::HashSet<i64> = Default::default();
        let mut tick = tokio::time::interval(period);
        let mut last_save = std::time::Instant::now();
        loop {
            tick.tick().await;
            let now = crate::db::now_unix();
            let Ok(nodes) = self.db.all_nodes().await else { continue };
            let now_expired: std::collections::HashSet<i64> = nodes.iter().filter(|n| n.expired(now)).map(|n| n.id).collect();
            let mut changed = now_expired != expired;
            for id in now_expired.difference(&expired) {
                tracing::info!(node_id = id, "device key expired");
            }
            expired = now_expired;
            match self.db.remove_inactive(&|id| self.is_online(id)) {
                Ok(gone) if !gone.is_empty() => {
                    tracing::info!(?gone, "removed devices not seen for too long");
                    changed = true;
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("removing inactive devices: {e:#}"),
            }
            if changed {
                self.notify();
            }
            if last_save.elapsed() >= Duration::from_secs(600) {
                last_save = std::time::Instant::now();
                if let Err(e) = self.db.save() {
                    tracing::warn!("saving the server state: {e:#}");
                }
            }
        }
    }

    pub(crate) fn is_exit_node(&self, id: i64) -> bool {
        self.exit_nodes.lock().unwrap().contains(&id)
    }

    pub(crate) fn is_online(&self, id: i64) -> bool {
        self.online.lock().unwrap().contains_key(&id)
    }

    fn set_online(&self, id: i64, delta: isize) {
        let mut online = self.online.lock().unwrap();
        let count = online.entry(id).or_insert(0);
        *count = count.saturating_add_signed(delta);
        if *count == 0 {
            online.remove(&id);
        }
    }

    /// Never waits. A full or missing inbox drops the frame.
    fn forward(&self, from: &Key, frame: Bytes) {
        let Some((to, _)) = relay::parse(&frame) else {
            return;
        };
        let Some(inbox) = self.relays.lock().unwrap().by_key.get(&to).map(|(_, tx)| tx.clone()) else {
            return;
        };
        let mut frame = Vec::from(frame);
        relay::set_key(&mut frame, from);
        let _ = inbox.try_send(Bytes::from(frame));
    }

    /// `None` if the node no longer exists
    async fn netmap_for(&self, node_id: i64) -> Result<Option<NetMap>> {
        let now = crate::db::now_unix();
        let nodes = self.db.all_nodes().await?;
        let owners = self.route_owners(&nodes, now);
        let online = self.online.lock().unwrap().clone();
        let exits = self.exit_nodes.lock().unwrap().clone();
        let acl = self.db.acl();
        let Some(me) = nodes.iter().find(|n| n.id == node_id) else { return Ok(None) };
        let expired = me.expired(now);
        let viewer = crate::acl::Member { id: me.id, tags: &me.tags };
        let routes_of = |id: i64| {
            let mut r: Vec<Ipv4Net> = owners.iter().filter(|(_, o)| **o == id).map(|(r, _)| *r).collect();
            r.sort();
            r
        };
        let to_node = |n: &NodeRow, accept| Node {
            online: online.contains_key(&n.id),
            exit_node: exits.contains(&n.id) && online.contains_key(&n.id),
            id: n.id,
            hostname: n.hostname.clone(),
            os: n.os.clone(),
            node_key: n.node_key,
            ip: n.ip,
            endpoints: n.endpoints.clone(),
            dns_name: n.dns_name.clone(),
            accept,
            routes: routes_of(n.id),
        };
        // Devices that may not talk either way do not see each other at all,
        // and one whose key expired sees and is seen by nobody
        let peers = nodes
            .iter()
            .filter(|n| n.id != node_id && !expired && !n.expired(now))
            .filter_map(|n| {
                let accept = crate::acl::view(acl.as_ref(), &viewer, &crate::acl::Member { id: n.id, tags: &n.tags })?;
                Some(to_node(n, accept))
            })
            .collect();
        Ok(Some(NetMap {
            self_node: to_node(me, retail_proto::acl::Accept::All),
            peers,
            stun_servers: self.stun_servers.lock().unwrap().clone(),
            helper: self.db.helper_device() == Some(node_id) && !expired,
            expires_at: me.expires_at,
            expired,
            server_addrs: self.server_addrs.lock().unwrap().clone(),
            server_fronts: self.server_fronts.lock().unwrap().clone(),
        }))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/register", post(register))
        .route("/api/v1/poll", get(poll))
        .route("/api/v1/tunnel", get(crate::tunnel::websocket))
        .route("/api/v1/tunnel/poll", post(crate::tunnel::poll_open))
        .route("/api/v1/tunnel/poll/{id}", get(crate::tunnel::poll_down).post(crate::tunnel::poll_up))
        .with_state(state)
}

impl AppState {
    pub(crate) fn polls(&self) -> &Mutex<HashMap<String, Arc<crate::tunnel::PollSession>>> {
        &self.polls
    }
}

/// Plain HTTP connections only reach the tunnel endpoints
fn insecure(peer: &crate::tls::PeerAddr) -> Option<Response> {
    (!peer.1).then(|| api_error(StatusCode::FORBIDDEN, "use HTTPS"))
}

fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into(), reason: None })).into_response()
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<crate::tls::PeerAddr>,
    body: Bytes,
) -> Response {
    if let Some(r) = insecure(&peer) {
        return r;
    }
    // Parsed here so the check above comes first
    let Ok(req) = serde_json::from_slice::<RegisterRequest>(&body) else {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "malformed registration request");
    };
    if !state.register_allowed(peer.0.ip()) {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again in a minute");
    }
    match state.db.register(&req).await {
        Ok(resp) => {
            tracing::info!(node_id = resp.node_id, ip = %resp.ip, hostname = %req.hostname, "node registered");
            state.notify();
            Json::<RegisterResponse>(resp).into_response()
        }
        Err(RegisterError::InvalidAuthKey) => {
            api_error(StatusCode::UNAUTHORIZED, "invalid, used or expired auth key")
        }
        Err(RegisterError::KeyInUse) => {
            api_error(StatusCode::CONFLICT, "this device key is registered already; only that device can register it again")
        }
        Err(RegisterError::AddressSpaceExhausted) => {
            api_error(StatusCode::INSUFFICIENT_STORAGE, "no free addresses left")
        }
        Err(RegisterError::Internal(e)) => {
            tracing::error!("register failed: {e:#}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

async fn poll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<crate::tls::PeerAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Some(r) = insecure(&peer) {
        return r;
    }
    let Some(token) = bearer(&headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    let node_id = match state.db.node_id_by_token(token).await {
        Ok(Some(id)) => id,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "unknown token"),
        Err(e) => {
            tracing::error!("token lookup failed: {e:#}");
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let ws = ws
        .max_message_size(MAX_CLIENT_MESSAGE)
        .max_frame_size(MAX_CLIENT_MESSAGE)
        .read_buffer_size(16 * 1024)
        .write_buffer_size(64 * 1024)
        .max_write_buffer_size(512 * 1024);
    ws.on_upgrade(move |socket| async move {
        state.set_online(node_id, 1);
        state.notify();
        tracing::info!(node_id, "node connected");
        if let Err(e) = serve_node(&state, node_id, socket).await {
            tracing::debug!(node_id, "poll connection ended: {e:#}");
        }
        state.set_online(node_id, -1);
        state.notify();
        tracing::info!(node_id, "node disconnected");
    })
}

async fn serve_node(state: &AppState, node_id: i64, socket: WebSocket) -> Result<()> {
    let key = state.db.all_nodes().await?.into_iter().find(|n| n.id == node_id).map(|n| n.node_key);
    let Some(key) = key else { return Ok(()) };
    let conn = state.next_conn.fetch_add(1, Ordering::Relaxed);
    let (inbox_tx, inbox) = mpsc::channel(RELAY_QUEUE);
    state.relays.lock().unwrap().by_key.insert(key, (conn, inbox_tx));
    let result = serve_connection(state, node_id, key, socket, inbox).await;
    let mut relays = state.relays.lock().unwrap();
    if relays.by_key.get(&key).is_some_and(|(c, _)| *c == conn) {
        relays.by_key.remove(&key);
        // The exit node and route offers end with the node's newest connection
        state.exit_nodes.lock().unwrap().remove(&node_id);
        state.offered_routes.lock().unwrap().remove(&node_id);
        // So does a helper node on it
        if state.helper_codes.lock().unwrap().remove(&node_id).is_some() {
            state.refresh_helper_code();
        }
    }
    result
}

async fn serve_connection(
    state: &AppState,
    node_id: i64,
    key: Key,
    mut socket: WebSocket,
    mut inbox: mpsc::Receiver<Bytes>,
) -> Result<()> {
    let mut changes = state.changes.subscribe();
    let mut shutdown = state.shutdown.subscribe();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    let mut last_sent: Option<String> = None;
    // An expired node may not relay to anyone, cause netmap rounds or act as helper
    let mut blocked = true;
    let mut pending_endpoints: Option<Vec<std::net::SocketAddr>> = None;
    let mut endpoints_due = tokio::time::Instant::now();
    let mut endpoints_applied: std::collections::VecDeque<tokio::time::Instant> = Default::default();
    // Send the first netmap immediately
    changes.mark_changed();

    loop {
        tokio::select! {
            biased;
            changed = changes.changed() => {
                changed?;
                let Some(nm) = state.netmap_for(node_id).await? else {
                    tracing::info!(node_id, "node was deleted; closing its connection");
                    let _ = socket.send(Message::Close(None)).await;
                    return Ok(());
                };
                blocked = nm.expired;
                // Expiry ends the helper role here, without relying on the device to withdraw
                if blocked && state.helper_codes.lock().unwrap().remove(&node_id).is_some() {
                    state.refresh_helper_code();
                }
                let json = serde_json::to_string(&ServerMessage::NetMap(nm))?;
                if last_sent.as_deref() != Some(json.as_str()) {
                    socket.send(Message::Text(json.clone().into())).await?;
                    last_sent = Some(json);
                }
            }
            // Ahead of the socket so a busy relay cannot starve it
            _ = tokio::time::sleep_until(endpoints_due), if pending_endpoints.is_some() => {
                let endpoints = pending_endpoints.take().unwrap_or_default();
                let now = tokio::time::Instant::now();
                endpoints_applied.push_back(now);
                if endpoints_applied.len() > ENDPOINTS_BURST {
                    endpoints_applied.pop_front();
                }
                endpoints_due = if endpoints_applied.len() == ENDPOINTS_BURST {
                    endpoints_applied[0] + ENDPOINTS_WINDOW
                } else {
                    now
                };
                if state.db.set_endpoints(node_id, &endpoints).await? && !blocked {
                    tracing::debug!(node_id, ?endpoints, "endpoints updated");
                    state.notify();
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Endpoints { mut endpoints }) => {
                            endpoints.truncate(MAX_ENDPOINTS);
                            pending_endpoints = Some(endpoints);
                        }
                        Ok(ClientMessage::Hostinfo { exit_node, mut routes }) => {
                            let mut changed = {
                                let mut exits = state.exit_nodes.lock().unwrap();
                                if exit_node { exits.insert(node_id) } else { exits.remove(&node_id) }
                            };
                            if changed {
                                tracing::info!(node_id, exit_node, "exit node offer changed");
                            }
                            routes.retain(|r| r.check_route().is_ok());
                            routes.sort();
                            routes.dedup();
                            routes.truncate(retail_proto::route::MAX_ROUTES);
                            {
                                let mut offered = state.offered_routes.lock().unwrap();
                                let before = offered.get(&node_id).cloned().unwrap_or_default();
                                if before != routes {
                                    tracing::info!(node_id, ?routes, "routes offered");
                                    changed = true;
                                    if routes.is_empty() { offered.remove(&node_id) } else { offered.insert(node_id, routes) };
                                }
                            }
                            if changed {
                                state.notify();
                            }
                        }
                        Ok(ClientMessage::HelperCode { code }) => {
                            // A device whose key expired is no longer the helper
                            let code = if blocked { None } else { code };
                            tracing::info!(node_id, ready = code.is_some(), "helper device reported");
                            {
                                let mut codes = state.helper_codes.lock().unwrap();
                                match code {
                                    Some(c) if c.len() < 4096 => codes.insert(node_id, c),
                                    _ => codes.remove(&node_id),
                                };
                            }
                            state.refresh_helper_code();
                        }
                        Err(e) => tracing::warn!(node_id, "bad client message: {e}"),
                    },
                    Some(Ok(Message::Binary(frame))) if !blocked => state.forward(&key, frame),
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                }
            }
            Some(frame) = inbox.recv() => {
                // Frames already queued go out with it, flushed together
                let mut bytes = frame.len();
                socket.feed(Message::Binary(frame)).await?;
                while bytes < RELAY_BATCH_BYTES {
                    let Ok(next) = inbox.try_recv() else { break };
                    bytes += next.len();
                    socket.feed(Message::Binary(next)).await?;
                }
                socket.flush().await?;
            }
            Ok(()) = shutdown.changed() => {
                let stopping = *shutdown.borrow_and_update();
                if stopping {
                    let _ = socket.send(Message::Close(None)).await;
                    return Ok(());
                }
            }
            _ = ping.tick() => {
                socket.send(Message::Ping(Vec::new().into())).await?;
                state.db.touch(node_id).await?;
            }
        }
    }
}
