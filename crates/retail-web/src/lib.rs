//! Web admin page for a network hosted by retaild. Reachable from two places
//! only, never the internet:
//! - this device, at `127.0.0.1`: a one-time login link (from the tray or
//!   `retail server web`) is exchanged for a session cookie, since any local
//!   program can reach loopback
//! - devices of the network the host allowed, at the host's mesh address.
//!   WireGuard authenticates the source address, so they need no login.
//!
//! Every request must name the listener in `Host` (defeats DNS rebinding), and
//! every change needs the `X-Retail-Web` header, which other sites cannot send
//! without a CORS preflight that is never answered.

mod package;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use retail_proto::api::{ApiError, InviteRequest, InviteResponse, ServerStatus};
use serde::{Deserialize, Serialize};

pub use package::ClientSource;

pub type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// What the page drives, implemented by the daemon
pub trait Backend: Send + Sync + 'static {
    fn status(&self) -> BoxFut<'_, ServerStatus>;
    fn start(&self) -> BoxFut<'_, Result<(), String>>;
    fn stop(&self) -> BoxFut<'_, Result<(), String>>;
    fn invite(&self, req: InviteRequest) -> BoxFut<'_, Result<InviteResponse, String>>;
    fn named_code(&self, id: i64) -> BoxFut<'_, Result<String, String>>;
    fn revoke(&self, id: i64) -> BoxFut<'_, Result<(), String>>;
    fn delete_node(&self, id: i64) -> BoxFut<'_, Result<(), String>>;
    /// Node ids allowed to open this page over the network
    fn admins(&self) -> Vec<i64>;
    fn set_admin(&self, id: i64, allowed: bool) -> Result<(), String>;
    /// This device's address in the network it hosts, while it is a member
    fn own_ip(&self) -> BoxFut<'_, Option<Ipv4Addr>>;
    /// Prebuilt clients this device can hand out, one per OS and architecture
    fn clients(&self) -> Vec<ClientSource>;
    /// Where uploaded files for a client variant go
    fn upload_dir(&self, variant: &str) -> Option<PathBuf>;
    /// Fetches a client's missing files from the official release
    fn fetch_client(&self, variant: &str) -> BoxFut<'_, Result<(), String>>;
}

/// Uploaded program files may be this large
const MAX_UPLOAD: usize = 200 << 20;

const SESSION_COOKIE: &str = "retail_web";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const LOGIN_TTL: Duration = Duration::from_secs(120);
const CHANGE_HEADER: &str = "x-retail-web";

#[derive(Clone)]
pub struct WebAdmin {
    backend: Arc<dyn Backend>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    logins: Arc<Mutex<HashMap<String, Instant>>>,
    port: u16,
}

#[derive(Clone, Copy, PartialEq)]
enum Listener {
    Local,
    Mesh(Ipv4Addr),
}

#[derive(Clone)]
struct Ctx {
    web: WebAdmin,
    listener: Listener,
}

impl WebAdmin {
    pub fn new(backend: Arc<dyn Backend>, port: u16) -> Self {
        WebAdmin { backend, sessions: Arc::default(), logins: Arc::default(), port }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// A link that signs the browser in once, within two minutes
    pub fn login_link(&self) -> String {
        let token = random_token();
        let mut logins = self.logins.lock().unwrap();
        logins.retain(|_, t| t.elapsed() < LOGIN_TTL);
        logins.insert(token.clone(), Instant::now());
        format!("http://127.0.0.1:{}/login?t={token}", self.port)
    }

    /// Serves this device's browser until the listener fails
    pub async fn serve_local(&self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        self.serve(listener, Listener::Local).await
    }

    /// Serves allowed devices of the network at this device's mesh address
    pub async fn serve_mesh(&self, listener: tokio::net::TcpListener, ip: Ipv4Addr) -> std::io::Result<()> {
        self.serve(listener, Listener::Mesh(ip)).await
    }

    async fn serve(&self, listener: tokio::net::TcpListener, which: Listener) -> std::io::Result<()> {
        let ctx = Ctx { web: self.clone(), listener: which };
        let app = Router::new()
            .route("/", get(page))
            .route("/login", get(login))
            .route("/api/status", get(status))
            .route("/api/server/start", post(start))
            .route("/api/server/stop", post(stop))
            .route("/api/invites", post(create_invite))
            .route("/api/invites/{id}/code", post(named_code))
            .route("/api/invites/{id}/revoke", post(revoke))
            .route("/api/nodes/{id}/delete", post(delete_node))
            .route("/api/nodes/{id}/admin", post(set_admin))
            .route("/api/qr", post(qr))
            .route("/api/clients/{variant}/fetch", post(fetch_client))
            .route(
                "/api/clients/{variant}/{name}",
                post(upload).layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD)),
            )
            .route("/download/{invite}/{variant}", get(download))
            .layer(middleware::from_fn_with_state(ctx.clone(), guard))
            .with_state(ctx);
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
    }
}

fn random_token() -> String {
    use base64::Engine;
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn deny(status: StatusCode, msg: &str) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// The exact `Host` values each listener answers to
fn host_ok(headers: &HeaderMap, which: Listener, port: u16) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else { return false };
    match which {
        Listener::Local => host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}"),
        Listener::Mesh(ip) => host == format!("{ip}:{port}"),
    }
}

async fn guard(State(ctx): State<Ctx>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let port = ctx.web.port;
    if !host_ok(req.headers(), ctx.listener, port) {
        return deny(StatusCode::FORBIDDEN, "unexpected Host");
    }
    if req.method() != Method::GET && req.method() != Method::POST {
        return deny(StatusCode::METHOD_NOT_ALLOWED, "GET or POST");
    }
    if req.method() == Method::POST {
        let origin_ok = req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok()).is_none_or(|o| {
            let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
            o == format!("http://{host}")
        });
        if !req.headers().contains_key(CHANGE_HEADER) || !origin_ok {
            return deny(StatusCode::FORBIDDEN, "changes need the page's own requests");
        }
    }
    let allowed = match ctx.listener {
        Listener::Local => {
            req.uri().path() == "/login" || {
                let sessions = &ctx.web.sessions;
                cookie(req.headers(), SESSION_COOKIE).is_some_and(|s| {
                    let mut map = sessions.lock().unwrap();
                    map.retain(|_, t| t.elapsed() < SESSION_TTL);
                    map.contains_key(&s)
                })
            }
        }
        Listener::Mesh(own) => mesh_allowed(&ctx, peer.ip(), own).await,
    };
    if !allowed {
        if req.method() == Method::GET && req.uri().path() == "/" && ctx.listener == Listener::Local {
            return (StatusCode::UNAUTHORIZED, Html(SIGN_IN_PAGE)).into_response();
        }
        return deny(StatusCode::UNAUTHORIZED, "not allowed");
    }
    next.run(req).await
}

/// WireGuard only lets a peer send from its own mesh address, which maps to
/// the node the host allowed. This device's own address does not count:
/// local programs reach that too.
async fn mesh_allowed(ctx: &Ctx, peer: IpAddr, own: Ipv4Addr) -> bool {
    let IpAddr::V4(ip) = peer.to_canonical() else { return false };
    if ip == own || !retail_proto::in_mesh(ip) {
        return false;
    }
    let admins = ctx.web.backend.admins();
    if admins.is_empty() {
        return false;
    }
    let status = ctx.web.backend.status().await;
    status.nodes.iter().any(|n| n.ip == ip && admins.contains(&n.id))
}

async fn login(State(ctx): State<Ctx>, uri: axum::http::Uri) -> Response {
    let token = uri.query().unwrap_or("").split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("").to_string();
    let valid = {
        let mut logins = ctx.web.logins.lock().unwrap();
        logins.remove(&token).is_some_and(|t| t.elapsed() < LOGIN_TTL)
    };
    if !valid || ctx.listener != Listener::Local {
        return (StatusCode::UNAUTHORIZED, Html(SIGN_IN_PAGE)).into_response();
    }
    let session = random_token();
    ctx.web.sessions.lock().unwrap().insert(session.clone(), Instant::now());
    let cookie = format!("{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", SESSION_TTL.as_secs());
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn page() -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Html(PAGE)).into_response()
}

#[derive(Serialize)]
struct StatusView {
    server: ServerStatus,
    admins: Vec<i64>,
    own_ip: Option<Ipv4Addr>,
    clients: Vec<ClientView>,
    /// Where allowed devices open this page
    mesh_url: Option<String>,
}

#[derive(Serialize)]
struct ClientView {
    id: String,
    label: String,
    missing: Vec<String>,
    fetchable: bool,
}

async fn status(State(ctx): State<Ctx>) -> Response {
    let b = &ctx.web.backend;
    let own_ip = b.own_ip().await;
    let view = StatusView {
        server: b.status().await,
        admins: b.admins(),
        own_ip,
        clients: b
            .clients()
            .into_iter()
            .map(|c| ClientView { id: c.id, label: c.label, missing: c.missing, fetchable: c.fetchable })
            .collect(),
        mesh_url: own_ip.map(|ip| format!("http://{ip}:{}", ctx.web.port)),
    };
    Json(view).into_response()
}

fn done(r: Result<(), String>) -> Response {
    match r {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => deny(StatusCode::BAD_REQUEST, &e),
    }
}

async fn start(State(ctx): State<Ctx>) -> Response {
    done(ctx.web.backend.start().await)
}

async fn stop(State(ctx): State<Ctx>) -> Response {
    done(ctx.web.backend.stop().await)
}

async fn create_invite(State(ctx): State<Ctx>, Json(req): Json<InviteRequest>) -> Response {
    match ctx.web.backend.invite(req).await {
        Ok(inv) => Json(inv).into_response(),
        Err(e) => deny(StatusCode::BAD_REQUEST, &e),
    }
}

async fn named_code(State(ctx): State<Ctx>, Path(id): Path<i64>) -> Response {
    match ctx.web.backend.named_code(id).await {
        Ok(code) => Json(InviteResponse { code, expires_at: 0 }).into_response(),
        Err(e) => deny(StatusCode::BAD_REQUEST, &e),
    }
}

async fn revoke(State(ctx): State<Ctx>, Path(id): Path<i64>) -> Response {
    done(ctx.web.backend.revoke(id).await)
}

async fn delete_node(State(ctx): State<Ctx>, Path(id): Path<i64>) -> Response {
    done(ctx.web.backend.delete_node(id).await)
}

#[derive(Deserialize)]
struct AdminReq {
    allowed: bool,
}

async fn set_admin(State(ctx): State<Ctx>, Path(id): Path<i64>, Json(req): Json<AdminReq>) -> Response {
    done(ctx.web.backend.set_admin(id, req.allowed))
}

/// Stores one program file for a client variant (a macOS build, say), so
/// the page can hand that client out. Only the files a client needs are
/// accepted, and only if they are executables for that system.
async fn upload(State(ctx): State<Ctx>, Path((variant, name)): Path<(String, String)>, body: axum::body::Body) -> Response {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let Some(dir) = ctx.web.backend.upload_dir(&variant) else {
        return deny(StatusCode::NOT_FOUND, "no such client");
    };
    let os = variant.split('-').next().unwrap_or("");
    let exe = |n: &str| if os == "windows" { format!("{n}.exe") } else { n.to_string() };
    let mut wanted = vec![exe("retail-tray"), exe("retaild"), exe("retail")];
    if os == "windows" {
        wanted.push("wintun.dll".into());
    }
    if !wanted.contains(&name) {
        return deny(StatusCode::BAD_REQUEST, &format!("expected one of: {}", wanted.join(", ")));
    }
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return deny(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    let tmp = dir.join(format!("{name}.upload"));
    let result: Result<(), String> = async {
        let mut file = tokio::fs::File::create(&tmp).await.map_err(|e| e.to_string())?;
        let mut stream = body.into_data_stream();
        let mut head: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            if head.len() < 4 {
                head.extend_from_slice(&chunk[..chunk.len().min(4 - head.len())]);
            }
            file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        file.flush().await.map_err(|e| e.to_string())?;
        if !executable_for(os, &head) {
            return Err(format!("this is not a {os} program file"));
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return deny(StatusCode::BAD_REQUEST, &e);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    match tokio::fs::rename(&tmp, dir.join(&name)).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => deny(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// PE for Windows, ELF for Linux, Mach-O (or universal) for macOS
fn executable_for(os: &str, head: &[u8]) -> bool {
    match os {
        "windows" => head.starts_with(b"MZ"),
        "linux" => head.starts_with(b"\x7fELF"),
        "macos" => matches!(head, [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]),
        _ => false,
    }
}

#[derive(Deserialize)]
struct QrReq {
    text: String,
}

/// An SVG QR code, so phones can scan invite codes off the page
async fn qr(Json(req): Json<QrReq>) -> Response {
    if req.text.len() > 2048 {
        return deny(StatusCode::PAYLOAD_TOO_LARGE, "too long for a QR code");
    }
    let Ok(code) = qrcode::QrCode::new(req.text.as_bytes()) else {
        return deny(StatusCode::BAD_REQUEST, "cannot encode");
    };
    let n = code.width();
    let quiet = 4;
    let size = n + 2 * quiet;
    let mut path = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            path.push_str(&format!("M{} {}h1v1h-1z", i % n + quiet, i / n + quiet));
        }
    }
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges"><rect width="{size}" height="{size}" fill="#fff"/><path d="{path}" fill="#000"/></svg>"##
    );
    ([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "no-store")], svg).into_response()
}

async fn fetch_client(State(ctx): State<Ctx>, Path(variant): Path<String>) -> Response {
    done(ctx.web.backend.fetch_client(&variant).await)
}

/// A client for one OS with the named invite's current code inside. Missing
/// program files come from the official release first, when possible.
async fn download(State(ctx): State<Ctx>, Path((invite, variant)): Path<(i64, String)>) -> Response {
    let b = &ctx.web.backend;
    let find = || b.clients().into_iter().find(|c| c.id == variant);
    let Some(mut source) = find() else {
        return deny(StatusCode::NOT_FOUND, "no such client");
    };
    if !source.missing.is_empty() && source.fetchable {
        if let Err(e) = b.fetch_client(&variant).await {
            return deny(StatusCode::BAD_GATEWAY, &e);
        }
        match find() {
            Some(s) => source = s,
            None => return deny(StatusCode::NOT_FOUND, "no such client"),
        }
    }
    if !source.missing.is_empty() {
        return deny(StatusCode::NOT_FOUND, &format!("files missing for this client: {}", source.missing.join(", ")));
    }
    let code = match b.named_code(invite).await {
        Ok(c) => c,
        Err(e) => return deny(StatusCode::BAD_REQUEST, &e),
    };
    let status = b.status().await;
    let name = status.invites.iter().find(|i| i.id == invite).and_then(|i| i.name.clone()).unwrap_or_default();
    match package::build(&source, &code, &name).await {
        Ok((len, body)) => {
            let file = package::file_name(&source, &name);
            let disposition = format!("attachment; filename=\"{file}\"");
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_LENGTH, len.to_string()),
                    (header::CONTENT_DISPOSITION, disposition),
                    (header::CACHE_CONTROL, "no-store".to_string()),
                ],
                body,
            )
                .into_response()
        }
        Err(e) => deny(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}")),
    }
}

/// Directory of prebuilt clients for other systems: `<dir>/<os>-<arch>/`
pub fn clients_dir(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("clients")
}

const PAGE: &str = include_str!("page.html");

const SIGN_IN_PAGE: &str = r#"<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>retail</title><style>body{font:15px system-ui,sans-serif;background:#f6f7f9;color:#1f2328;display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#fff;border-radius:14px;padding:28px 32px;max-width:420px;box-shadow:0 1px 3px #0001}h1{font-size:18px;margin:0 0 10px}code{background:#eef2ff;padding:2px 6px;border-radius:6px}
@media(prefers-color-scheme:dark){body{background:#16181d;color:#e6e8eb}main{background:#1f2228}code{background:#24304a}}</style>
<main><h1>로그인이 필요합니다</h1><p>트레이의 서버 창에서 <b>웹에서 열기</b>를 누르거나, 이 PC에서 <code>retail server web</code>을 실행하세요. 링크는 2분 동안 한 번만 쓸 수 있습니다.</p></main></html>"#;

#[cfg(test)]
mod tests;
