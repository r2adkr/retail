//! Loopback HTTP API for the `retail` CLI. Every request needs the
//! `X-Retail-Local` header (a custom header forces a CORS preflight, which is
//! never answered) and a loopback `Host` (defeats DNS rebinding). Requests that
//! change anything also need the token from `retail_proto::local::token_path`,
//! readable only by users allowed to control retail. Stopping the daemon and
//! giving a proxy the Windows sign-in need the administrator token
//! (`retail_proto::local::admin_token_path`).

use std::sync::Arc;

use axum::extract::Path;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use retail_proto::api::{
    ApiError, HelperStartRequest, HelperStatus, InviteRequest, PrefsRequest, ServerSelect,
    ServerStartRequest, SystemProxy, UpRequest,
};

use crate::backend::Backend;

pub const LOCAL_HEADER: &str = "x-retail-local";

/// Whether the request carried the administrator token
#[derive(Clone, Copy)]
struct Admin(bool);

pub fn router(
    backend: Arc<Backend>,
    token: Arc<String>,
    admin: Arc<String>,
    api: std::net::SocketAddr,
) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/up", post(up))
        .route("/down", post(down))
        .route("/logout", post(logout))
        .route("/update/check", post(update_check))
        .route("/update/install", post(update_install))
        .route("/servers/switch", post(switch_server))
        .route("/servers/forget", post(forget_server))
        .route("/prefs", post(prefs))
        .route("/wake", post(wake))
        .route("/files/{id}/accept", post(accept_file))
        .route("/files/{id}/decline", post(decline_file))
        .route("/server", get(server_status))
        .route("/server/start", post(server_start))
        .route("/server/stop", post(server_stop))
        .route("/server/invite", post(server_invite))
        .route("/server/nodes/{id}/delete", post(server_delete_node))
        .route("/server/nodes/{id}/tags", post(server_tags))
        .route("/server/nodes/{id}/routes", post(server_routes))
        .route("/server/nodes/{id}/renew", post(server_renew))
        .route("/server/expiry", post(server_expiry))
        .route("/server/backup", post(server_backup))
        .route("/server/restore", post(server_restore))
        .route("/server/acl", post(server_acl))
        .route("/server/helper-device", post(server_helper_device))
        .route("/server/tunnel", post(server_tunnel))
        .route("/server/invites/{id}/revoke", post(server_revoke_invite))
        // POST so the guard asks for the token: the answer is a reusable invite
        .route("/server/invites/{id}/code", post(server_named_code))
        // The installer of a named invite, for the tray's server window
        .route(
            "/server/invites/{id}/package/{variant}",
            post(server_package),
        )
        .route("/helper", get(helper_status))
        // POST so the guard asks for the token: the code carries the helper's secret
        .route("/helper/status", post(helper_status_with_code))
        .route("/helper/start", post(helper_start))
        .route("/helper/stop", post(helper_stop))
        .route("/proxy/system", post(system_proxy))
        .route("/web/login", post(web_login))
        .route("/shutdown", post(shutdown))
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            guard(token.clone(), admin.clone(), api, req, next)
        }))
        .with_state(backend)
}

async fn guard(
    token: Arc<String>,
    admin: Arc<String>,
    api: std::net::SocketAddr,
    mut req: Request,
    next: Next,
) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.rsplit_once(':').map_or(h, |(name, _)| name))
        .is_some_and(|name| matches!(name, "127.0.0.1" | "localhost" | "[::1]"));
    if !host_ok || !req.headers().contains_key(LOCAL_HEADER) {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    let user = peer.and_then(|p| local_user(p, api));
    if req.method() != axum::http::Method::GET {
        let given = req
            .headers()
            .get(retail_proto::local::TOKEN_HEADER)
            .map(|v| v.as_bytes());
        let ok = given.is_some_and(|g| same_secret(g, token.as_bytes())) || user.is_some();
        if !ok {
            return error(
                StatusCode::FORBIDDEN,
                "not allowed: run as administrator/root, or (Linux) join the `retail` group",
            );
        }
    }
    let is_admin = req
        .headers()
        .get(retail_proto::local::ADMIN_HEADER)
        .is_some_and(|g| same_secret(g.as_bytes(), admin.as_bytes()))
        || user == Some(LocalUser::Root);
    req.extensions_mut().insert(Admin(is_admin));
    next.run(req).await
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum LocalUser {
    Root,
    Member,
}

/// On Linux, who is asking, from the kernel's socket table: root, or a
/// member of the `retail` group as /etc/group says now. A user added to the
/// group can use the tray app at once, before signing in again gives their
/// processes the group (and the token file). Elsewhere the token decides.
#[cfg(target_os = "linux")]
fn local_user(peer: std::net::SocketAddr, api: std::net::SocketAddr) -> Option<LocalUser> {
    let uid = retail_proto::listener::peer_uid(peer, api)?;
    if uid == 0 {
        return Some(LocalUser::Root);
    }
    in_group(uid, "retail").then_some(LocalUser::Member)
}

#[cfg(not(target_os = "linux"))]
fn local_user(_peer: std::net::SocketAddr, _api: std::net::SocketAddr) -> Option<LocalUser> {
    None
}

/// Whether the user is in `group`, by name in its member list or as their
/// primary group
#[cfg(target_os = "linux")]
fn in_group(uid: u32, group: &str) -> bool {
    let (Ok(passwd), Ok(groups)) = (
        std::fs::read_to_string("/etc/passwd"),
        std::fs::read_to_string("/etc/group"),
    ) else {
        return false;
    };
    let Some((name, primary)) = passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2].parse() == Ok(uid)).then(|| (f[0].to_string(), f[3].to_string()))
    }) else {
        return false;
    };
    groups.lines().any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        f.len() > 3 && f[0] == group && (f[2] == primary || f[3].split(',').any(|m| m == name))
    })
}

/// Ends the daemon the way a service stop would, undoing its system changes
/// (Windows has no stop signal for it). Administrators only.
async fn shutdown(
    State(b): State<Arc<Backend>>,
    axum::Extension(Admin(admin)): axum::Extension<Admin>,
) -> Response {
    if !admin {
        return error(
            StatusCode::FORBIDDEN,
            "only an administrator can stop retaild",
        );
    }
    b.stop_requested.notify_one();
    StatusCode::NO_CONTENT.into_response()
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: msg.into(),
            reason: None,
        }),
    )
        .into_response()
}

fn failed(e: anyhow::Error) -> Response {
    error(StatusCode::BAD_REQUEST, format!("{e:#}"))
}

/// `failed` for a request that contacts the server: says why it could not be reached
fn not_reached(e: anyhow::Error) -> Response {
    let reason =
        Some(crate::failure::classify(&e)).filter(|r| *r != retail_proto::api::FailReason::Other);
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: format!("{e:#}"),
            reason,
        }),
    )
        .into_response()
}

async fn status(State(b): State<Arc<Backend>>) -> Response {
    Json(b.status().await).into_response()
}

async fn up(State(b): State<Arc<Backend>>, Json(req): Json<UpRequest>) -> Response {
    match b.up(req).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => not_reached(e),
    }
}

async fn down(State(b): State<Arc<Backend>>) -> Response {
    match b.down().await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn logout(State(b): State<Arc<Backend>>) -> Response {
    match b.logout().await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn update_check(State(b): State<Arc<Backend>>) -> Response {
    match b.updater.check().await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn update_install(State(b): State<Arc<Backend>>) -> Response {
    match b.updater.start_install() {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn switch_server(State(b): State<Arc<Backend>>, Json(req): Json<ServerSelect>) -> Response {
    match b.switch_server(&req.server).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => not_reached(e),
    }
}

async fn forget_server(State(b): State<Arc<Backend>>, Json(req): Json<ServerSelect>) -> Response {
    match b.forget_server(&req.server).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn prefs(
    State(b): State<Arc<Backend>>,
    axum::Extension(Admin(admin)): axum::Extension<Admin>,
    Json(req): Json<PrefsRequest>,
) -> Response {
    match b.set_prefs(req, admin).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn accept_file(
    State(b): State<Arc<Backend>>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Response {
    match b.accept_file(id).await {
        Ok((offer, body)) => {
            let mut r = Response::new(body);
            r.headers_mut()
                .insert(axum::http::header::CONTENT_LENGTH, offer.size.into());
            r.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            r
        }
        Err(e) => failed(e),
    }
}

async fn decline_file(
    State(b): State<Arc<Backend>>,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> Response {
    b.decline_file(id);
    Json(serde_json::json!({})).into_response()
}

async fn wake(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::WakeRequest>,
) -> Response {
    match b.wake(&req.peer).await {
        Ok(sent_by) => Json(retail_proto::api::WakeResponse { sent_by }).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_status(State(b): State<Arc<Backend>>) -> Response {
    Json(b.server_status().await).into_response()
}

async fn server_start(
    State(b): State<Arc<Backend>>,
    Json(req): Json<ServerStartRequest>,
) -> Response {
    match b.server_start(req).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_stop(State(b): State<Arc<Backend>>) -> Response {
    match b.server_stop().await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_named_code(State(b): State<Arc<Backend>>, Path(id): Path<i64>) -> Response {
    match b.host.named_code(id).await {
        Ok(code) => Json(retail_proto::api::InviteResponse {
            code,
            expires_at: 0,
        })
        .into_response(),
        Err(e) => failed(e),
    }
}

async fn server_package(
    State(b): State<Arc<Backend>>,
    Path((id, variant)): Path<(i64, String)>,
) -> Response {
    match b.web.get() {
        Some(web) => web.package(id, &variant).await,
        None => failed(anyhow::anyhow!(
            "the web admin page is off, which also makes installers"
        )),
    }
}

async fn helper_status(State(b): State<Arc<Backend>>) -> Response {
    Json(HelperStatus {
        code: None,
        ..b.helper.status().await
    })
    .into_response()
}

async fn helper_status_with_code(State(b): State<Arc<Backend>>) -> Response {
    Json(b.helper.status().await).into_response()
}

async fn helper_start(
    State(b): State<Arc<Backend>>,
    Json(req): Json<HelperStartRequest>,
) -> Response {
    match b.helper.start(&req).await {
        Ok(()) => Json(b.helper.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn helper_stop(State(b): State<Arc<Backend>>) -> Response {
    match b.helper.stop().await {
        Ok(()) => Json(b.helper.status().await).into_response(),
        Err(e) => failed(e),
    }
}

/// A one-time link that signs this device's browser in to the web admin page
async fn web_login(State(b): State<Arc<Backend>>) -> Response {
    match b.web.get() {
        Some(web) => Json(serde_json::json!({ "url": web.login_link() })).into_response(),
        None => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the web admin page is off (retaild --web-port)",
        ),
    }
}

/// From the tray app; held in memory only
async fn system_proxy(Json(req): Json<SystemProxy>) -> Response {
    crate::proxy::set_user(&req.proxies);
    Json(()).into_response()
}

async fn server_invite(State(b): State<Arc<Backend>>, Json(req): Json<InviteRequest>) -> Response {
    match b.server_invite(req).await {
        Ok(inv) => Json(inv).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_delete_node(
    State(b): State<Arc<Backend>>,
    Path(id): Path<i64>,
    body: axum::body::Bytes,
) -> Response {
    // The body is optional: older callers send none
    let req: retail_proto::api::RemoveRequest = match body.is_empty() {
        true => Default::default(),
        false => match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        },
    };
    match b.host.delete_node(id, req.revoke_invite).await {
        Ok(true) => Json(b.server_status().await).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such device"),
        Err(e) => failed(e),
    }
}

async fn server_tags(
    State(b): State<Arc<Backend>>,
    Path(id): Path<i64>,
    Json(req): Json<retail_proto::api::TagsRequest>,
) -> Response {
    match b.host.set_tags(id, &req.tags).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_routes(
    State(b): State<Arc<Backend>>,
    Path(id): Path<i64>,
    Json(req): Json<retail_proto::api::RoutesRequest>,
) -> Response {
    match b.host.set_routes(id, &req.routes).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_renew(
    State(b): State<Arc<Backend>>,
    Path(id): Path<i64>,
    Json(req): Json<retail_proto::api::RenewRequest>,
) -> Response {
    match b.host.renew(id, req.never).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_expiry(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::ExpiryRequest>,
) -> Response {
    match b
        .host
        .set_expiry(req.key_expiry_days, req.remove_inactive_days)
        .await
    {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_backup(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::BackupRequest>,
) -> Response {
    match b.host.backup(&req.passphrase).await {
        Ok(backup) => Json(retail_proto::api::BackupResponse { backup }).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_restore(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::RestoreRequest>,
) -> Response {
    match b.host.restore(&req.backup, &req.passphrase).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_acl(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::AclRequest>,
) -> Response {
    match b.host.set_acl(req.acl).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_helper_device(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::HelperDeviceRequest>,
) -> Response {
    match b.host.set_helper_device(req.id).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_tunnel(
    State(b): State<Arc<Backend>>,
    Json(req): Json<retail_proto::api::TunnelRequest>,
) -> Response {
    match b.host.set_tunnel(req.on).await {
        Ok(()) => Json(b.server_status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_revoke_invite(State(b): State<Arc<Backend>>, Path(id): Path<i64>) -> Response {
    match b.host.revoke_invite(id).await {
        Ok(true) => Json(b.server_status().await).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such invite"),
        Err(e) => failed(e),
    }
}

/// Runs in time independent of where the inputs differ
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
