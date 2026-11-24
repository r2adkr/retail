//! Loopback HTTP API for the `retail` CLI. Every request needs the
//! `X-Retail-Local` header (a custom header forces a CORS preflight, which is
//! never answered) and a loopback `Host` (defeats DNS rebinding). Requests that
//! change anything also need the token from `retail_proto::local::token_path`,
//! readable only by users allowed to control retail.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum::extract::Path;
use retail_proto::api::{
    ApiError, HelperStartRequest, InviteRequest, PrefsRequest, ServerStartRequest, SystemProxy, UpRequest,
};

use crate::backend::Backend;

pub const LOCAL_HEADER: &str = "x-retail-local";

pub fn router(backend: Arc<Backend>, token: Arc<String>) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/up", post(up))
        .route("/down", post(down))
        .route("/logout", post(logout))
        .route("/prefs", post(prefs))
        .route("/server", get(server_status))
        .route("/server/start", post(server_start))
        .route("/server/stop", post(server_stop))
        .route("/server/invite", post(server_invite))
        .route("/server/nodes/{id}/delete", post(server_delete_node))
        .route("/server/invites/{id}/revoke", post(server_revoke_invite))
        // POST so the guard asks for the token: the answer is a reusable invite
        .route("/server/invites/{id}/code", post(server_named_code))
        .route("/helper", get(helper_status))
        .route("/helper/start", post(helper_start))
        .route("/helper/stop", post(helper_stop))
        .route("/proxy/system", post(system_proxy))
        .route("/web/login", post(web_login))
        .layer(middleware::from_fn(move |req: Request, next: Next| guard(token.clone(), req, next)))
        .with_state(backend)
}

async fn guard(token: Arc<String>, req: Request, next: Next) -> Response {
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.rsplit_once(':').map_or(h, |(name, _)| name))
        .is_some_and(|name| matches!(name, "127.0.0.1" | "localhost" | "[::1]"));
    if !host_ok || !req.headers().contains_key(LOCAL_HEADER) {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    if req.method() != axum::http::Method::GET {
        let given = req.headers().get(retail_proto::local::TOKEN_HEADER).map(|v| v.as_bytes());
        let ok = given.is_some_and(|g| same_secret(g, token.as_bytes()));
        if !ok {
            return error(
                StatusCode::FORBIDDEN,
                "not allowed: run as administrator/root, or (Linux) join the `retail` group",
            );
        }
    }
    next.run(req).await
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn failed(e: anyhow::Error) -> Response {
    error(StatusCode::BAD_REQUEST, format!("{e:#}"))
}

async fn status(State(b): State<Arc<Backend>>) -> Response {
    Json(b.status().await).into_response()
}

async fn up(State(b): State<Arc<Backend>>, Json(req): Json<UpRequest>) -> Response {
    match b.up(req).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
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

async fn prefs(State(b): State<Arc<Backend>>, Json(req): Json<PrefsRequest>) -> Response {
    match b.set_prefs(req).await {
        Ok(()) => Json(b.status().await).into_response(),
        Err(e) => failed(e),
    }
}

async fn server_status(State(b): State<Arc<Backend>>) -> Response {
    Json(b.server_status().await).into_response()
}

async fn server_start(State(b): State<Arc<Backend>>, Json(req): Json<ServerStartRequest>) -> Response {
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
        Ok(code) => Json(retail_proto::api::InviteResponse { code, expires_at: 0 }).into_response(),
        Err(e) => failed(e),
    }
}

async fn helper_status(State(b): State<Arc<Backend>>) -> Response {
    Json(b.helper.status().await).into_response()
}

async fn helper_start(State(b): State<Arc<Backend>>, Json(req): Json<HelperStartRequest>) -> Response {
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
        None => error(StatusCode::SERVICE_UNAVAILABLE, "the web admin page is off (retaild --web-port)"),
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

async fn server_delete_node(State(b): State<Arc<Backend>>, Path(id): Path<i64>) -> Response {
    match b.host.delete_node(id).await {
        Ok(true) => Json(b.server_status().await).into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, "no such device"),
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
