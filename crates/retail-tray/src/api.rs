//! Talks to retaild's local API from a background thread, so the UI thread
//! never blocks on the network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use retail_proto::api::{
    ApiError, InviteRequest, InviteResponse, PrefsRequest, ServerStartRequest, ServerStatus, StatusResponse, UpRequest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Popup,
    Settings,
}

pub enum Command {
    /// With an auth key or an invite code this (re-)registers
    Up { server: String, auth_key: Option<String>, hostname: Option<String>, invite: Option<String>, origin: Origin },
    Down,
    Logout,
    Refresh,
    Prefs { req: PrefsRequest, origin: Origin },
    /// Hosting a network on this device
    Server(ServerCommand),
}

pub enum ServerCommand {
    Refresh,
    Start,
    Stop,
    Invite,
    Remove(i64),
    /// Opens the web admin page with a one-time sign-in link
    OpenWeb,
}

pub enum ApiEvent {
    Status(Result<StatusResponse, String>),
    Action { origin: Origin, kind: ActionKind, result: Result<StatusResponse, String> },
    /// Server status after a refresh or a server command (`Err` for a failed command)
    Server(Result<ServerStatus, String>),
    Invite(Result<InviteResponse, String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Up,
    Down,
    Logout,
    Prefs,
}

/// Starts the poller. It refreshes every second while `fast` is set (a window
/// is open) and every five seconds otherwise, also polling the server status
/// while `dashboard` is set, and runs commands as they arrive.
pub fn spawn(
    addr: SocketAddr,
    fast: Arc<AtomicBool>,
    dashboard: Arc<AtomicBool>,
    on_event: impl Fn(ApiEvent) + Send + 'static,
) -> mpsc::Sender<Command> {
    let (tx, rx) = mpsc::channel::<Command>();
    crate::sysproxy::spawn(addr);
    std::thread::Builder::new()
        .name("retail-api".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            loop {
                let wait = if fast.load(Ordering::Relaxed) { Duration::from_secs(1) } else { Duration::from_secs(5) };
                let (origin, kind, result) = match rx.recv_timeout(wait) {
                    Ok(Command::Up { server, auth_key, hostname, invite, origin }) => {
                        let body = serde_json::to_string(&UpRequest { server, auth_key, hostname, invite }).unwrap_or_default();
                        // Registration contacts the control server, which may be slow
                        (origin, ActionKind::Up, call(addr, "POST", "/up", Some(&body), Duration::from_secs(40)))
                    }
                    Ok(Command::Down) => {
                        (Origin::Popup, ActionKind::Down, call(addr, "POST", "/down", None, Duration::from_secs(10)))
                    }
                    Ok(Command::Prefs { req, origin }) => {
                        let body = serde_json::to_string(&req).unwrap_or_default();
                        // A new memory limit restarts the tunnel
                        (origin, ActionKind::Prefs, call(addr, "POST", "/prefs", Some(&body), Duration::from_secs(20)))
                    }
                    Ok(Command::Logout) => {
                        (Origin::Settings, ActionKind::Logout, call(addr, "POST", "/logout", None, Duration::from_secs(10)))
                    }
                    Ok(Command::Refresh) | Err(mpsc::RecvTimeoutError::Timeout) => {
                        on_event(ApiEvent::Status(call(addr, "GET", "/status", None, Duration::from_secs(3))));
                        if dashboard.load(Ordering::Relaxed) {
                            on_event(ApiEvent::Server(call(addr, "GET", "/server", None, Duration::from_secs(3))));
                        }
                        continue;
                    }
                    Ok(Command::Server(cmd)) => {
                        let t = Duration::from_secs(30);
                        match cmd {
                            ServerCommand::Refresh => on_event(ApiEvent::Server(call(addr, "GET", "/server", None, t))),
                            ServerCommand::Start => {
                                let body = serde_json::to_string(&ServerStartRequest { join: true, ..Default::default() }).unwrap_or_default();
                                on_event(ApiEvent::Server(call(addr, "POST", "/server/start", Some(&body), t)));
                            }
                            ServerCommand::Stop => on_event(ApiEvent::Server(call(addr, "POST", "/server/stop", None, t))),
                            ServerCommand::Remove(id) => {
                                on_event(ApiEvent::Server(call(addr, "POST", &format!("/server/nodes/{id}/delete"), None, t)));
                            }
                            ServerCommand::OpenWeb => {
                                if let Ok(v) = call::<serde_json::Value>(addr, "POST", "/web/login", Some("{}"), t)
                                    && let Some(url) = v["url"].as_str()
                                {
                                    open_browser(url);
                                }
                                continue;
                            }
                            ServerCommand::Invite => {
                                let body = serde_json::to_string(&InviteRequest::default()).unwrap_or_default();
                                on_event(ApiEvent::Invite(call(addr, "POST", "/server/invite", Some(&body), t)));
                            }
                        }
                        on_event(ApiEvent::Status(call(addr, "GET", "/status", None, Duration::from_secs(3))));
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                };
                let failed = result.is_err();
                on_event(ApiEvent::Action { origin, kind, result });
                if failed {
                    on_event(ApiEvent::Status(call(addr, "GET", "/status", None, Duration::from_secs(3))));
                }
            }
        })
        .expect("spawning the API thread");
    tx
}

/// For threads other than the poller
pub fn status_blocking(addr: SocketAddr) -> Result<retail_proto::api::StatusResponse, String> {
    call(addr, "GET", "/status", None, Duration::from_secs(3))
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn post_blocking(addr: SocketAddr, path: &str, body: &str) -> Result<(), String> {
    post_blocking_timeout(addr, path, body, Duration::from_secs(5))
}

pub fn post_blocking_timeout(addr: SocketAddr, path: &str, body: &str, timeout: Duration) -> Result<(), String> {
    call::<serde_json::Value>(addr, "POST", path, Some(body), timeout).map(|_| ())
}

fn call<T: serde::de::DeserializeOwned>(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> Result<T, String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(800))
        .map_err(|_| "retaild가 꺼져 있습니다".to_string())?;
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let body = body.unwrap_or("");
    // Read each time because the daemon writes a new token whenever it starts
    let token = retail_proto::local::read_token().map(|t| format!("X-Retail-Token: {t}\r\n")).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Retail-Local: 1\r\n{token}Connection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(1 << 20).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("malformed status line")?;
    let body = &raw[split + 4..];
    if (200..300).contains(&code) {
        serde_json::from_slice(body).map_err(|e| format!("bad status JSON: {e}"))
    } else {
        Err(friendly(serde_json::from_slice::<ApiError>(body).map(|e| e.error).unwrap_or_else(|_| format!("HTTP {code}"))))
    }
}

/// Opens `url` in the default browser
fn open_browser(url: &str) {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

/// The daemon words its errors in English for logs and the CLI; the common
/// ones are said in Korean here, the rest shown as they are
fn friendly(msg: String) -> String {
    let known: [(&str, &str); 9] = [
        ("invalid, used or expired auth key", "초대 코드나 인증 키가 잘못됐거나, 이미 쓰였거나, 만료됐습니다."),
        ("too many attempts", "시도가 너무 많습니다. 1분 뒤에 다시 해 보세요."),
        ("not a retail invite code", "retail 초대 코드가 아닙니다. retail1.로 시작하는 코드를 붙여 넣으세요."),
        ("the invite code is damaged", "초대 코드가 손상됐습니다. 다시 복사해 붙여 넣으세요."),
        ("the invite code is incomplete", "초대 코드가 일부만 들어왔습니다. 다시 복사해 붙여 넣으세요."),
        ("request timed out", "서버에 연결하지 못했습니다. 서버 주소와 네트워크를 확인하세요."),
        ("connecting to", "서버에 연결하지 못했습니다. 서버 주소와 네트워크를 확인하세요."),
        ("not allowed", "권한이 없습니다. 관리자 권한으로 실행하세요(Linux는 retail 그룹)."),
        ("the server is not running", "서버가 꺼져 있습니다."),
    ];
    known.iter().find(|(k, _)| msg.contains(k)).map_or(msg, |(_, ko)| ko.to_string())
}
