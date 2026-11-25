//! Talks to retaild's local API from a background thread, so the UI thread
//! never blocks on the network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use retail_proto::api::{
    ApiError, InviteRequest, InviteResponse, PrefsRequest, ServerSelect, ServerStartRequest, ServerStatus, StatusResponse, UpRequest,
};

use crate::i18n::tr;

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
    /// Connect to a saved server instead of the current one
    Switch(String),
    /// Remove a saved server
    Forget(String),
    /// Look for a newer release now
    CheckUpdate,
    InstallUpdate,
    Refresh,
    Prefs { req: PrefsRequest, origin: Origin },
    /// Hosting a network on this device
    Server(ServerCommand),
}

pub enum ServerCommand {
    Refresh,
    Start,
    Stop,
    /// A new invite, or a new code for a named one
    CreateInvite(InviteRequest),
    /// The current code of a named invite: shown, or copied when `copy`
    Code { id: i64, copy: bool },
    Revoke(i64),
    /// The installer of a named invite for `variant`, saved to `dir`
    Package { id: i64, variant: String, dir: PathBuf },
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
    /// A named invite's code, for showing or copying
    Code { id: i64, copy: bool, result: Result<String, String> },
    /// Where an installer was saved
    Saved(Result<PathBuf, String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Up,
    Down,
    Logout,
    Prefs,
    Switch,
    Forget,
    Update,
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
                    Ok(Command::Switch(server)) => {
                        let body = serde_json::to_string(&ServerSelect { server }).unwrap_or_default();
                        (Origin::Settings, ActionKind::Switch, call(addr, "POST", "/servers/switch", Some(&body), Duration::from_secs(20)))
                    }
                    Ok(Command::Forget(server)) => {
                        let body = serde_json::to_string(&ServerSelect { server }).unwrap_or_default();
                        (Origin::Settings, ActionKind::Forget, call(addr, "POST", "/servers/forget", Some(&body), Duration::from_secs(10)))
                    }
                    Ok(Command::CheckUpdate) => {
                        (Origin::Settings, ActionKind::Update, call(addr, "POST", "/update/check", None, Duration::from_secs(70)))
                    }
                    Ok(Command::InstallUpdate) => {
                        (Origin::Settings, ActionKind::Update, call(addr, "POST", "/update/install", None, Duration::from_secs(10)))
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
                                    && let Ok(page) = retail_proto::local::sign_in_page(url)
                                {
                                    // A private page that posts the sign-in, keeping the link off the browser's command line
                                    open_browser(&page.display().to_string());
                                }
                                continue;
                            }
                            ServerCommand::CreateInvite(req) => {
                                let body = serde_json::to_string(&req).unwrap_or_default();
                                on_event(ApiEvent::Invite(call(addr, "POST", "/server/invite", Some(&body), t)));
                                on_event(ApiEvent::Server(call(addr, "GET", "/server", None, t)));
                            }
                            ServerCommand::Code { id, copy } => {
                                let result = call::<InviteResponse>(addr, "POST", &format!("/server/invites/{id}/code"), Some("{}"), t);
                                on_event(ApiEvent::Code { id, copy, result: result.map(|r| r.code) });
                                continue;
                            }
                            ServerCommand::Revoke(id) => {
                                let path = format!("/server/invites/{id}/revoke");
                                if let Err(e) = call::<serde_json::Value>(addr, "POST", &path, Some("{}"), t) {
                                    on_event(ApiEvent::Server(Err(e)));
                                }
                                on_event(ApiEvent::Server(call(addr, "GET", "/server", None, t)));
                            }
                            ServerCommand::Package { id, variant, dir } => {
                                // Fetching an official client first can take minutes
                                let path = format!("/server/invites/{id}/package/{variant}");
                                on_event(ApiEvent::Saved(download(addr, &path, &dir, Duration::from_secs(600))));
                                continue;
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

/// POSTs `path` and saves the answer in `dir` under the name the daemon
/// gives it, streaming (installers are tens of MiB)
fn download(addr: SocketAddr, path: &str, dir: &Path, timeout: Duration) -> Result<PathBuf, String> {
    retail_proto::local::check_listener(addr)?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(800))
        .map_err(|_| tr("retaild is not running").to_string())?;
    s.set_read_timeout(Some(timeout)).ok();
    let token = retail_proto::local::read_token().map(|t| format!("X-Retail-Token: {t}\r\n")).unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Retail-Local: 1\r\n{token}Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    // The head, byte by byte up to the blank line
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).map_err(|e| e.to_string())? == 0 || head.len() > 16 * 1024 {
            return Err("malformed response".into());
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("malformed status line")?;
    if !(200..300).contains(&code) {
        let mut body = Vec::new();
        s.take(1 << 16).read_to_end(&mut body).ok();
        return Err(friendly(serde_json::from_slice::<ApiError>(&body).map(|e| e.error).unwrap_or_else(|_| format!("HTTP {code}"))));
    }
    let name = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))
        .and_then(|l| l.split("filename=\"").nth(1))
        .and_then(|r| r.split('"').next())
        .filter(|n| retail_proto::package::safe_name(n))
        .unwrap_or("retail-installer")
        .to_string();
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let dest = free_name(dir, &name);
    let tmp = dest.with_extension("part");
    let mut out = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::io::copy(&mut s, &mut out).map_err(|e| e.to_string())?;
    drop(out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
    Ok(dest)
}

/// `name` in `dir`, or `name (2)` and so on if taken
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (name.to_string(), String::new()),
    };
    (1..)
        .map(|i| if i == 1 { dir.join(name) } else { dir.join(format!("{stem} ({i}){ext}")) })
        .find(|p| !p.exists())
        .unwrap_or_else(|| dir.join(name))
}

/// The user's downloads folder, or the home folder
pub fn downloads_dir() -> PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = home.join("Downloads");
    if d.is_dir() { d } else { home }
}

/// Shows `file` selected in the system's file manager
pub fn reveal(file: &Path) {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("explorer");
        c.arg(format!("/select,{}", file.display()));
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg("-R").arg(file);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(file.parent().unwrap_or(file));
        c
    };
    let _ = cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
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
        .map_err(|_| tr("retaild is not running").to_string())?;
    // Changes carry invite codes, passwords and backups, and their answers are
    // acted on: only for the real daemon. Status reads go to whoever answers.
    if method != "GET" {
        retail_proto::local::check_listener(addr)?;
    }
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
/// ones are reworded and translated here, the rest shown as they are
fn friendly(msg: String) -> String {
    let known: [(&str, &'static str); 9] = [
        ("invalid, used or expired auth key", "The invite code or auth key is wrong, already used, or expired."),
        ("too many attempts", "Too many attempts. Try again in a minute."),
        ("not a retail invite code", "This is not a retail invite code. Paste a code that starts with retail1."),
        ("the invite code is damaged", "The invite code is damaged. Copy and paste it again."),
        ("the invite code is incomplete", "Only part of the invite code came through. Copy and paste it again."),
        ("request timed out", "Could not reach the server. Check the server address and your network."),
        ("connecting to", "Could not reach the server. Check the server address and your network."),
        ("not allowed", "Permission denied. Run as administrator (on Linux, join the retail group)."),
        ("the server is not running", "The server is not running."),
    ];
    known.iter().find(|(k, _)| msg.contains(k)).map_or(msg, |(_, en)| tr(en).to_string())
}
