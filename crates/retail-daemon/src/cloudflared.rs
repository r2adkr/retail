//! The internet tunnel: a Cloudflare quick tunnel in front of the hosted
//! server, for servers no port can be opened to (CGNAT, routers that do not
//! forward, providers that block incoming connections). cloudflared connects
//! out to Cloudflare and gets a `https://….trycloudflare.com` address that
//! forwards to the server's port on 127.0.0.1; devices use it as a front
//! (WebSocket or HTTP polling, with the pinned TLS inside, so Cloudflare sees
//! only ciphertext).
//!
//! The address changes whenever cloudflared starts, and devices outside can
//! only learn a new one through the old one. So cloudflared outlives retaild:
//! it runs detached (its own process group; `KillMode=process` in the systemd
//! unit, `AbandonProcessGroup` in the launchd job, outside the scheduled
//! task's job on Windows), and a retaild that starts again takes over the one
//! running, found through `run.json` and its metrics port. Turning the tunnel
//! or the server off, or removing retail, ends it.
//!
//! cloudflared is fetched from its GitHub release on first use, pinned to one
//! version and checked against the SHA-256 GitHub publishes for each file,
//! and kept in `<state>/tunnel`, which only administrators/root can write.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use retail_proto::api::TunnelStatus;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

pub const VERSION: &str = "2026.11.2";

/// One file of the pinned release
struct Asset {
    name: &'static str,
    sha256: &'static str,
    /// macOS ships a .tgz holding the program
    tgz: bool,
}

fn asset() -> Option<Asset> {
    let (name, sha256, tgz) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => {
            ("cloudflared-windows-amd64.exe", "555b46c85582461d189cac30d14ad05480d612613801be9f110b8ce08c5b2113", false)
        }
        ("linux", "x86_64") => ("cloudflared-linux-amd64", "56f13335143ec0e22772963290683a84a04114a35ec64cbc794a4d39ff9bb8cf", false),
        ("linux", "aarch64") => ("cloudflared-linux-arm64", "04a7b7f08bce85d56b26ffe1fdbfbb21a074495a363d16f0783c40e25b5c5281", false),
        ("linux", "arm") => ("cloudflared-linux-armhf", "ab8dda127892266ef25d9787ea43be2314832204e2e32272901ae36010454684", false),
        ("macos", "x86_64") => ("cloudflared-darwin-amd64.tgz", "6153d9ec629174882a3adbff2f7dc5a24b4f3bdd7ccc38eaa84fba26eb890311", true),
        ("macos", "aarch64") => ("cloudflared-darwin-arm64.tgz", "f6d58eeec91ad1ec5fd1f7e4a587303772929b2625be5d24068033851c36ff55", true),
        _ => return None,
    };
    Some(Asset { name, sha256, tgz })
}

fn program(dir: &Path) -> PathBuf {
    dir.join(if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" })
}

/// The cloudflared that runs, with what retaild needs to find it again
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Run {
    pid: u32,
    metrics: u16,
    /// The server port it forwards to
    origin: u16,
}

fn read_run(dir: &Path) -> Option<Run> {
    serde_json::from_slice(&std::fs::read(dir.join("run.json")).ok()?).ok()
}

/// How long the supervisor waits between checks, and for a new tunnel
const CHECK_EVERY: Duration = Duration::from_secs(15);
const START_WAIT: Duration = Duration::from_secs(60);

pub struct Tunnel {
    dir: PathBuf,
    status: Arc<Mutex<TunnelStatus>>,
    url: watch::Receiver<Option<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl Tunnel {
    /// Starts (or takes over) the tunnel to the server on `origin`
    pub fn start(dir: PathBuf, origin: u16) -> Tunnel {
        let status = Arc::new(Mutex::new(TunnelStatus::default()));
        let (tx, url) = watch::channel(None);
        let task = tokio::spawn(supervise(dir.clone(), origin, status.clone(), tx));
        Tunnel { dir, status, url, task }
    }

    pub fn status(&self) -> TunnelStatus {
        self.status.lock().unwrap().clone()
    }

    /// `https://…` while it is up
    pub fn url(&self) -> watch::Receiver<Option<String>> {
        self.url.clone()
    }

    /// retaild stops: cloudflared keeps running for the next retaild
    pub fn detach(self) {
        self.task.abort();
    }

    /// The tunnel is turned off: cloudflared ends
    pub async fn stop(self) {
        self.task.abort();
        end_recorded(&self.dir).await;
    }
}

/// Ends the cloudflared `run.json` names, if it is still ours (turning the
/// tunnel off, removing retail)
pub async fn end_recorded(dir: &Path) {
    let dir = dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || end_recorded_now(&dir)).await;
}

/// `end_recorded`, outside the async runtime's threads (removing retail)
pub fn end_recorded_now(dir: &Path) {
    if let Some(run) = read_run(dir) {
        let exe = std::env::var_os("RETAIL_CLOUDFLARED").map_or_else(|| program(dir), PathBuf::from);
        end(run.pid, &exe);
    }
    let _ = std::fs::remove_file(dir.join("run.json"));
}

async fn supervise(dir: PathBuf, origin: u16, status: Arc<Mutex<TunnelStatus>>, url: watch::Sender<Option<String>>) {
    let set = |u: Option<String>, e: Option<String>| {
        *status.lock().unwrap() = TunnelStatus { url: u.clone(), error: e };
        url.send_if_modified(|cur| std::mem::replace(cur, u.clone()) != u);
    };
    let mut backoff = Duration::from_secs(10);
    loop {
        let up = match adopt(&dir, origin).await {
            Some(up) => {
                tracing::info!(url = %up.1, "internet tunnel: taking over the running cloudflared");
                Ok(up)
            }
            None => {
                set(None, None);
                launch(&dir, origin).await
            }
        };
        let (metrics, address) = match up {
            Ok(up) => up,
            Err(e) => {
                tracing::warn!("internet tunnel: {e:#}");
                set(None, Some(format!("{e:#}")));
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
                continue;
            }
        };
        backoff = Duration::from_secs(10);
        tracing::info!(url = %address, "internet tunnel up");
        set(Some(address), None);
        // Three missed checks in a row: it died or lost Cloudflare, and a new
        // one gets a new address
        let mut missed = 0;
        while missed < 3 {
            tokio::time::sleep(CHECK_EVERY).await;
            missed = if quick_host(metrics).await.is_some() { 0 } else { missed + 1 };
        }
        tracing::warn!("internet tunnel: cloudflared stopped answering; starting it again");
        end_recorded(&dir).await;
    }
}

/// The cloudflared a retaild before this one started, if it still forwards
/// to `origin` and has its address
async fn adopt(dir: &Path, origin: u16) -> Option<(u16, String)> {
    let run = read_run(dir)?;
    if run.origin != origin {
        return None;
    }
    let host = quick_host(run.metrics).await?;
    Some((run.metrics, format!("https://{host}")))
}

async fn launch(dir: &Path, origin: u16) -> Result<(u16, String)> {
    end_recorded(dir).await;
    let exe = ensure_program(dir).await?;
    let metrics = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free local port")?;
        l.local_addr()?.port()
    };
    let log = dir.join("cloudflared.log");
    let _ = std::fs::remove_file(&log);
    let args = [
        "tunnel".to_string(),
        "--no-autoupdate".into(),
        "--loglevel".into(),
        "warn".into(),
        "--logfile".into(),
        log.display().to_string(),
        "--metrics".into(),
        format!("127.0.0.1:{metrics}"),
        "--url".into(),
        format!("http://127.0.0.1:{origin}"),
    ];
    let mut child = spawn_detached(&exe, &args).context("starting cloudflared")?;
    let run = Run { pid: child.id(), metrics, origin };
    if let Err(e) = std::fs::write(dir.join("run.json"), serde_json::to_vec(&run)?) {
        // Unrecorded, nothing could end it later
        let _ = child.kill();
        let _ = child.wait();
        return Err(e).context("recording cloudflared");
    }
    let deadline = tokio::time::Instant::now() + START_WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(code)) = child.try_wait() {
            let _ = std::fs::remove_file(dir.join("run.json"));
            bail!("cloudflared ended ({code}): {}", last_lines(&log));
        }
        if let Some(host) = quick_host(metrics).await {
            // Reaped by whoever is its parent once this retaild is gone;
            // while it runs, a thread waits so it does not linger as a zombie
            std::thread::spawn(move || child.wait());
            return Ok((metrics, format!("https://{host}")));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    end_recorded(dir).await;
    bail!("Cloudflare gave no tunnel address within a minute (is outgoing TCP/UDP 7844 blocked?): {}", last_lines(&log))
}

fn last_lines(log: &Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(3).collect();
    let joined = lines.into_iter().rev().collect::<Vec<_>>().join(" / ");
    if joined.is_empty() { "no log".into() } else { joined.chars().take(400).collect() }
}

/// The quick tunnel's host name from cloudflared's metrics server
/// (`/quicktunnel`: `{"hostname":"….trycloudflare.com"}`), empty until up
async fn quick_host(metrics: u16) -> Option<String> {
    let body = local_get(metrics, "/quicktunnel").await?;
    #[derive(Deserialize)]
    struct Quick {
        hostname: String,
    }
    let q: Quick = serde_json::from_str(&body).ok()?;
    let host = q.hostname.trim().trim_start_matches("https://").to_ascii_lowercase();
    valid_host(&host).then_some(host)
}

/// A quick tunnel's host name that can go into an `https://` URL as it is.
/// Only Cloudflare's: a local program answering on the metrics port (another
/// user's, once cloudflared is gone) must not name a host for every device.
fn valid_host(host: &str) -> bool {
    host.len() < 254
        && host
            .strip_suffix(".trycloudflare.com")
            .is_some_and(|sub| !sub.is_empty() && sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && host.len() < 254
        && host.contains('.')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

async fn local_get(port: u16, path: &str) -> Option<String> {
    let work = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        s.write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.take(64 * 1024).read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n")?;
        head.starts_with("HTTP/1.").then_some(())?;
        head.split_whitespace().nth(1).filter(|s| *s == "200")?;
        Some(body.to_string())
    };
    tokio::time::timeout(Duration::from_secs(3), work).await.ok().flatten()
}

fn sha256_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Some(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// The checked program, fetched when missing or changed. `RETAIL_CLOUDFLARED`
/// names another program instead (tests; only root sets retaild's environment).
async fn ensure_program(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::state::secure_dir(dir);
    if let Some(p) = std::env::var_os("RETAIL_CLOUDFLARED") {
        return Ok(PathBuf::from(p));
    }
    let a = asset().context("there is no cloudflared for this system")?;
    let exe = program(dir);
    let recorded = std::fs::read_to_string(dir.join("cloudflared.sha256")).ok();
    let now = tokio::task::spawn_blocking({
        let exe = exe.clone();
        move || sha256_file(&exe)
    })
    .await?;
    let good = match (&now, &recorded) {
        (Some(h), Some(r)) => h == r.trim() && (a.tgz || h == a.sha256),
        _ => false,
    };
    if good {
        return Ok(exe);
    }
    tracing::info!(version = VERSION, file = a.name, "internet tunnel: fetching cloudflared");
    let url = format!("https://github.com/cloudflare/cloudflared/releases/download/{VERSION}/{}", a.name);
    let download = dir.join(format!("{}.download", a.name));
    let got = tokio::time::timeout(Duration::from_secs(600), crate::releases::get(&url, Some(&download)))
        .await
        .context("fetching cloudflared took too long")?
        .with_context(|| format!("fetching cloudflared {VERSION}"))?
        .0;
    if got != a.sha256 {
        let _ = std::fs::remove_file(&download);
        bail!("cloudflared {VERSION} does not match its published checksum");
    }
    let _ = std::fs::remove_file(&exe);
    if a.tgz {
        // Into a folder of its own, whatever the archive calls its member
        // (`cloudflared` or `./cloudflared`)
        let unpack = dir.join("unpack");
        let _ = std::fs::remove_dir_all(&unpack);
        std::fs::create_dir_all(&unpack)?;
        let out = std::process::Command::new("tar").arg("-xzf").arg(&download).arg("-C").arg(&unpack).output();
        let _ = std::fs::remove_file(&download);
        let found = match out {
            Ok(o) if o.status.success() => find_program(&unpack),
            Ok(o) => {
                let _ = std::fs::remove_dir_all(&unpack);
                bail!("unpacking cloudflared: {}", String::from_utf8_lossy(&o.stderr).trim())
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&unpack);
                bail!("unpacking cloudflared: {e}")
            }
        };
        let moved = match found {
            Some(f) => std::fs::rename(&f, &exe).context("putting cloudflared in place"),
            None => Err(anyhow::anyhow!("the cloudflared archive has no cloudflared in it")),
        };
        let _ = std::fs::remove_dir_all(&unpack);
        moved?;
    } else {
        std::fs::rename(&download, &exe)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755))?;
    }
    let h = sha256_file(&exe).context("reading cloudflared")?;
    std::fs::write(dir.join("cloudflared.sha256"), &h)?;
    Ok(exe)
}

/// The file named `cloudflared` in `dir` or a folder in it
fn find_program(dir: &Path) -> Option<PathBuf> {
    let direct = dir.join("cloudflared");
    if direct.is_file() {
        return Some(direct);
    }
    std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path().join("cloudflared")).find(|p| p.is_file())
}

/// Started apart from retaild, so stopping retaild (an update, a restart)
/// leaves it running
fn spawn_detached(exe: &Path, args: &[String]) -> std::io::Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(exe);
    cmd.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        cmd.spawn()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        // Out of the scheduled task's job, which ending the task would end;
        // a job that allows no breakaway refuses, and it starts inside
        match cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB).spawn() {
            Ok(c) => Ok(c),
            Err(e) => {
                tracing::debug!("cloudflared outside the job: {e}");
                cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP).spawn()
            }
        }
    }
}

/// Ends process `pid` if it is `exe` (a recorded pid may have been reused)
fn end(pid: u32, exe: &Path) {
    if !is(pid, exe) {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: plain syscall on a pid checked just above
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        for _ in 0..30 {
            if !is(pid, exe) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // SAFETY: as above
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(0x0800_0000)
            .output();
    }
}

/// Whether process `pid` runs `exe`
fn is(pid: u32, exe: &Path) -> bool {
    let want = exe.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    #[cfg(target_os = "linux")]
    {
        // Started with its full path, which its command line keeps (a
        // script's after its interpreter)
        let _ = &want;
        let exe = exe.to_string_lossy();
        std::fs::read(format!("/proc/{pid}/cmdline"))
            .is_ok_and(|c| c.split(|b| *b == 0).take(2).any(|arg| arg == exe.as_bytes()))
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim().to_ascii_lowercase().ends_with(&want))
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .creation_flags(0x0800_0000)
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).to_ascii_lowercase().contains(&format!("\"{want}\"")))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (pid, want);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_program_in_an_unpacked_archive() {
        let dir = std::env::temp_dir().join(format!("retail-cf-unpack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a")).unwrap();
        assert_eq!(find_program(&dir), None);
        std::fs::write(dir.join("a").join("cloudflared"), b"x").unwrap();
        assert_eq!(find_program(&dir), Some(dir.join("a").join("cloudflared")));
        std::fs::write(dir.join("cloudflared"), b"x").unwrap();
        assert_eq!(find_program(&dir), Some(dir.join("cloudflared")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_names_are_checked() {
        assert!(valid_host("sunny-river-1234.trycloudflare.com"));
        assert!(!valid_host(""));
        assert!(!valid_host("localhost"));
        assert!(!valid_host("evil.com/path"));
        assert!(!valid_host("a b.trycloudflare.com"));
        assert!(!valid_host("tunnel.example.com"));
        assert!(!valid_host("x.evil.trycloudflare.com.example"));
        assert!(!valid_host("a.b.trycloudflare.com"));
    }

    #[test]
    fn every_release_system_has_a_pinned_file() {
        if matches!(
            (std::env::consts::OS, std::env::consts::ARCH),
            ("windows", "x86_64") | ("linux", "x86_64" | "aarch64" | "arm") | ("macos", "x86_64" | "aarch64")
        ) {
            let a = asset().unwrap();
            assert_eq!(a.sha256.len(), 64);
            assert!(a.name.starts_with("cloudflared-"));
        }
    }

    /// A metrics server as cloudflared's: the address is read from it
    #[tokio::test]
    async fn reads_the_address_from_the_metrics_server() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            for body in [r#"{"hostname":""}"#, r#"{"hostname":"sunny-river-1234.trycloudflare.com"}"#] {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        assert_eq!(quick_host(port).await, None, "not up yet");
        assert_eq!(quick_host(port).await.as_deref(), Some("sunny-river-1234.trycloudflare.com"));
        assert_eq!(quick_host(port).await, None, "nothing listening");
    }
}
