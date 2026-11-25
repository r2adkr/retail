//! Installing retaild without the tray app: `retaild install [--server]` copies
//! the programs to their place, has the daemon start at boot (systemd,
//! launchd, Task Scheduler) and, with `--server`, starts a server that does
//! not join its own network and prints the first invite. The tray app's
//! installer uses `retaild service register|stop|remove` for the same boot
//! registration.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

#[derive(clap::Subcommand)]
pub enum Cmd {
    /// Install retaild (and the `retail` CLI next to it) as a service that
    /// starts at boot. With --server, also start a server here that does not
    /// join its own network (as on a VPS) and print an invite.
    Install {
        /// Host a network on this machine
        #[arg(long)]
        server: bool,
        /// TCP port of the server (default 443)
        #[arg(long, requires = "server")]
        port: Option<u16>,
        /// A host name pointing at this machine, for invites
        #[arg(long, requires = "server")]
        domain: Option<String>,
        /// Where the programs go (default: /usr/local/bin, or %ProgramFiles%\retail)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Start the daemon directly instead of registering a service (tests)
        #[arg(long, hide = true)]
        no_service: bool,
    },
    /// Stop retaild and remove the service and the programs. The state
    /// directory (keys, server data) stays.
    Uninstall {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Boot registration only, for the tray app's installer
    #[command(hide = true)]
    Service {
        #[arg(value_parser = ["register", "stop", "remove"])]
        action: String,
    },
}

/// On Windows the daemon is stopped by terminating it, so the system settings
/// a session undoes when it ends stay behind: the name resolution rule that
/// sends `.retail.internal` to the MagicDNS address, the exit node's NAT and
/// the firewall rule. Removing retail removes them too, and ends the internet
/// tunnel's cloudflared, which outlives the daemon on purpose.
fn remove_system_changes(state_dir: Option<&Path>) {
    let state = state_dir.map_or_else(crate::state::default_state_dir, Path::to_path_buf);
    crate::cloudflared::end_recorded_now(&state.join("tunnel"));
    // The downloaded program, not data
    let _ = std::fs::remove_dir_all(state.join("tunnel"));
    #[cfg(windows)]
    {
        for script in [
            "Get-DnsClientNrptRule | Where-Object Comment -eq 'retail' | Remove-DnsClientNrptRule -Force",
            "Remove-NetNat -Name retail-exit -Confirm:$false -ErrorAction SilentlyContinue",
        ] {
            let _ = std::process::Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).output();
        }
        crate::firewall::remove_inbound();
    }
}

pub fn run(cmd: Cmd, state_dir: Option<&Path>, api: SocketAddr) -> Result<()> {
    match cmd {
        Cmd::Service { action } => {
            let me = std::env::current_exe()?;
            match action.as_str() {
                "register" => register(&me),
                "stop" => {
                    stop(api);
                    Ok(())
                }
                _ => {
                    stop(api);
                    unregister();
                    remove_system_changes(state_dir);
                    Ok(())
                }
            }
        }
        Cmd::Uninstall { dir } => {
            require_admin()?;
            stop(api);
            unregister();
            remove_system_changes(state_dir);
            let dir = dir.unwrap_or_else(default_dir);
            for name in ["retaild", "retail"] {
                let _ = std::fs::remove_file(dir.join(exe(name)));
            }
            if cfg!(windows) {
                let _ = std::fs::remove_file(dir.join("wintun.dll"));
                let _ = std::fs::remove_dir(&dir);
            }
            println!("retaild is removed. Its state stays in {}.", state_dir.map_or_else(crate::state::default_state_dir, Path::to_path_buf).display());
            Ok(())
        }
        Cmd::Install { server, port, domain, dir, no_service } => {
            if !no_service {
                require_admin()?;
            }
            let dir = dir.unwrap_or_else(default_dir);
            let me = std::env::current_exe()?;
            let here = me.parent().context("retaild has no folder")?.to_path_buf();
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            if !no_service {
                stop(api);
            }
            let same = here.canonicalize().ok() == dir.canonicalize().ok();
            let mut files = vec![exe("retaild"), exe("retail")];
            if cfg!(windows) {
                files.push("wintun.dll".into());
            }
            for f in &files {
                let src = if *f == exe("retaild") { me.clone() } else { here.join(f) };
                if same || !src.is_file() {
                    if !src.is_file() && *f != exe("retaild") {
                        eprintln!("note: {f} is not next to retaild; install it to {} yourself", dir.display());
                    }
                    continue;
                }
                copy(&src, &dir.join(f)).with_context(|| format!("installing {f}"))?;
            }
            let daemon = dir.join(exe("retaild"));
            if no_service {
                let mut cmd = std::process::Command::new(&daemon);
                if let Some(s) = state_dir {
                    cmd.arg("--state-dir").arg(s);
                }
                cmd.arg("--api").arg(api.to_string());
                cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
                cmd.spawn().context("starting retaild")?;
            } else {
                register(&daemon)?;
            }
            wait_for(api)?;
            println!("retaild is installed in {} and starts at boot.", dir.display());
            if !server {
                println!("Join a network with: retail up --invite <code>");
                return Ok(());
            }
            let req = retail_proto::api::ServerStartRequest { join: false, port, domain, ..Default::default() };
            let st: retail_proto::api::ServerStatus = call(api, "/server/start", &serde_json::to_string(&req)?)?;
            let inv: retail_proto::api::InviteResponse = call(api, "/server/invite", "{}")?;
            println!();
            println!("The server is running and starts again at boot.");
            match (&st.public, st.lan.is_empty()) {
                (Some(p), _) => println!("  address:  {p}"),
                // A VPS has its public address on its own interface
                (None, false) => println!("  address:  {}", st.lan.join(", ")),
                (None, true) => println!("  address:  not known yet (`retail server status`)"),
            }
            println!("  firewall: allow TCP {} and UDP 3478 in", st.port.unwrap_or(443));
            if let Some(w) = &st.warning {
                println!("  note:     {w}");
            }
            println!();
            println!("Invite for the first device (one-time, 24 hours):");
            println!("  {}", inv.code);
            println!();
            println!("Manage it here with `retail server …` (status, invite --name, acl, tag, helper-device),");
            println!("or open the web admin page from your computer:");
            println!("  ssh -L 41180:127.0.0.1:41180 <this machine>, then `retail server web --print` here");
            Ok(())
        }
    }
}

fn exe(name: &str) -> String {
    if cfg!(windows) { format!("{name}.exe") } else { name.to_string() }
}

fn default_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into())).join("retail")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

/// Replaces `dest`, which may be running (renamed aside on Windows)
fn copy(src: &Path, dest: &Path) -> Result<()> {
    let tmp = dest.with_extension("new");
    std::fs::copy(src, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(windows)]
    if dest.exists() {
        let old = dest.with_extension("old");
        let _ = std::fs::remove_file(&old);
        std::fs::rename(dest, &old)?;
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn require_admin() -> Result<()> {
    #[cfg(unix)]
    let admin = unsafe { libc::geteuid() } == 0;
    #[cfg(windows)]
    let admin = std::process::Command::new("net").arg("session").output().is_ok_and(|o| o.status.success());
    if !admin {
        bail!("run this as administrator (Windows) or root (sudo)");
    }
    Ok(())
}

fn wait_for(api: SocketAddr) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        if TcpStream::connect_timeout(&api, Duration::from_millis(300)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bail!("retaild did not start (see its log: journalctl -u retaild, or the Task Scheduler history)")
}

/// A POST to the local API with the token
fn call<T: serde::de::DeserializeOwned>(api: SocketAddr, path: &str, body: &str) -> Result<T> {
    // The daemon writes its token just after it starts listening
    let token = (0..50)
        .find_map(|_| retail_proto::local::read_token().or_else(|| {
            std::thread::sleep(Duration::from_millis(100));
            None
        }))
        .context("no local API token")?;
    let mut s = TcpStream::connect_timeout(&api, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Retail-Local: 1\r\nX-Retail-Token: {token}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )?;
    let mut raw = Vec::new();
    s.take(1 << 20).read_to_end(&mut raw)?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").context("malformed answer")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let ok = head.split_whitespace().nth(1).is_some_and(|c| c.starts_with('2'));
    let body = &raw[split + 4..];
    if !ok {
        let e = serde_json::from_slice::<retail_proto::api::ApiError>(body).map(|e| e.error).unwrap_or_else(|_| head.lines().next().unwrap_or("").to_string());
        bail!("{path}: {e}");
    }
    Ok(serde_json::from_slice(body)?)
}

fn run_quiet(program: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(program).args(args).output().with_context(|| program.to_string())?;
    if !out.status.success() {
        bail!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[cfg(windows)]
const TASK: &str = "retail\\retaild";

/// Asks the running daemon to exit on its own and waits for it, so it undoes
/// what it set up (name resolution rule, router ports, firewall rule): Task
/// Scheduler and taskkill end it without a chance to. Needs the administrator
/// token, so only an administrator can stop it this way.
#[cfg(windows)]
fn request_stop(api: SocketAddr) {
    let Some(admin) = retail_proto::local::read_admin_token() else { return };
    let token = retail_proto::local::read_token().unwrap_or_default();
    if retail_proto::local::check_listener(api).is_err() {
        return;
    }
    let Ok(mut s) = TcpStream::connect_timeout(&api, Duration::from_millis(500)) else { return };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "POST /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Retail-Local: 1\r\nX-Retail-Token: {token}\r\nX-Retail-Admin: {admin}\r\n\
         Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let mut head = [0u8; 10];
    if s.write_all(req.as_bytes()).is_err() || s.read_exact(&mut head).is_err() || !head.starts_with(b"HTTP/1.1 2") {
        return;
    }
    drop(s);
    // The API stops listening once the cleanup is done
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if TcpStream::connect_timeout(&api, Duration::from_millis(200)).is_err() {
            std::thread::sleep(Duration::from_millis(500));
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Task Scheduler defaults would stop the daemon after 72 hours and on
/// battery, and never restart it, so the task is imported from XML.
#[cfg(windows)]
pub fn register(daemon: &Path) -> Result<()> {
    create_task(daemon)?;
    run_quiet("schtasks", &["/Run", "/TN", TASK])
}

/// What marks the current task definition (the one-minute trigger)
#[cfg(windows)]
const TASK_MARK: &str = "retail node daemon (2)";

/// The boot trigger, and a trigger every minute that starts the daemon when
/// it is not running (after an update, or a crash: Task Scheduler restarts
/// nothing that exits with an error code). Running, the minute's start is
/// ignored.
#[cfg(windows)]
fn create_task(daemon: &Path) -> Result<()> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{TASK_MARK}</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="System"><Exec><Command>{}</Command></Exec></Actions>
</Task>"#,
        xml_text(&daemon.display().to_string())
    );
    // In the state folder, which only SYSTEM and administrators may change:
    // in a shared temporary folder another user could swap the file before
    // Task Scheduler reads it, and run their program as SYSTEM
    let dir = crate::state::default_state_dir();
    std::fs::create_dir_all(&dir).context("creating the state folder")?;
    crate::state::secure_dir(&dir);
    let path = dir.join("retaild-task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).context("writing the task")?;
    let path_s = path.display().to_string();
    let created = run_quiet("schtasks", &["/Create", "/TN", TASK, "/XML", &path_s, "/F"]);
    let _ = std::fs::remove_file(&path);
    created
}

/// `s` as XML text: a folder may be named `R&D`
#[cfg(windows)]
fn xml_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A daemon started by an older task definition (from 1.0.1 or before, which
/// an update leaves in place) puts in the current one. Running instances
/// carry on.
#[cfg(windows)]
pub fn update_task() {
    let Ok(me) = std::env::current_exe() else { return };
    let Ok(out) = std::process::Command::new("schtasks").args(["/Query", "/TN", TASK, "/XML"]).output() else { return };
    // UTF-16 or the console's code page, by Windows version
    let raw = out.stdout.strip_prefix(&[0xFF, 0xFE]).unwrap_or(&out.stdout);
    let xml = if raw.len() >= 2 && raw.iter().skip(1).step_by(2).take(64).all(|b| *b == 0) {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    // Not installed as the task (a test, a copy elsewhere), or current
    let ours = xml.contains(&format!("<Command>{}</Command>", xml_text(&me.display().to_string())));
    if !out.status.success() || !ours || xml.contains(TASK_MARK) {
        return;
    }
    match create_task(&me) {
        Ok(()) => tracing::info!("boot task updated: it now also starts retaild when it is not running"),
        Err(e) => tracing::warn!("updating the boot task: {e:#}"),
    }
}

#[cfg(windows)]
pub fn stop(api: SocketAddr) {
    // Off first: the task's one-minute trigger would otherwise start it again,
    // in the middle of an installer replacing the programs. `register` turns
    // it back on.
    let _ = run_quiet("schtasks", &["/Change", "/TN", TASK, "/DISABLE"]);
    request_stop(api);
    let _ = run_quiet("schtasks", &["/End", "/TN", TASK]);
    // Not this process (`retaild service stop` itself)
    let _ = run_quiet("taskkill", &["/F", "/FI", &format!("PID ne {}", std::process::id()), "/IM", "retaild.exe"]);
    std::thread::sleep(Duration::from_millis(500));
}

#[cfg(windows)]
pub fn unregister() {
    let _ = run_quiet("schtasks", &["/Delete", "/TN", TASK, "/F"]);
}

#[cfg(target_os = "linux")]
pub fn register(daemon: &Path) -> Result<()> {
    if run_quiet("systemctl", &["--version"]).is_err() {
        bail!("systemd was not found; start {} yourself (as root), for example from your init system", daemon.display());
    }
    let dir = daemon.parent().map(|d| d.display().to_string()).unwrap_or_else(|| "/usr/local/bin".into());
    let unit = include_str!("../../../packaging/systemd/retaild.service").replace("/usr/local/bin", &dir);
    std::fs::write("/etc/systemd/system/retaild.service", unit).context("writing the systemd unit")?;
    run_quiet("systemctl", &["daemon-reload"])?;
    run_quiet("systemctl", &["enable", "--now", "retaild"])?;
    run_quiet("systemctl", &["restart", "retaild"])
}

#[cfg(target_os = "linux")]
pub fn stop(_api: SocketAddr) {
    let _ = run_quiet("systemctl", &["stop", "retaild"]);
}

#[cfg(target_os = "linux")]
pub fn unregister() {
    let _ = run_quiet("systemctl", &["disable", "retaild"]);
    let _ = std::fs::remove_file("/etc/systemd/system/retaild.service");
    let _ = run_quiet("systemctl", &["daemon-reload"]);
}

#[cfg(target_os = "macos")]
const PLIST: &str = "/Library/LaunchDaemons/dev.retail.retaild.plist";

#[cfg(target_os = "macos")]
pub fn register(daemon: &Path) -> Result<()> {
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.retail.retaild</string>
<key>ProgramArguments</key><array><string>{}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>AbandonProcessGroup</key><true/>
</dict></plist>
"#,
        daemon.display()
    );
    std::fs::write(PLIST, plist).context("writing the launchd job")?;
    let _ = run_quiet("launchctl", &["bootout", "system", PLIST]);
    // bootout returns before the job is gone, and bootstrap fails ("5:
    // Input/output error") until it is
    let mut tries = 0;
    loop {
        match run_quiet("launchctl", &["bootstrap", "system", PLIST]) {
            Ok(()) => return Ok(()),
            Err(e) if tries >= 20 => return Err(e),
            Err(_) => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub fn stop(_api: SocketAddr) {
    let _ = run_quiet("launchctl", &["bootout", "system", PLIST]);
}

#[cfg(target_os = "macos")]
pub fn unregister() {
    let _ = std::fs::remove_file(PLIST);
}
