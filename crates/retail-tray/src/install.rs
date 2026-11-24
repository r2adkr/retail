//! Self-install for client packages (`retail_proto::package`). Run as a
//! package, the tray app asks to join, raises itself to administrator once,
//! unpacks the daemon and CLI next to a plain copy of itself, has the daemon
//! start at boot (Windows Task Scheduler, systemd, launchd), joins with the
//! invite inside, then registers and starts the tray app for the user.
//!
//! On a device already in another network it asks whether to switch; the
//! daemon then leaves that network (keeping it among the saved servers) and
//! joins this one.
//!
//! Flags: `--install` (the raised step), `--switch` (it may leave another
//! network), `--uninstall`, `--package-info`, and for tests `--prefix DIR` (install under DIR), `--no-service` (start
//! the daemon directly instead of registering it), `--no-autostart`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use retail_proto::api::BackendState;
use retail_proto::package::{Manifest, read_manifest, safe_name};

use crate::i18n::{tr, trf};

const API_WAIT: Duration = Duration::from_secs(30);

struct Opts {
    prefix: Option<PathBuf>,
    service: bool,
    autostart: bool,
    /// The user agreed to leave the network this device is in
    switch: bool,
}

impl Opts {
    fn parse(args: &[String]) -> Self {
        let prefix = args.iter().position(|a| a == "--prefix").and_then(|i| args.get(i + 1)).map(PathBuf::from);
        Opts {
            prefix,
            service: !args.iter().any(|a| a == "--no-service"),
            autostart: !args.iter().any(|a| a == "--no-autostart"),
            switch: args.iter().any(|a| a == "--switch"),
        }
    }

    /// Hands the same test flags to the raised step
    fn forward(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = &self.prefix {
            out.push("--prefix".into());
            out.push(p.display().to_string());
        }
        if !self.service {
            out.push("--no-service".into());
        }
        if self.switch {
            out.push("--switch".into());
        }
        out
    }
}

fn exe(name: &str) -> String {
    if cfg!(windows) { format!("{name}.exe") } else { name.to_string() }
}

/// Where the programs go
fn bin_dir(o: &Opts) -> PathBuf {
    if let Some(p) = &o.prefix {
        return p.join("bin");
    }
    if cfg!(windows) {
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into())).join("retail")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

fn api_addr() -> SocketAddr {
    std::env::var("RETAIL_API")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| retail_proto::LOCAL_API_ADDR.parse().expect("valid default address"))
}

/// Handles the installer flags, or this executable being a package. Returns
/// the exit code when it did; `None` means start the tray app as usual.
pub fn run(args: &[String]) -> Option<i32> {
    let mut opts = Opts::parse(args);
    let me = std::env::current_exe().ok()?;
    if args.iter().any(|a| a == "--uninstall") {
        return Some(report(uninstall(&opts)));
    }
    let manifest = File::open(&me).ok().and_then(|mut f| read_manifest(&mut f));
    if args.iter().any(|a| a == "--package-info") {
        match &manifest {
            Some(m) => println!("{}", serde_json::to_string_pretty(m).unwrap_or_default()),
            None => println!("not a package"),
        }
        return Some(0);
    }
    let manifest = manifest?;
    crate::i18n::set(crate::config::Config::load().language);
    let Ok(invite) = retail_proto::invite::Invite::decode(&manifest.invite) else {
        message("retail", tr("This installer is damaged: its invite code is unreadable."));
        return Some(2);
    };
    if args.iter().any(|a| a == "--install") {
        return Some(report(privileged(&me, &manifest, &opts)));
    }
    let network = if manifest.network.is_empty() {
        tr("a retail network").to_string()
    } else {
        trf("the retail network \"{name}\"", &[("name", &manifest.network)])
    };
    // retail already here and in another network: switch rather than install
    let target = format!("https://{}", invite.addrs[0]);
    let current = crate::api::status_blocking(api_addr())
        .ok()
        .filter(|s| s.state != BackendState::NeedsLogin)
        .and_then(|s| s.server)
        .filter(|s| *s != target);
    let (question, yes) = match &current {
        Some(cur) => (
            trf(
                "This computer is connected to {current}. Leave it and switch to {network}? You can switch back in retail's settings.",
                &[("current", &crate::settings::server_label(cur)), ("network", &network)],
            ),
            tr("Switch"),
        ),
        None => (trf("Install retail on this computer and join {network}?", &[("network", &network)]), tr("Install")),
    };
    if !confirm("retail", &question, yes) {
        return Some(1);
    }
    opts.switch = current.is_some();
    let code = if is_admin() {
        report(privileged(&me, &manifest, &opts))
    } else {
        match elevate(&me, &opts) {
            Ok(code) => code,
            Err(e) => report(Err(e)),
        }
    };
    if code != 0 {
        return Some(code);
    }
    let tray = bin_dir(&opts).join(exe("retail-tray"));
    if opts.autostart
        && let Err(e) = autostart(&tray)
    {
        eprintln!("retail: could not start the tray app at sign-in: {e}");
    }
    let done = if opts.switch {
        trf("This computer switched to {network}.", &[("network", &network)])
    } else {
        trf("retail is installed and this computer joined {network}.", &[("network", &network)])
    };
    message("retail", &done);
    if opts.autostart {
        let _ = std::process::Command::new(&tray).spawn();
    }
    Some(0)
}

fn report(r: Result<(), String>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            message("retail", &e);
            3
        }
    }
}

/// The raised part: files, boot registration, joining
fn privileged(me: &Path, m: &Manifest, o: &Opts) -> Result<(), String> {
    let dir = bin_dir(o);
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if o.service {
        // A daemon installed before is stopped by its own program
        let _ = daemon_service(&dir.join(exe("retaild")), "stop");
    }
    let mut src = File::open(me).map_err(|e| format!("reading the installer: {e}"))?;
    copy_range(&mut src, 0, m.base_len, &dir.join(exe("retail-tray")))?;
    for f in &m.files {
        if !safe_name(&f.name) {
            return Err(format!("the installer contains an unexpected file name: {}", f.name));
        }
        copy_range(&mut src, f.offset, f.len, &dir.join(&f.name))?;
    }
    let daemon = dir.join(exe("retaild"));
    if o.service {
        daemon_service(&daemon, "register")?;
    } else {
        let state = o.prefix.as_ref().map(|p| p.join("state"));
        let mut cmd = std::process::Command::new(&daemon);
        if let Some(s) = state {
            cmd.arg("--state-dir").arg(s);
        }
        cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        cmd.spawn().map_err(|e| format!("starting retaild: {e}"))?;
    }
    join(&m.invite, o.switch)
}

/// Writes `len` bytes from `offset` to `dest`, replacing it atomically
fn copy_range(src: &mut File, offset: u64, len: u64, dest: &Path) -> Result<(), String> {
    let err = |e: std::io::Error| format!("writing {}: {e}", dest.display());
    src.seek(SeekFrom::Start(offset)).map_err(err)?;
    let tmp = dest.with_extension("new");
    let mut out = File::create(&tmp).map_err(err)?;
    std::io::copy(&mut src.take(len), &mut out).map_err(err)?;
    out.flush().map_err(err)?;
    drop(out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(err)?;
    }
    std::fs::rename(&tmp, dest).map_err(err)
}

/// Waits for the daemon, then joins. A device in another network leaves it
/// only if the user agreed (`switch`); the daemon keeps it as a saved server.
fn join(invite: &str, switch: bool) -> Result<(), String> {
    let addr = api_addr();
    let start = Instant::now();
    let status = loop {
        match crate::api::status_blocking(addr) {
            Ok(s) => break s,
            Err(_) if start.elapsed() < API_WAIT => std::thread::sleep(Duration::from_millis(300)),
            Err(e) => return Err(trf("retaild did not start: {error}", &[("error", &e)])),
        }
    };
    let code = retail_proto::invite::Invite::decode(invite).map_err(|e| e.to_string())?;
    let target = format!("https://{}", code.addrs[0]);
    match status.server {
        Some(s) if !switch && status.state != BackendState::NeedsLogin && s != target => {
            return Err(trf(
                "retail is installed, but this computer already belongs to another network ({current}). To switch, run this installer again and choose to switch.",
                &[("current", &crate::settings::server_label(&s))],
            ));
        }
        Some(s) if s == target && status.state == BackendState::Running => return Ok(()),
        _ => {}
    }
    let body = serde_json::to_string(&retail_proto::api::UpRequest { invite: Some(invite.to_string()), ..Default::default() })
        .map_err(|e| e.to_string())?;
    crate::api::post_blocking_timeout(addr, "/up", &body, Duration::from_secs(60)).map_err(|e| trf("Joining failed: {error}", &[("error", &e)]))
}

fn uninstall(o: &Opts) -> Result<(), String> {
    if !is_admin() {
        return Err("run the uninstaller as administrator/root".into());
    }
    let dir = bin_dir(o);
    if o.service {
        let _ = daemon_service(&dir.join(exe("retaild")), "remove");
    }
    for name in ["retaild", "retail", "retail-tray"] {
        let _ = std::fs::remove_file(dir.join(exe(name)));
    }
    if cfg!(windows) {
        let _ = std::fs::remove_file(dir.join("wintun.dll"));
        let _ = std::fs::remove_dir(&dir);
    }
    remove_autostart();
    Ok(())
}

#[cfg(windows)]
fn run_quiet(program: &str, args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(program).args(args).output().map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

/// Boot registration of the daemon (systemd, launchd, Task Scheduler), done
/// by retaild itself: `retaild service register|stop|remove`
fn daemon_service(daemon: &Path, action: &str) -> Result<(), String> {
    if !daemon.is_file() {
        return Err(format!("{} is missing", daemon.display()));
    }
    let out = std::process::Command::new(daemon).args(["service", action]).output().map_err(|e| format!("{}: {e}", daemon.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().trim_start_matches("Error: ").to_string())
    }
}

/// Done from the user's own process: a raised process may run as another
/// administrator, whose sign-in settings are not the user's
#[cfg(windows)]
fn autostart(tray: &Path) -> Result<(), String> {
    let value = format!("\"{}\"", tray.display());
    run_quiet("reg", &["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "retail", "/d", &value, "/f"])
}

#[cfg(windows)]
fn remove_autostart() {
    let _ = run_quiet("reg", &["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "retail", "/f"]);
}

#[cfg(target_os = "linux")]
fn autostart_file() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join("autostart").join("retail-tray.desktop"))
}

#[cfg(target_os = "linux")]
fn autostart(tray: &Path) -> Result<(), String> {
    let file = autostart_file().ok_or("no home directory")?;
    std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
    let desktop = format!("[Desktop Entry]\nType=Application\nName=retail\nExec={}\nX-GNOME-Autostart-enabled=true\n", tray.display());
    std::fs::write(&file, desktop).map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn remove_autostart() {
    if let Some(f) = autostart_file() {
        let _ = std::fs::remove_file(f);
    }
}

#[cfg(target_os = "macos")]
fn agent_file() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("HOME")?).join("Library/LaunchAgents/dev.retail.tray.plist"))
}

#[cfg(target_os = "macos")]
fn autostart(tray: &Path) -> Result<(), String> {
    let file = agent_file().ok_or("no home directory")?;
    std::fs::create_dir_all(file.parent().unwrap()).map_err(|e| e.to_string())?;
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>dev.retail.tray</string>\
         <key>ProgramArguments</key><array><string>{}</string></array><key>RunAtLoad</key><true/></dict></plist>\n",
        tray.display()
    );
    std::fs::write(&file, plist).map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
fn remove_autostart() {
    if let Some(f) = agent_file() {
        let _ = std::fs::remove_file(f);
    }
}

#[cfg(windows)]
fn is_admin() -> bool {
    // `net session` succeeds only in an elevated process
    std::process::Command::new("net").arg("session").output().is_ok_and(|o| o.status.success())
}

#[cfg(unix)]
fn is_admin() -> bool {
    std::process::Command::new("id").arg("-u").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

/// Runs this executable with `--install` as administrator and waits for it
#[cfg(windows)]
fn elevate(me: &Path, o: &Opts) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let mut params = vec!["--install".to_string()];
    params.extend(o.forward().into_iter().map(|a| format!("\"{a}\"")));
    let (verb, file, params) = (wide("runas"), wide(&me.display().to_string()), wide(&params.join(" ")));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 0;
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        return Err("administrator permission was not given".into());
    }
    let mut code = 1u32;
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    Ok(code as i32)
}

#[cfg(target_os = "linux")]
fn elevate(me: &Path, o: &Opts) -> Result<i32, String> {
    let mut args = vec![me.display().to_string(), "--install".to_string()];
    args.extend(o.forward());
    match std::process::Command::new("pkexec").args(&args).status() {
        Ok(s) => Ok(s.code().unwrap_or(1)),
        Err(_) => Err(format!("pkexec was not found. Run as root instead:\n  sudo {}", args.join(" "))),
    }
}

#[cfg(target_os = "macos")]
fn elevate(me: &Path, o: &Opts) -> Result<i32, String> {
    let mut cmd = format!("'{}' --install", me.display().to_string().replace('\'', "'\\''"));
    for a in o.forward() {
        cmd.push_str(&format!(" '{}'", a.replace('\'', "'\\''")));
    }
    let script = format!("do shell script \"{}\" with administrator privileges", cmd.replace('\\', "\\\\").replace('"', "\\\""));
    match std::process::Command::new("osascript").args(["-e", &script]).status() {
        Ok(s) => Ok(s.code().unwrap_or(1)),
        Err(e) => Err(format!("osascript: {e}")),
    }
}

#[cfg(windows)]
fn message(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(text).as_ptr(), wide(title).as_ptr(), MB_OK | MB_ICONINFORMATION) };
}

#[cfg(windows)]
fn confirm(title: &str, text: &str, _yes: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONQUESTION, MB_YESNO, MessageBoxW};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(text).as_ptr(), wide(title).as_ptr(), MB_YESNO | MB_ICONQUESTION) == IDYES }
}

#[cfg(target_os = "macos")]
fn message(title: &str, text: &str) {
    let script = format!("display dialog \"{}\" with title \"{title}\" buttons {{\"OK\"}} default button 1", text.replace('"', "'"));
    let _ = std::process::Command::new("osascript").args(["-e", &script]).status();
}

#[cfg(target_os = "macos")]
fn confirm(title: &str, text: &str, yes: &str) -> bool {
    let script = format!(
        "display dialog \"{}\" with title \"{title}\" buttons {{\"{}\", \"{yes}\"}} default button 2 cancel button 1",
        text.replace('"', "'"),
        tr("Cancel")
    );
    std::process::Command::new("osascript").args(["-e", &script]).status().is_ok_and(|s| s.success())
}

/// A terminal when there is one, otherwise zenity if installed
#[cfg(target_os = "linux")]
fn message(title: &str, text: &str) {
    if std::process::Command::new("zenity").args(["--info", "--title", title, "--text", text]).status().is_err() {
        println!("{text}");
    }
}

#[cfg(target_os = "linux")]
fn confirm(title: &str, text: &str, yes: &str) -> bool {
    if std::env::var_os("RETAIL_INSTALL_YES").is_some() {
        return true;
    }
    if let Ok(s) = std::process::Command::new("zenity").args(["--question", "--title", title, "--text", text, "--ok-label", yes, "--cancel-label", tr("Cancel")]).status() {
        return s.success();
    }
    print!("{text} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ranges() {
        let dir = std::env::temp_dir().join(format!("retail-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src_path = dir.join("pkg");
        std::fs::write(&src_path, b"TRAYdaemoncli").unwrap();
        let mut src = File::open(&src_path).unwrap();
        copy_range(&mut src, 4, 6, &dir.join("retaild")).unwrap();
        copy_range(&mut src, 0, 4, &dir.join("retail-tray")).unwrap();
        assert_eq!(std::fs::read(dir.join("retaild")).unwrap(), b"daemon");
        assert_eq!(std::fs::read(dir.join("retail-tray")).unwrap(), b"TRAY");
        let _ = std::fs::remove_dir_all(dir);
    }
}
