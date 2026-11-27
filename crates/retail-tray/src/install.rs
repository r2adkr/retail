//! Self-install for client packages (`retail_proto::package`). Run as a
//! package, the tray app asks to install, raises itself to administrator
//! once, unpacks the daemon and CLI next to a plain copy of itself, has the
//! daemon start at boot (Windows Task Scheduler, systemd, launchd), joins with
//! the invite inside if there is one, then registers and starts the tray app
//! for the user.
//!
//! The official installer of a release is such a package without an invite:
//! it installs (or updates) retail, and the tray app then offers to join.
//! A package a server made joins its network; on a device already in another
//! network it asks whether to switch, and the daemon then leaves that network
//! (keeping it among the saved servers) and joins this one.
//!
//! Flags: `--install` (the raised step), `--switch` (it may leave another
//! network), `--invite CODE` (join with this code), `--yes` (ask nothing),
//! `--uninstall`, `--package-info`, and for tests `--prefix DIR` (install
//! under DIR), `--no-service` (start the daemon directly instead of
//! registering it), `--no-autostart`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use retail_proto::api::BackendState;
use retail_proto::package::{Manifest, read_manifest, safe_name};

use crate::i18n::{tr, trf};
use crate::setup;

const API_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Opts {
    prefix: Option<PathBuf>,
    service: bool,
    autostart: bool,
    /// The user agreed to leave the network this device is in
    switch: bool,
    /// Given on the command line, in place of the package's
    invite: Option<String>,
    yes: bool,
    /// The raised step writes its error here for the window that started it
    result: Option<PathBuf>,
    /// This is the window, raised to administrator at the start (Windows);
    /// the user's own process that raised it does the per-user steps
    raised_window: bool,
}

impl Opts {
    fn parse(args: &[String]) -> Self {
        let value = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        Opts {
            prefix: value("--prefix").map(PathBuf::from),
            service: !args.iter().any(|a| a == "--no-service"),
            autostart: !args.iter().any(|a| a == "--no-autostart"),
            switch: args.iter().any(|a| a == "--switch"),
            invite: value("--invite").filter(|i| !i.trim().is_empty()),
            yes: args.iter().any(|a| a == "--yes")
                || std::env::var_os("RETAIL_INSTALL_YES").is_some(),
            result: value("--result").map(PathBuf::from),
            raised_window: args.iter().any(|a| a == "--raised-window"),
        }
    }

    /// Hands the same flags to the raised step
    fn forward(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(p) = &self.prefix {
            out.push("--prefix".into());
            out.push(p.display().to_string());
        }
        if let Some(i) = &self.invite {
            out.push("--invite".into());
            out.push(i.clone());
        }
        if let Some(r) = &self.result {
            out.push("--result".into());
            out.push(r.display().to_string());
        }
        if self.yes {
            out.push("--yes".into());
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
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// Where the programs go
fn bin_dir(o: &Opts) -> PathBuf {
    if let Some(p) = &o.prefix {
        return p.join("bin");
    }
    if cfg!(windows) {
        PathBuf::from(
            std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
        )
        .join("retail")
    } else if cfg!(target_os = "macos") {
        PathBuf::from(retail_proto::programs::MACOS_DIR)
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

fn api_addr() -> SocketAddr {
    std::env::var("RETAIL_API")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            retail_proto::LOCAL_API_ADDR
                .parse()
                .expect("valid default address")
        })
}

/// The package this program is, or on macOS the one in the app it runs from
/// (`retail.app/Contents/Resources/retail.package`, next to `MacOS/retail`)
fn package(me: &Path) -> Option<(PathBuf, Manifest)> {
    let read = |p: &Path| {
        File::open(p)
            .ok()
            .and_then(|mut f| read_manifest(&mut f))
            .map(|m| (p.to_path_buf(), m))
    };
    read(me).or_else(|| {
        let macos = me
            .parent()
            .filter(|d| cfg!(target_os = "macos") && d.ends_with("Contents/MacOS"))?;
        read(&macos.parent()?.join("Resources").join("retail.package"))
    })
}

/// Handles the installer flags, or this executable being a package. Returns
/// the exit code when it did; `None` means start the tray app as usual.
pub fn run(args: &[String]) -> Option<i32> {
    let mut opts = Opts::parse(args);
    let me = std::env::current_exe().ok()?;
    if args.iter().any(|a| a == "--uninstall") {
        crate::i18n::set(crate::config::Config::load().language);
        QUIET.store(opts.yes, std::sync::atomic::Ordering::Relaxed);
        // From Settings → Installed apps, which starts it unraised: the raised
        // copy does the work and tells how it went
        #[cfg(windows)]
        if !is_admin() {
            return Some(
                elevate_with(&me, "--uninstall", &opts, || {}).unwrap_or_else(|e| {
                    tell(&e);
                    1
                }),
            );
        }
        let r = uninstall(&opts, &me);
        if r.is_ok() {
            let done = tr(
                "retail was removed from this computer. Its settings and keys stay, should you install it again.",
            );
            // A window on Windows (Settings → Installed apps starts it); on
            // Linux and macOS it runs from a terminal or the package manager
            if cfg!(windows) {
                tell(done)
            } else {
                println!("{done}")
            }
        }
        return Some(report(r));
    }
    let found = package(&me);
    if args.iter().any(|a| a == "--package-info") {
        match &found {
            Some((_, m)) => println!("{}", serde_json::to_string_pretty(m).unwrap_or_default()),
            None => println!("not a package"),
        }
        return Some(0);
    }
    let (source, manifest) = found?;
    crate::i18n::set(crate::config::Config::load().language);
    QUIET.store(opts.yes, std::sync::atomic::Ordering::Relaxed);
    // The command line's code, the package's, or none (the official installer)
    if opts.invite.is_none() && !manifest.invite.is_empty() {
        opts.invite = Some(manifest.invite.clone());
    }
    let invite = match opts
        .invite
        .as_deref()
        .map(retail_proto::invite::Invite::decode)
    {
        None => None,
        Some(Ok(i)) => Some(i),
        Some(Err(_)) => {
            tell(tr(
                "This installer is damaged: its invite code is unreadable.",
            ));
            return Some(2);
        }
    };
    if args.iter().any(|a| a == "--install") {
        let r = privileged(&source, &manifest, &opts);
        // For the window that raised this step, which shows the error itself
        if let Some(f) = &opts.result {
            write_result(f, r.as_ref().err().map_or("", String::as_str));
            return Some(if r.is_ok() { 0 } else { 3 });
        }
        return Some(report(r));
    }
    let network = if manifest.network.is_empty() {
        tr("a retail network").to_string()
    } else {
        trf(
            "the retail network \"{name}\"",
            &[("name", &manifest.network)],
        )
    };
    let status = crate::api::status_blocking(api_addr()).ok();
    let installed = status.is_some() || bin_dir(&opts).join(exe("retaild")).is_file();
    // retail already here and in another network: switch rather than install
    let current = invite.as_ref().and_then(|invite| {
        let target = format!("https://{}", invite.addrs[0]);
        status
            .as_ref()
            .filter(|s| s.state != BackendState::NeedsLogin)
            .and_then(|s| s.server.clone())
            .filter(|s| *s != target)
    });
    let version = env!("CARGO_PKG_VERSION");
    opts.switch = current.is_some();
    // The installer's own window where there is a desktop to show it on
    if !opts.yes && has_desktop() {
        // Windows asks for administrator rights as the installer opens; this
        // process waits and then sets up the tray app for the user. Declined,
        // the window opens here and asks again when installing.
        #[cfg(windows)]
        if !opts.raised_window
            && !is_admin()
            && let Some(code) = raised_window(&me, &opts, installed)
        {
            return Some(code);
        }
        let kind = match (&invite, &current) {
            (Some(_), Some(cur)) => setup::Kind::Switch {
                current: crate::settings::server_label(cur),
                network: network.clone(),
            },
            (Some(_), None) => setup::Kind::Join {
                network: network.clone(),
            },
            (None, _) if installed => setup::Kind::Update,
            (None, _) => setup::Kind::Install,
        };
        let joined = status
            .as_ref()
            .is_some_and(|s| s.state != BackendState::NeedsLogin && s.server.is_some());
        let dir = bin_dir(&opts).display().to_string();
        let work_opts = opts.clone();
        let (me, source, manifest) = (me.clone(), source.clone(), manifest.clone());
        let work = move |typed: Option<String>| -> Result<(), String> {
            let mut o = work_opts.clone();
            if typed.is_some() {
                o.invite = typed;
            }
            install_now(&me, &source, &manifest, &o)?;
            match (&o.result, o.raised_window) {
                // Tells the user's process waiting for this window
                (Some(f), true) => write_result(f, INSTALLED),
                _ => {
                    after_install(&o, installed);
                }
            }
            Ok(())
        };
        if let Some(code) = setup::run_window(kind, version, &dir, joined, Box::new(work)) {
            return Some(code);
        }
        // No window could open: ask in dialogs as below
    }
    let (question, yes) = match (&invite, &current) {
        (Some(_), Some(cur)) => (
            trf(
                "This computer is connected to {current}. Leave it and switch to {network}? You can switch back in retail's settings.",
                &[
                    ("current", &crate::settings::server_label(cur)),
                    ("network", &network),
                ],
            ),
            tr("Switch"),
        ),
        (Some(_), None) => (
            trf(
                "Install retail on this computer and join {network}?",
                &[("network", &network)],
            ),
            tr("Install"),
        ),
        (None, _) if installed => (
            trf(
                "Update retail on this computer to version {version}?",
                &[("version", &version)],
            ),
            tr("Update"),
        ),
        (None, _) => (
            trf(
                "Install retail {version} on this computer?",
                &[("version", &version)],
            ),
            tr("Install"),
        ),
    };
    if !opts.yes && !confirm("retail", &question, yes) {
        return Some(1);
    }
    let code = report(install_now(&me, &source, &manifest, &opts));
    if code != 0 {
        return Some(code);
    }
    let desktop = after_install(&opts, installed);
    let done = match (&invite, opts.switch) {
        (Some(_), true) => trf("This computer switched to {network}.", &[("network", &network)]),
        (Some(_), false) => trf("retail is installed and this computer joined {network}.", &[("network", &network)]),
        (None, _) if installed => trf("retail is updated to version {version}.", &[("version", &version)]),
        (None, _) if desktop => tr("retail is installed. Join a network from the retail icon.").to_string(),
        (None, _) => tr("retail is installed. Join a network with `retail up --invite <code>`, or host one with `retail server start`.").to_string(),
    };
    tell(&done);
    Some(0)
}

/// The file the raised step answers in, made by the user beforehand under a
/// name nobody can guess: in a shared temporary folder (Linux `/tmp`) another
/// user's link of a known name would have root write wherever it points
fn result_file(what: &str) -> Result<PathBuf, String> {
    for _ in 0..8 {
        // Keys from the system's random source, new for each RandomState
        let nonce = std::hash::BuildHasher::hash_one(
            &std::collections::hash_map::RandomState::new(),
            std::process::id(),
        );
        let path = std::env::temp_dir().join(format!("retail-{what}-{nonce:016x}.txt"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err("no temporary file could be made".into())
}

/// Answers in the file `result_file` made: only an existing file, and on
/// Unix not through a link
fn write_result(path: &Path, text: &str) {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW);
    if let Ok(mut f) = o.open(path) {
        let _ = f.write_all(text.as_bytes());
    }
}

/// What the raised window writes once it has installed
const INSTALLED: &str = "installed";

/// Runs the installer window as administrator and waits for it. When it
/// says it has installed, the tray app is set up here, as the user (a raised
/// process would start it as administrator, in the administrator's sign-in
/// settings). `None` if the user declined.
#[cfg(windows)]
fn raised_window(me: &Path, opts: &Opts, installed: bool) -> Option<i32> {
    let result = result_file("window").ok()?;
    let raised = Opts {
        result: Some(result.clone()),
        ..opts.clone()
    };
    let mut done = false;
    let code = elevate_with(me, "--raised-window", &raised, || {
        if !done && std::fs::read_to_string(&result).is_ok_and(|s| s == INSTALLED) {
            done = true;
            after_install(opts, installed);
        }
    })
    .ok()?;
    if !done && std::fs::read_to_string(&result).is_ok_and(|s| s == INSTALLED) {
        after_install(opts, installed);
    }
    let _ = std::fs::remove_file(&result);
    Some(code)
}

/// Installs, raising itself to administrator if it is not one: the raised
/// copy runs `--install` and leaves its error in a file for this one
fn install_now(me: &Path, source: &Path, m: &Manifest, opts: &Opts) -> Result<(), String> {
    if is_admin() {
        return privileged(source, m, opts);
    }
    let result = result_file("install")?;
    let raised = Opts {
        result: Some(result.clone()),
        yes: true,
        ..opts.clone()
    };
    let code = elevate(me, &raised)?;
    let error = std::fs::read_to_string(&result).unwrap_or_default();
    let _ = std::fs::remove_file(&result);
    match (code, error.trim()) {
        (0, _) => Ok(()),
        (_, "") => Err(trf(
            "The installation stopped (code {code}).",
            &[("code", &code)],
        )),
        (_, e) => Err(e.to_string()),
    }
}

/// The user's part after installing: the tray app at sign-in and now.
/// Returns whether there is a desktop for it.
fn after_install(opts: &Opts, installed: bool) -> bool {
    let tray = bin_dir(opts).join(exe("retail-tray"));
    // A server without a desktop gets no tray app
    let desktop = opts.autostart && has_desktop();
    if desktop && let Err(e) = autostart(&tray) {
        eprintln!("retail: could not start the tray app at sign-in: {e}");
    }
    // On an update a tray app already running restarts itself into the new
    // one when it sees its program file replaced; starting another would make two
    if desktop && !installed {
        // Not on the installer's output, which a script may be reading to its end
        use std::process::Stdio;
        // With its popup open, so it is plain that retail is there
        let _ = std::process::Command::new(&tray)
            .arg("--show")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    desktop
}

/// Whether a desktop session can show the tray app (Linux may be a server).
/// Under sudo the tray app would be root's, so it is left out: run without
/// sudo on a desktop and the installer asks for the password itself.
fn has_desktop() -> bool {
    if cfg!(target_os = "linux") {
        (std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some())
            && std::env::var_os("SUDO_USER").is_none()
    } else {
        true
    }
}

/// With `--yes` nothing is shown in a window, which would wait for a click
/// (scripted installs, CI); messages go to the terminal
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn tell(text: &str) {
    if QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        println!("{text}");
    } else {
        message("retail", text);
    }
}

fn report(r: Result<(), String>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => {
            tell(&e);
            3
        }
    }
}

/// The raised part: files, boot registration, joining
fn privileged(source: &Path, m: &Manifest, o: &Opts) -> Result<(), String> {
    let dir = bin_dir(o);
    #[cfg(target_os = "macos")]
    if o.prefix.is_none() {
        retail_proto::programs::make_root_only(&dir)
            .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if o.service {
        // A daemon installed before is stopped by its own program
        let _ = daemon_service(&dir.join(exe("retaild")), "stop");
    }
    let mut src = File::open(source).map_err(|e| format!("reading the installer: {e}"))?;
    copy_range(&mut src, 0, m.base_len, &dir.join(exe("retail-tray")))?;
    for f in &m.files {
        if !safe_name(&f.name) {
            return Err(format!(
                "the installer contains an unexpected file name: {}",
                f.name
            ));
        }
        copy_range(&mut src, f.offset, f.len, &dir.join(&f.name))?;
    }
    #[cfg(target_os = "macos")]
    if o.prefix.is_none() {
        retail_proto::programs::link(&dir, Path::new(retail_proto::programs::MACOS_LINKS))
            .map_err(|e| {
                format!(
                    "linking the programs in {}: {e}",
                    retail_proto::programs::MACOS_LINKS
                )
            })?;
    }
    // Before the daemon starts, so it gives the group its token file
    #[cfg(target_os = "linux")]
    if o.service {
        let_user_control();
    }
    // In the system's list of apps (not for a trial install under --prefix)
    if o.service
        && o.prefix.is_none()
        && let Err(e) = crate::app_entry::add(&dir, env!("CARGO_PKG_VERSION"))
    {
        eprintln!("retail: could not add retail to the list of apps: {e}");
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
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd.spawn().map_err(|e| format!("starting retaild: {e}"))?;
    }
    match &o.invite {
        Some(invite) => join(invite, o.switch),
        None => wait_for_daemon().map(|_| ()),
    }
}

/// On Linux the users who may control retail are root and the `retail`
/// group: the group is made if missing, and the user who ran the installer
/// (through pkexec or sudo) joins it, so their tray app works
#[cfg(target_os = "linux")]
fn let_user_control() {
    let quiet = |cmd: &str, args: &[&str]| {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !quiet("getent", &["group", "retail"]) && !quiet("groupadd", &["--system", "retail"]) {
        eprintln!("retail: could not make the retail group");
        return;
    }
    let user = match std::env::var("PKEXEC_UID") {
        Ok(uid) => std::process::Command::new("id")
            .args(["-nu", &uid])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Err(_) => std::env::var("SUDO_USER").ok(),
    };
    if let Some(user) = user.filter(|u| !u.is_empty() && u != "root")
        && !quiet("usermod", &["-aG", "retail", &user])
    {
        eprintln!("retail: could not add {user} to the retail group");
    }
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
    // Windows will not overwrite a running program (the tray app, when this
    // installs over itself) but lets it be renamed: it moves aside to `.old`,
    // which the daemon removes when it next starts
    #[cfg(windows)]
    if dest.exists() {
        let old = dest.with_extension(match dest.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.old"),
            None => "old".into(),
        });
        let _ = std::fs::remove_file(&old);
        std::fs::rename(dest, &old).map_err(err)?;
    }
    std::fs::rename(&tmp, dest).map_err(err)
}

/// Waits for the daemon to answer. What answers must be the daemon just
/// started, not a program that took its port first: it would get the invite,
/// or fake a join.
fn wait_for_daemon() -> Result<retail_proto::api::StatusResponse, String> {
    let addr = api_addr();
    let start = Instant::now();
    let status = loop {
        match crate::api::status_blocking(addr) {
            Ok(s) => break s,
            Err(_) if start.elapsed() < API_WAIT => std::thread::sleep(Duration::from_millis(300)),
            Err(e) => return Err(trf("retaild did not start: {error}", &[("error", &e)])),
        }
    };
    retail_proto::local::check_listener(addr)?;
    Ok(status)
}

/// Waits for the daemon, then joins. A device in another network leaves it
/// only if the user agreed (`switch`); the daemon keeps it as a saved server.
fn join(invite: &str, switch: bool) -> Result<(), String> {
    let addr = api_addr();
    let mut status = wait_for_daemon()?;
    let code = retail_proto::invite::Invite::decode(invite).map_err(|e| e.to_string())?;
    let target = format!("https://{}", code.addrs[0]);
    // Already in this network: the daemon answers before it has reconnected
    // (an update), so give it a moment rather than joining again
    let start = Instant::now();
    while status.server.as_deref() == Some(target.as_str())
        && status.state == BackendState::Stopped
        && start.elapsed() < API_WAIT
    {
        std::thread::sleep(Duration::from_millis(500));
        match crate::api::status_blocking(addr) {
            Ok(s) => status = s,
            Err(_) => break,
        }
    }
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
    let body = serde_json::to_string(&retail_proto::api::UpRequest {
        invite: Some(invite.to_string()),
        ..Default::default()
    })
    .map_err(|e| e.to_string())?;
    crate::api::post_blocking_timeout(addr, "/up", &body, Duration::from_secs(60))
        .map_err(|e| trf("Joining failed: {error}", &[("error", &e)]))
}

fn uninstall(o: &Opts, me: &Path) -> Result<(), String> {
    if !is_admin() {
        return Err("run the uninstaller as administrator/root".into());
    }
    let dir = bin_dir(o);
    if o.service {
        let mut daemon = dir.join(exe("retaild"));
        // Installed before 1.0.2, in the folder the links are in now
        if cfg!(target_os = "macos") && o.prefix.is_none() && !daemon.is_file() {
            daemon = Path::new(retail_proto::programs::MACOS_LINKS).join("retaild");
        }
        let _ = daemon_service(&daemon, "remove");
    }
    if o.prefix.is_none() {
        crate::app_entry::remove(&dir);
    }
    end_other_tray_apps();
    for name in ["retaild", "retail", "retail-tray"] {
        let _ = std::fs::remove_file(dir.join(exe(name)));
    }
    if cfg!(windows) {
        let _ = std::fs::remove_file(dir.join("wintun.dll"));
        let _ = std::fs::remove_dir(&dir);
    }
    #[cfg(target_os = "macos")]
    if o.prefix.is_none() {
        retail_proto::programs::unlink(&dir, Path::new(retail_proto::programs::MACOS_LINKS));
        let _ = std::fs::remove_dir(&dir);
        let _ = dir.parent().map(std::fs::remove_dir);
    }
    // Run from the folder it removes (Settings → Installed apps), or a
    // program in it still ending: Windows keeps a running program's file, so
    // the folder goes a moment after this has ended
    #[cfg(windows)]
    if dir.exists() {
        let _ = remove_dir_later(&dir, 3);
    }
    let _ = me;
    remove_autostart();
    Ok(())
}

/// Removes `dir` after about `pings - 1` seconds, from a process of its own
#[cfg(windows)]
fn remove_dir_later(dir: &Path, pings: u32) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    // cmd reads its command line as it is: Rust's quoting (\" for a quote)
    // would leave it a path it cannot find
    std::process::Command::new(system_program("cmd"))
        .raw_arg(format!(
            "/C ping -n {pings} 127.0.0.1 >NUL & rmdir /S /Q \"{}\"",
            dir.display()
        ))
        .creation_flags(0x0800_0000)
        .spawn()
}

/// The tray apps still running, every signed-in user's, but not this
/// process (which is one of the same program)
fn end_other_tray_apps() {
    #[cfg(windows)]
    let _ = run_quiet(
        "taskkill",
        &[
            "/F",
            "/IM",
            "retail-tray.exe",
            "/FI",
            &format!("PID ne {}", std::process::id()),
        ],
    );
    #[cfg(unix)]
    if let Ok(out) = std::process::Command::new("pgrep")
        .args(["-x", "retail-tray"])
        .output()
    {
        let me = std::process::id().to_string();
        for pid in String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter(|p| *p != me)
        {
            let _ = std::process::Command::new("kill").arg(pid).status();
        }
    }
}

#[cfg(windows)]
fn run_quiet(program: &str, args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(system_program(program))
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Boot registration of the daemon (systemd, launchd, Task Scheduler), done
/// by retaild itself: `retaild service register|stop|remove`
fn daemon_service(daemon: &Path, action: &str) -> Result<(), String> {
    if !daemon.is_file() {
        return Err(format!("{} is missing", daemon.display()));
    }
    let out = std::process::Command::new(daemon)
        .args(["service", action])
        .output()
        .map_err(|e| format!("{}: {e}", daemon.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr)
            .trim()
            .trim_start_matches("Error: ")
            .to_string())
    }
}

/// Starts retaild as a service, asking for administrator permission: its
/// boot registration is put in place again (the current one) and started.
/// For a daemon that did not come back after an update, or was stopped.
pub fn start_daemon() -> Result<(), String> {
    let mut dir = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(Path::to_path_buf)
        .ok_or("no program folder")?;
    // Run as root: the root-only folder's, not one through a link the user can change
    if cfg!(target_os = "macos")
        && Path::new(retail_proto::programs::MACOS_DIR)
            .join("retaild")
            .is_file()
    {
        dir = PathBuf::from(retail_proto::programs::MACOS_DIR);
    }
    let daemon = dir.join(if cfg!(windows) {
        "retaild.exe"
    } else {
        "retaild"
    });
    if !daemon.is_file() {
        return Err(format!("{} is missing", daemon.display()));
    }
    start_daemon_raised(&daemon)
}

#[cfg(windows)]
fn start_daemon_raised(daemon: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let (verb, file, params) = (
        wide("runas"),
        wide(&daemon.display().to_string()),
        wide("service register"),
    );
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = 0; // SW_HIDE
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        return Err(tr("Administrator permission was not given.").into());
    }
    let mut code = 1u32;
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }
    if code == 0 {
        Ok(())
    } else {
        Err(tr("retaild could not be started.").into())
    }
}

#[cfg(target_os = "linux")]
fn start_daemon_raised(daemon: &Path) -> Result<(), String> {
    match std::process::Command::new("pkexec")
        .arg(daemon)
        .args(["service", "register"])
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => Err(tr("retaild could not be started.").into()),
        Err(_) => Err(format!("sudo {} service register", daemon.display())),
    }
}

#[cfg(target_os = "macos")]
fn start_daemon_raised(daemon: &Path) -> Result<(), String> {
    // The path goes in as an AppleScript string: quotes and backslashes escaped
    let path = daemon
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let script = format!(
        "do shell script quoted form of \"{path}\" & \" service register\" with administrator privileges"
    );
    match std::process::Command::new("osascript")
        .args(["-e", &script])
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        _ => Err(tr("retaild could not be started.").into()),
    }
}

/// Done from the user's own process: a raised process may run as another
/// administrator, whose sign-in settings are not the user's
#[cfg(windows)]
fn autostart(tray: &Path) -> Result<(), String> {
    let value = format!("\"{}\"", tray.display());
    run_quiet(
        "reg",
        &[
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "retail",
            "/d",
            &value,
            "/f",
        ],
    )
}

#[cfg(windows)]
fn remove_autostart() {
    let _ = run_quiet(
        "reg",
        &[
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "retail",
            "/f",
        ],
    );
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
    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=retail\nExec={}\nX-GNOME-Autostart-enabled=true\n",
        tray.display()
    );
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
    Some(
        PathBuf::from(std::env::var_os("HOME")?).join("Library/LaunchAgents/dev.retail.tray.plist"),
    )
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
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: the token handle is ours and closed; the buffer is the size given
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// A Windows program from System32 (`reg`, `taskkill`, `cmd`, PowerShell),
/// never one of the same name in the folder this runs from, which for an
/// installer is Downloads
#[cfg(windows)]
pub fn system_program(name: &str) -> std::path::PathBuf {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    // SAFETY: the buffer's length is passed
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n > 0 && n < buf.len() {
        String::from_utf16_lossy(&buf[..n])
    } else {
        r"C:\Windows\System32".to_string()
    };
    let dir = std::path::PathBuf::from(dir);
    match name {
        "powershell" => dir
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        _ => dir.join(format!("{name}.exe")),
    }
}

#[cfg(unix)]
fn is_admin() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

/// Runs this executable with `--install` as administrator and waits for it
#[cfg(windows)]
fn elevate(me: &Path, o: &Opts) -> Result<i32, String> {
    elevate_with(me, "--install", o, || {})
}

/// Runs this executable with `step` as administrator, calling `tick` now
/// and then until it ends
#[cfg(windows)]
fn elevate_with(me: &Path, step: &str, o: &Opts, mut tick: impl FnMut()) -> Result<i32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let mut params = vec![step.to_string()];
    params.extend(o.forward().into_iter().map(|a| format!("\"{a}\"")));
    let (verb, file, params) = (
        wide("runas"),
        wide(&me.display().to_string()),
        wide(&params.join(" ")),
    );
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    // Windows applies this to the program's first window: hidden for the
    // install step, which has none, shown for the installer window
    info.nShow = if step == "--raised-window" { 1 } else { 0 }; // SW_SHOWNORMAL, SW_HIDE
    if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
        return Err("administrator permission was not given".into());
    }
    while unsafe { WaitForSingleObject(info.hProcess, 300) } == WAIT_TIMEOUT {
        tick();
    }
    let mut code = 1u32;
    unsafe {
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
        Err(_) => Err(format!(
            "pkexec was not found. Run as root instead:\n  sudo {}",
            args.join(" ")
        )),
    }
}

#[cfg(target_os = "macos")]
fn elevate(me: &Path, o: &Opts) -> Result<i32, String> {
    let mut cmd = format!(
        "'{}' --install",
        me.display().to_string().replace('\'', "'\\''")
    );
    for a in o.forward() {
        cmd.push_str(&format!(" '{}'", a.replace('\'', "'\\''")));
    }
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    match std::process::Command::new("osascript")
        .args(["-e", &script])
        .status()
    {
        Ok(s) => Ok(s.code().unwrap_or(1)),
        Err(e) => Err(format!("osascript: {e}")),
    }
}

#[cfg(windows)]
fn message(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide(title).as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        )
    };
}

#[cfg(windows)]
fn confirm(title: &str, text: &str, _yes: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONQUESTION, MB_YESNO, MessageBoxW,
    };
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide(title).as_ptr(),
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES
    }
}

#[cfg(target_os = "macos")]
fn message(title: &str, text: &str) {
    let script = format!(
        "display dialog \"{}\" with title \"{title}\" buttons {{\"OK\"}} default button 1",
        text.replace('"', "'")
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .status();
}

#[cfg(target_os = "macos")]
fn confirm(title: &str, text: &str, yes: &str) -> bool {
    let script = format!(
        "display dialog \"{}\" with title \"{title}\" buttons {{\"{}\", \"{yes}\"}} default button 2 cancel button 1",
        text.replace('"', "'"),
        tr("Cancel")
    );
    std::process::Command::new("osascript")
        .args(["-e", &script])
        .status()
        .is_ok_and(|s| s.success())
}

/// A dialog (zenity) on a desktop, otherwise the terminal
#[cfg(target_os = "linux")]
fn message(title: &str, text: &str) {
    let shown = has_desktop()
        && std::process::Command::new("zenity")
            .args(["--info", "--title", title, "--text", text])
            .status()
            .is_ok_and(|s| s.success());
    if !shown {
        println!("{text}");
    }
}

#[cfg(target_os = "linux")]
fn confirm(title: &str, text: &str, yes: &str) -> bool {
    if std::env::var_os("RETAIL_INSTALL_YES").is_some() {
        return true;
    }
    // zenity exits 1 for "no" and 5 or more when it could not ask
    if has_desktop()
        && let Ok(s) = std::process::Command::new("zenity")
            .args([
                "--question",
                "--title",
                title,
                "--text",
                text,
                "--ok-label",
                yes,
                "--cancel-label",
                tr("Cancel"),
            ])
            .status()
        && matches!(s.code(), Some(0 | 1))
    {
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

    /// As under "C:\Program Files": a path with a space
    #[cfg(windows)]
    #[test]
    fn removes_a_folder_with_a_space_later() {
        let dir = std::env::temp_dir().join(format!("retail test {}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("file.txt"), "x").unwrap();
        let status = remove_dir_later(&dir, 1).unwrap().wait().unwrap();
        assert!(status.success());
        assert!(!dir.exists());
    }

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
