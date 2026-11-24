//! Updates to new official releases. The daemon checks the newest release
//! now and then; when asked (or on its own with `auto_update`) it downloads
//! the programs for this system, checks them against the release's
//! `SHA256SUMS`, puts them in place of the running ones and restarts. The
//! service manager starts the new daemon (systemd, launchd, Task Scheduler),
//! and the tray app restarts itself when it sees the daemon's new version.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use retail_proto::api::UpdateStatus;
use tokio::sync::Notify;

use crate::releases;

/// The first check waits for the network to settle after boot
const FIRST_CHECK: Duration = Duration::from_secs(60);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

/// Systems with official builds
const OFFICIAL: [&str; 6] = ["windows-x86_64", "linux-x86_64", "linux-aarch64", "linux-arm", "macos-aarch64", "macos-x86_64"];

pub struct Updater {
    status: Mutex<UpdateStatus>,
    state_dir: PathBuf,
    /// Set once new programs are in place; the daemon then restarts
    restarting: AtomicBool,
    pub restart: Notify,
}

fn variant() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn exe(name: &str) -> String {
    if cfg!(windows) { format!("{name}.exe") } else { name.to_string() }
}

/// The programs an update replaces, in the folder of the running daemon
fn programs() -> Vec<String> {
    ["retaild", "retail", "retail-tray"].into_iter().map(exe).collect()
}

impl Updater {
    pub fn new(state_dir: &Path) -> Self {
        let supported = OFFICIAL.contains(&variant().as_str()) && releases::base().is_some();
        Updater {
            status: Mutex::new(UpdateStatus { current: env!("CARGO_PKG_VERSION").into(), supported, ..Default::default() }),
            state_dir: state_dir.to_path_buf(),
            restarting: AtomicBool::new(false),
            restart: Notify::new(),
        }
    }

    pub fn status(&self) -> UpdateStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn restarting(&self) -> bool {
        self.restarting.load(Ordering::Relaxed)
    }

    /// Looks up the newest release
    pub async fn check(&self) -> Result<()> {
        if !self.status().supported {
            bail!("there are no official builds for {}", variant());
        }
        match releases::latest_version().await {
            Ok(latest) => {
                let mut s = self.status.lock().unwrap();
                s.available = releases::newer(&latest, &s.current);
                if s.available && s.latest.as_deref() != Some(latest.as_str()) {
                    tracing::info!("retail {latest} is available (this is {})", s.current);
                }
                s.latest = Some(latest);
                s.error = None;
                Ok(())
            }
            Err(e) => {
                self.status.lock().unwrap().error = Some(format!("{e:#}"));
                Err(e)
            }
        }
    }

    /// Downloads the newest release for this system and puts it in place of
    /// the running programs, then asks the daemon to restart
    pub async fn install(&self) -> Result<()> {
        let latest = self.begin()?;
        self.finish(latest).await
    }

    /// `install` in the background, so the caller sees `installing` at once
    pub fn start_install(self: &std::sync::Arc<Self>) -> Result<()> {
        let latest = self.begin()?;
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.finish(latest).await {
                tracing::warn!("update failed: {e:#}");
            }
        });
        Ok(())
    }

    fn begin(&self) -> Result<String> {
        let mut s = self.status.lock().unwrap();
        if s.installing {
            bail!("an update is already being installed");
        }
        if !s.available {
            bail!("there is no newer version to install");
        }
        let latest = s.latest.clone().context("no release found yet")?;
        s.installing = true;
        s.error = None;
        Ok(latest)
    }

    async fn finish(&self, latest: String) -> Result<()> {
        let result = self.install_version(&latest).await;
        let mut s = self.status.lock().unwrap();
        s.installing = false;
        match result {
            Ok(()) => {
                tracing::info!("updated to {latest}; restarting");
                self.restarting.store(true, Ordering::Relaxed);
                self.restart.notify_one();
                Ok(())
            }
            Err(e) => {
                s.error = Some(format!("{e:#}"));
                Err(e)
            }
        }
    }

    async fn install_version(&self, version: &str) -> Result<()> {
        let bin = std::env::current_exe()?.parent().context("the daemon has no folder")?.to_path_buf();
        let dir = self.state_dir.join("update").join(format!("v{version}"));
        // Only the programs that are installed here: a server-only machine may have no tray
        let files: Vec<String> = programs().into_iter().filter(|f| bin.join(f).is_file()).collect();
        // Every file is fetched and checked now; none already there is trusted
        let _ = std::fs::remove_dir_all(&dir);
        releases::fetch_version(version, &variant(), &files, &dir).await?;
        for f in &files {
            replace(&dir.join(f), &bin.join(f)).with_context(|| format!("replacing {}", bin.join(f).display()))?;
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}

/// Puts `new` in place of `target`, which may be running. Unix: a rename over
/// it (the running program keeps its old file). Windows refuses to overwrite a
/// running program but lets it be renamed, so the old one moves aside to
/// `.old`, removed at the next start.
fn replace(new: &Path, target: &Path) -> std::io::Result<()> {
    let staged = target.with_extension(if cfg!(windows) { "exe.new" } else { "new" });
    std::fs::copy(new, &staged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(windows)]
    {
        let old = target.with_extension("exe.old");
        let _ = std::fs::remove_file(&old);
        if target.exists() {
            std::fs::rename(target, &old)?;
        }
    }
    std::fs::rename(&staged, target)
}

/// Removes what an earlier update left behind
pub fn clean_up(state_dir: &Path) {
    if let Some(bin) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        for f in programs() {
            let _ = std::fs::remove_file(bin.join(&f).with_extension(if cfg!(windows) { "exe.old" } else { "old" }));
        }
    }
    let _ = std::fs::remove_dir_all(state_dir.join("update"));
}

/// Checks now and then, and installs on its own when the user turned that on
pub fn spawn(backend: std::sync::Arc<crate::backend::Backend>) {
    tokio::spawn(async move {
        tokio::time::sleep(FIRST_CHECK).await;
        loop {
            let u = &backend.updater;
            if u.status().supported
                && u.check().await.is_ok()
                && u.status().available
                && backend.auto_update().await
                && let Err(e) = u.install().await
            {
                tracing::warn!("automatic update failed: {e:#}");
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// After the daemon has shut down for an update: have the service manager
/// start the new program. systemd (`Restart=on-failure`) and launchd
/// (`KeepAlive`) do so on a failure exit; Task Scheduler only a minute later,
/// so the task is also started again a few seconds after this exits.
pub fn restart_after_exit() -> ! {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED: u32 = 0x0000_0008 | 0x0800_0000; // DETACHED_PROCESS | CREATE_NO_WINDOW
        let _ = std::process::Command::new("cmd")
            .args(["/C", "ping -n 4 127.0.0.1 >NUL & schtasks /Run /TN retail\\retaild"])
            .creation_flags(DETACHED)
            .spawn();
    }
    std::process::exit(75)
}
