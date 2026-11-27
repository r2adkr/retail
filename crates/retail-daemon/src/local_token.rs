//! The local API token file is readable only by users allowed to control
//! retail; the administrator token next to it only by administrators/root

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Written after `write_new`, which makes and protects the folder
pub fn write_admin() -> Result<String> {
    let token = new_token();
    write_private(&retail_proto::local::admin_token_path(), &token)?;
    Ok(token)
}

/// A file someone else made, or holds open, is never reused for a secret
fn write_private(path: &Path, token: &str) -> Result<()> {
    use std::io::Write;
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing {}", path.display()));
        }
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    // No sharing: nobody can open it for reading while the inherited
    // entries are still on it
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 0);
    let mut f = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(windows)]
    {
        let ok = std::process::Command::new("icacls")
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "/grant:r",
                "*S-1-5-32-544:F",
                "/Q",
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        anyhow::ensure!(ok, "could not restrict access to {}", path.display());
    }
    f.write_all(token.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
pub fn write_new() -> Result<String> {
    let token = new_token();
    // The last run's administrator token goes first: the folder's permissions
    // are set again below and would reach it
    let _ = std::fs::remove_file(retail_proto::local::admin_token_path());
    let path = retail_proto::local::token_path();
    let dir = path.parent().context("token path has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    restrict(dir, &path)?;
    std::fs::write(&path, &token).with_context(|| format!("writing {}", path.display()))?;
    restrict(dir, &path)?;
    Ok(token)
}

#[cfg(unix)]
fn restrict(dir: &Path, file: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Root plus the control group when it exists, otherwise root only
    let group = if cfg!(target_os = "macos") {
        "admin"
    } else {
        "retail"
    };
    let mut gid = group_id(group);
    for (p, mode) in [(dir, 0o750), (file, 0o640)] {
        if !p.exists() {
            continue;
        }
        // Not allowed to give it to the group (a unit without CAP_CHOWN):
        // root only, and the group's members sign in with the token instead
        if let Some(g) = gid
            && let Err(e) = std::os::unix::fs::chown(p, None, Some(g))
        {
            tracing::warn!("could not give {} to the {group} group: {e}", p.display());
            gid = None;
        }
        let mode = if gid.is_some() { mode } else { mode & 0o700 };
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(unix)]
fn group_id(name: &str) -> Option<u32> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name)
            .then(|| f.nth(1)?.parse().ok())
            .flatten()
    })
}

#[cfg(windows)]
fn restrict(dir: &Path, file: &Path) -> Result<()> {
    crate::state::take_over(dir);
    // SYSTEM and Administrators get full access, INTERACTIVE (local logons) read
    // SIDs rather than account names, which are localized. The folder only:
    // with /T icacls would put these folder-only entries on the file too,
    // which leaves it readable by nobody
    let ok = std::process::Command::new("icacls")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-4:(OI)(CI)R",
            "/Q",
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    anyhow::ensure!(ok, "could not restrict access to {}", dir.display());
    // The token takes the folder's entries (the administrator token, written
    // later, gets its own)
    if file.exists() {
        let ok = std::process::Command::new("icacls")
            .arg(file)
            .args(["/reset", "/Q"])
            .output()
            .is_ok_and(|o| o.status.success());
        anyhow::ensure!(ok, "could not set access to {}", file.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_file_is_new_and_unshared_until_written() {
        let dir = std::env::temp_dir().join(format!("retail-token-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin-token");
        std::fs::write(&path, "old").unwrap();
        write_private(&path, "secret").unwrap();
        #[cfg(unix)]
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        // A file held open by someone else is not reused
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let _ = std::fs::remove_file(&path);
            let held = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .share_mode(1)
                .open(&path)
                .unwrap();
            assert!(write_private(&path, "secret").is_err());
            drop(held);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
