//! Where the programs live on macOS. Before 1.0.2 they went to
//! /usr/local/bin, which Homebrew hands to the user on Intel Macs: that user
//! could swap the program launchd runs as root. They now live in a folder
//! only root can change, with links in /usr/local/bin for the command line.

#[cfg(unix)]
use std::path::Path;

pub const MACOS_DIR: &str = "/Library/retail/bin";
/// Links to the programs, so `retail` is on the PATH
pub const MACOS_LINKS: &str = "/usr/local/bin";
pub const NAMES: [&str; 3] = ["retaild", "retail", "retail-tray"];

/// Whether only root can change what is in `dir`: it and every folder above
/// it belong to root, and no one but root's group may write to them
#[cfg(unix)]
pub fn root_only(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(dir) = dir.canonicalize() else {
        return false;
    };
    dir.ancestors().all(|d| {
        std::fs::metadata(d).is_ok_and(|m| {
            m.uid() == 0 && m.mode() & 0o002 == 0 && (m.mode() & 0o020 == 0 || m.gid() == 0)
        })
    })
}

/// Makes `dir` (and its missing parents) root's, readable by everyone
#[cfg(unix)]
pub fn make_root_only(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    if root_only(dir) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "{} can be changed by users other than root",
            dir.display()
        )))
    }
}

/// Puts links to the programs in `dir` in place of what `links` has by
/// those names (an older install's files)
#[cfg(unix)]
pub fn link(dir: &Path, links: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(links)?;
    for name in NAMES {
        let target = dir.join(name);
        if !target.is_file() {
            continue;
        }
        let at = links.join(name);
        // Removes a link itself, never what it points at
        let _ = std::fs::remove_file(&at);
        std::os::unix::fs::symlink(&target, &at)?;
    }
    Ok(())
}

/// Removes the links to `dir`, and the programs an install before 1.0.2 left
/// in `links`
#[cfg(unix)]
pub fn unlink(dir: &Path, links: &Path) {
    for name in NAMES {
        let at = links.join(name);
        let ours = match std::fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => {
                std::fs::read_link(&at).is_ok_and(|t| t.starts_with(dir))
            }
            // `retail` alone is a name another program could have
            Ok(m) => m.is_file() && name != "retail",
            Err(_) => false,
        };
        if ours {
            let _ = std::fs::remove_file(&at);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn links_replace_old_files() {
        let tmp = std::env::temp_dir().join(format!("retail-links-{}", std::process::id()));
        let (dir, links) = (tmp.join("bin"), tmp.join("links"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&links).unwrap();
        std::fs::write(dir.join("retaild"), "new").unwrap();
        std::fs::write(links.join("retaild"), "old").unwrap();
        link(&dir, &links).unwrap();
        assert_eq!(
            std::fs::read_to_string(links.join("retaild")).unwrap(),
            "new"
        );
        assert!(
            std::fs::symlink_metadata(links.join("retaild"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // No program, no link
        assert!(!links.join("retail-tray").exists());
        unlink(&dir, &links);
        assert!(std::fs::symlink_metadata(links.join("retaild")).is_err());
        assert!(dir.join("retaild").is_file());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn temp_folder_is_not_root_only() {
        // World-writable (and on CI not root's either)
        assert!(!root_only(Path::new("/tmp")));
        assert!(root_only(Path::new("/")));
    }
}
