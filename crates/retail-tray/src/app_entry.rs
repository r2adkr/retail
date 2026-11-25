//! retail in the system's list of apps, the same way on every system:
//! Windows gets a Start menu entry and an entry in Settings → Installed apps
//! (which removes it), macOS `retail.app` in Applications, Linux an entry in
//! the app menu. Each opens the tray app's popup (`retail-tray --show`): the
//! running one's, or a new tray app's.

use std::path::Path;

/// Puts the entry in place for the programs in `dir`. Done by the installer
/// as administrator/root, for every user of the computer.
pub fn add(dir: &Path, version: &str) -> Result<(), String> {
    imp::add(dir, version)
}

/// Takes it away again (uninstalling)
pub fn remove(dir: &Path) {
    imp::remove(dir)
}

/// An .ico holding one 256-pixel PNG, which Windows reads as it is
#[cfg_attr(not(windows), allow(dead_code))]
fn ico(png: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + png.len());
    out.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserved, type 1 (icon), one image
    out.extend_from_slice(&[0, 0, 0, 0]); // 256×256 (written as 0), no palette, reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // planes
    out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&(png.len() as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes()); // where the image starts
    out.extend_from_slice(png);
    out
}

/// An .icns holding one 256-pixel PNG (`ic08`)
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn icns(png: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + png.len());
    out.extend_from_slice(b"icns");
    out.extend_from_slice(&((16 + png.len()) as u32).to_be_bytes());
    out.extend_from_slice(b"ic08");
    out.extend_from_slice(&((8 + png.len()) as u32).to_be_bytes());
    out.extend_from_slice(png);
    out
}

#[cfg(windows)]
mod imp {
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};

    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\retail";
    const NO_WINDOW: u32 = 0x0800_0000;

    fn shortcut() -> PathBuf {
        let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(data).join(r"Microsoft\Windows\Start Menu\Programs\retail.lnk")
    }

    fn run(program: &str, args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new(crate::install::system_program(program))
            .args(args)
            .creation_flags(NO_WINDOW)
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("{program}: {}", String::from_utf8_lossy(&out.stderr).trim()))
        }
    }

    fn reg(name: &str, kind: &str, value: &str) -> Result<(), String> {
        run("reg", &["add", KEY, "/v", name, "/t", kind, "/d", value, "/f"])
    }

    pub fn add(dir: &Path, version: &str) -> Result<(), String> {
        let tray = dir.join("retail-tray.exe");
        let icon = dir.join("retail.ico");
        if let Some(png) = crate::icon::app_png(256) {
            std::fs::write(&icon, super::ico(&png)).map_err(|e| format!("writing {}: {e}", icon.display()))?;
        }
        // PowerShell's single quotes take everything as it is but a quote
        let q = |p: &Path| p.display().to_string().replace('\'', "''");
        let script = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.Arguments = '--show'; \
             $s.IconLocation = '{},0'; $s.Description = 'retail'; $s.WorkingDirectory = '{}'; $s.Save()",
            q(&shortcut()),
            q(&tray),
            q(&icon),
            q(dir)
        );
        run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])?;

        let size_kb: u64 = std::fs::read_dir(dir)
            .map(|d| d.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum::<u64>() / 1024)
            .unwrap_or(0);
        reg("DisplayName", "REG_SZ", "retail")?;
        reg("DisplayVersion", "REG_SZ", version)?;
        reg("Publisher", "REG_SZ", "retail")?;
        reg("DisplayIcon", "REG_SZ", &icon.display().to_string())?;
        reg("InstallLocation", "REG_SZ", &dir.display().to_string())?;
        reg("UninstallString", "REG_SZ", &format!("\"{}\" --uninstall", tray.display()))?;
        reg("QuietUninstallString", "REG_SZ", &format!("\"{}\" --uninstall --yes", tray.display()))?;
        reg("URLInfoAbout", "REG_SZ", "https://github.com/r2adkr/retail")?;
        reg("EstimatedSize", "REG_DWORD", &size_kb.to_string())?;
        reg("NoModify", "REG_DWORD", "1")?;
        reg("NoRepair", "REG_DWORD", "1")
    }

    pub fn remove(dir: &Path) {
        let _ = std::fs::remove_file(shortcut());
        let _ = run("reg", &["delete", KEY, "/f"]);
        let _ = std::fs::remove_file(dir.join("retail.ico"));
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;

    const APP: &str = "/Applications/retail.app";

    pub fn add(dir: &Path, version: &str) -> Result<(), String> {
        let app = Path::new(APP);
        let err = |e: std::io::Error| format!("writing {APP}: {e}");
        // Made anew each time (an update may change it)
        let _ = std::fs::remove_dir_all(app);
        std::fs::create_dir_all(app.join("Contents/MacOS")).map_err(err)?;
        std::fs::create_dir_all(app.join("Contents/Resources")).map_err(err)?;
        // LSUIElement: no Dock icon, as the menu bar app has none
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>CFBundleExecutable</key><string>retail</string>\n\
             <key>CFBundleIdentifier</key><string>dev.retail.app</string>\n\
             <key>CFBundleName</key><string>retail</string>\n\
             <key>CFBundleDisplayName</key><string>retail</string>\n\
             <key>CFBundlePackageType</key><string>APPL</string>\n\
             <key>CFBundleIconFile</key><string>retail</string>\n\
             <key>CFBundleShortVersionString</key><string>{version}</string>\n\
             <key>CFBundleVersion</key><string>{version}</string>\n\
             <key>LSUIElement</key><true/>\n\
             </dict></plist>\n"
        );
        std::fs::write(app.join("Contents/Info.plist"), plist).map_err(err)?;
        // A script rather than a copy: the programs in `dir` update
        // themselves, and this keeps opening the current one
        let launcher = app.join("Contents/MacOS/retail");
        let tray = dir.join("retail-tray").display().to_string().replace('\'', "'\\''");
        std::fs::write(&launcher, format!("#!/bin/sh\nexec '{tray}' --show\n")).map_err(err)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).map_err(err)?;
        }
        if let Some(png) = crate::icon::app_png(256) {
            std::fs::write(app.join("Contents/Resources/retail.icns"), super::icns(&png)).map_err(err)?;
        }
        // Finder and Launchpad pick up the new app
        let _ = std::process::Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
            .args(["-f", APP])
            .output();
        Ok(())
    }

    pub fn remove(_dir: &Path) {
        let _ = std::fs::remove_dir_all(APP);
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::path::Path;

    /// The .deb brings its own entry; installs without it get this one
    const PACKAGED: &str = "/usr/share/applications/retail.desktop";
    const ENTRY: &str = "/usr/local/share/applications/retail.desktop";
    pub const ICON: &str = "/usr/local/share/icons/hicolor/256x256/apps/retail.png";

    pub fn add(dir: &Path, _version: &str) -> Result<(), String> {
        let err = |p: &str, e: std::io::Error| format!("writing {p}: {e}");
        if let Some(png) = crate::icon::app_png(256) {
            std::fs::create_dir_all(Path::new(ICON).parent().unwrap()).map_err(|e| err(ICON, e))?;
            std::fs::write(ICON, png).map_err(|e| err(ICON, e))?;
        }
        if Path::new(PACKAGED).exists() {
            return Ok(());
        }
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName=retail\nComment=Your devices in one private network\n\
             Exec={} --show\nIcon={ICON}\nCategories=Network;\n",
            dir.join("retail-tray").display()
        );
        std::fs::create_dir_all(Path::new(ENTRY).parent().unwrap()).map_err(|e| err(ENTRY, e))?;
        std::fs::write(ENTRY, entry).map_err(|e| err(ENTRY, e))
    }

    pub fn remove(_dir: &Path) {
        let _ = std::fs::remove_file(ENTRY);
        let _ = std::fs::remove_file(ICON);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn icon_files_hold_the_png() {
        let png = crate::icon::app_png(256).unwrap();
        assert_eq!(&png[1..4], b"PNG");
        let ico = super::ico(&png);
        assert_eq!(&ico[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!(u32::from_le_bytes(ico[18..22].try_into().unwrap()), 22);
        assert_eq!(&ico[22..], &png[..]);
        let icns = super::icns(&png);
        assert_eq!(&icns[..4], b"icns");
        assert_eq!(u32::from_be_bytes(icns[4..8].try_into().unwrap()) as usize, icns.len());
        assert_eq!(&icns[8..12], b"ic08");
    }
}
