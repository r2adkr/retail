//! Sending files to other devices, and taking the ones they send (see the
//! daemon's files.rs). Sending connects straight to the other device's mesh
//! address. An offer to this device is asked about with the system's
//! notification (Windows: a toast whose buttons open `retail-file:` links,
//! which start this program with `--file-answer`; Linux: notify-send with
//! actions) or, on macOS, a system dialog; an accepted file goes into the
//! user's Downloads, never over an existing file.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use retail_proto::api::FileOffer;

use crate::i18n::{tr, trf};
use crate::settings::bytes;

/// Offers already put to the user
static ASKED: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

/// Asks about each new offer once, each on its own thread
pub fn on_offers(api: SocketAddr, offers: &[FileOffer]) {
    let mut asked = ASKED.lock().unwrap();
    let asked = asked.get_or_insert_with(HashSet::new);
    // A restarted daemon numbers its offers from 1 again
    asked.retain(|id| offers.iter().any(|o| o.id == *id));
    for offer in offers {
        if asked.insert(offer.id) {
            let offer = offer.clone();
            std::thread::spawn(move || ask(api, offer));
        }
    }
}

fn question(offer: &FileOffer) -> String {
    trf(
        "{from} wants to send you {name} ({size}).",
        &[
            ("from", &offer.from),
            ("name", &offer.name),
            ("size", &bytes(offer.size)),
        ],
    )
}

/// Takes the offer and tells the user how it went
pub fn accept(api: SocketAddr, id: u64, name: &str) {
    match receive(api, id, name) {
        Ok(path) => {
            let shown = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            notify(&trf("Saved {name} in Downloads.", &[("name", &shown)]));
        }
        Err(e) => notify(&trf(
            "Could not save {name}: {error}",
            &[("name", &name), ("error", &e)],
        )),
    }
}

pub fn decline(api: SocketAddr, id: u64) {
    let _ = crate::api::post_blocking(api, &format!("/files/{id}/decline"), "{}");
}

/// Chooses a file and sends it, telling the user how it went
pub fn send_to(ip: Ipv4Addr, device: String) {
    let Some(path) = pick_file(&trf(
        "Choose a file to send to {device}",
        &[("device", &device)],
    )) else {
        return;
    };
    let name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let msg = match send(ip, &path) {
        Ok(true) => trf(
            "{name} was sent to {device}.",
            &[("name", &name), ("device", &device)],
        ),
        Ok(false) => trf(
            "{device} declined {name}.",
            &[("name", &name), ("device", &device)],
        ),
        Err(e) => trf(
            "Could not send {name}: {error}",
            &[("name", &name), ("error", &e)],
        ),
    };
    notify(&msg);
}

/// `Ok(false)` when the other side said no
fn send(ip: Ipv4Addr, path: &Path) -> Result<bool, String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let addr = SocketAddr::from((ip, retail_proto::FILE_PORT));
    let mut conn = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .map_err(|_| tr("the device does not answer (it may need a newer retail)").to_string())?;
    let header = serde_json::json!({ "name": name, "size": size }).to_string();
    conn.write_all(format!("{header}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    // The other side has two minutes to answer
    conn.set_read_timeout(Some(Duration::from_secs(150))).ok();
    let mut reader = BufReader::new(conn.try_clone().map_err(|e| e.to_string())?);
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .map_err(|_| tr("no answer").to_string())?;
    match answer.trim() {
        "ok" => {}
        "busy" => return Err(tr("the device has too many files waiting").into()),
        _ => return Ok(false),
    }
    conn.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let sent = std::io::copy(&mut file, &mut conn).map_err(|e| e.to_string())?;
    if sent != size {
        return Err(tr("the file changed while it was sent").into());
    }
    let _ = conn.shutdown(std::net::Shutdown::Write);
    Ok(true)
}

/// Streams the accepted file from the daemon into Downloads
fn receive(api: SocketAddr, id: u64, name: &str) -> Result<PathBuf, String> {
    let s = crate::api::open_post(api, &format!("/files/{id}/accept"))?;
    s.set_read_timeout(Some(Duration::from_secs(90))).ok();
    let mut reader = BufReader::new(s);
    let mut status = String::new();
    reader.read_line(&mut status).map_err(|e| e.to_string())?;
    let mut length: Option<u64> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("malformed response".into());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            length = v.trim().parse().ok();
        }
    }
    if status.split_whitespace().nth(1) != Some("200") {
        let mut body = Vec::new();
        let _ = reader.take(4096).read_to_end(&mut body);
        let code = status
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        return Err(crate::api::api_error(&body, code));
    }
    let length = length.ok_or("no length")?;
    let dir = downloads();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (part, final_path) = free_names(&dir, name);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)
        .map_err(|e| e.to_string())?;
    let copied = std::io::copy(&mut reader.take(length), &mut out);
    drop(out);
    match copied {
        Ok(n) if n == length => {}
        Ok(_) | Err(_) => {
            let _ = std::fs::remove_file(&part);
            return Err(tr("the sender stopped").into());
        }
    }
    std::fs::rename(&part, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}

/// `name`, or `name (2)`, ... that is not taken, and its `.part` while it arrives
fn free_names(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    for n in 1.. {
        let file = if n == 1 {
            name.to_string()
        } else {
            format!("{stem} ({n}){ext}")
        };
        let path = dir.join(&file);
        let part = dir.join(format!("{file}.part"));
        if !path.exists() && !part.exists() {
            return (part, path);
        }
    }
    unreachable!()
}

fn downloads() -> PathBuf {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .map(PathBuf::from)
        .unwrap_or_default();
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Ok(dirs) = std::fs::read_to_string(home.join(".config/user-dirs.dirs"))
        && let Some(line) = dirs.lines().find(|l| l.starts_with("XDG_DOWNLOAD_DIR="))
    {
        let v = line["XDG_DOWNLOAD_DIR=".len()..]
            .trim_matches('"')
            .replace("$HOME", &home.to_string_lossy());
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    home.join("Downloads")
}

// --- Asking, notifying and choosing, per system ---

#[cfg(windows)]
fn ask(api: SocketAddr, offer: FileOffer) {
    if win::toast_question(&offer).is_err() {
        // No toast (PowerShell missing or blocked): a plain question
        if win::yes_no(&question(&offer)) {
            accept(api, offer.id, &offer.name);
        } else {
            decline(api, offer.id);
        }
    }
}

#[cfg(target_os = "macos")]
fn ask(api: SocketAddr, offer: FileOffer) {
    let script = format!(
        "display dialog \"{}\" with title \"retail\" buttons {{\"{}\", \"{}\"}} default button 2 giving up after 110",
        osa(&question(&offer)),
        osa(tr("Decline")),
        osa(tr("Accept"))
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output();
    let yes = out.is_ok_and(|o| {
        String::from_utf8_lossy(&o.stdout).contains(&format!("button returned:{}", tr("Accept")))
    });
    if yes {
        accept(api, offer.id, &offer.name)
    } else {
        decline(api, offer.id)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn ask(api: SocketAddr, offer: FileOffer) {
    let out = std::process::Command::new("notify-send")
        .args(["-a", "retail", "-t", "110000", "--wait"])
        .args([
            "-A",
            &format!("accept={}", tr("Accept")),
            "-A",
            &format!("decline={}", tr("Decline")),
        ])
        .args(["retail", &question(&offer)])
        .output();
    let answer = match out {
        // Empty: the notification server shows no buttons
        Ok(o) if o.status.success() => match String::from_utf8_lossy(&o.stdout).trim() {
            "" => None,
            answer => Some(answer == "accept"),
        },
        _ => None,
    };
    // An older notify-send without actions: zenity's question instead
    let yes = answer.unwrap_or_else(|| {
        std::process::Command::new("zenity")
            .args([
                "--question",
                "--title=retail",
                &format!("--text={}", question(&offer)),
            ])
            .status()
            .is_ok_and(|s| s.success())
    });
    if yes {
        accept(api, offer.id, &offer.name)
    } else {
        decline(api, offer.id)
    }
}

#[cfg(windows)]
pub fn notify(text: &str) {
    if win::toast(text, None).is_err() {
        win::message(text);
    }
}

#[cfg(target_os = "macos")]
pub fn notify(text: &str) {
    let script = format!(
        "display notification \"{}\" with title \"retail\"",
        osa(text)
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .status();
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn notify(text: &str) {
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "retail", "retail", text])
        .status();
}

#[cfg(target_os = "macos")]
fn osa(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn pick_file(prompt: &str) -> Option<PathBuf> {
    let script = format!(
        "POSIX path of (choose file with prompt \"{}\")",
        osa(prompt)
    );
    let out = std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn pick_file(prompt: &str) -> Option<PathBuf> {
    let tries: [(&str, Vec<String>); 2] = [
        (
            "zenity",
            vec!["--file-selection".into(), format!("--title={prompt}")],
        ),
        (
            "kdialog",
            vec![
                "--getopenfilename".into(),
                ".".into(),
                "--title".into(),
                prompt.into(),
            ],
        ),
    ];
    for (program, args) in tries {
        if let Ok(out) = std::process::Command::new(program).args(&args).output() {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return (out.status.success() && !path.is_empty()).then(|| PathBuf::from(path));
        }
    }
    None
}

#[cfg(windows)]
fn pick_file(prompt: &str) -> Option<PathBuf> {
    win::open_dialog(prompt)
}

/// `retail-tray --file-answer retail-file:accept/ID`, from a toast's button
#[cfg(windows)]
pub fn answer_link(api: SocketAddr, link: &str) {
    let rest = link
        .trim_end_matches('/')
        .strip_prefix("retail-file:")
        .unwrap_or("");
    let (verb, id) = rest.split_once('/').unwrap_or(("", ""));
    let Ok(id) = id.parse::<u64>() else { return };
    match verb {
        "accept" => {
            // The name as the daemon lists it, so nothing in the link is trusted
            let name = crate::api::status_blocking(api)
                .ok()
                .and_then(|s| s.file_offers.into_iter().find(|o| o.id == id))
                .map(|o| o.name);
            match name {
                Some(name) => accept(api, id, &name),
                None => notify(tr("That file is no longer offered.")),
            }
        }
        "decline" => decline(api, id),
        _ => {}
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::process::CommandExt;

    const AUMID: &str = "dev.retail.tray";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set(key: &str, name: Option<&str>, value: &str) {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, REG_SZ, RegSetKeyValueW};
        let data = wide(value);
        let name = name.map(wide);
        // SAFETY: NUL-terminated wide strings
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                wide(key).as_ptr(),
                name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            );
        }
    }

    /// The name and icon toasts show, and the `retail-file:` links their buttons open
    fn register() {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let base = format!("Software\\Classes\\AppUserModelId\\{AUMID}");
        set(&base, Some("DisplayName"), "retail");
        if let (Some(dir), Some(png)) = (std::env::var_os("LOCALAPPDATA"), crate::icon::app_png(64))
        {
            let icon = PathBuf::from(dir).join("retail").join("toast.png");
            if std::fs::create_dir_all(icon.parent().unwrap()).is_ok()
                && std::fs::write(&icon, png).is_ok()
            {
                set(&base, Some("IconUri"), &icon.display().to_string());
            }
        }
        set("Software\\Classes\\retail-file", None, "URL:retail file");
        set("Software\\Classes\\retail-file", Some("URL Protocol"), "");
        let command = format!("\"{}\" --file-answer \"%1\"", exe.display());
        set(
            "Software\\Classes\\retail-file\\shell\\open\\command",
            None,
            &command,
        );
    }

    fn xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    pub fn toast_question(offer: &FileOffer) -> Result<(), ()> {
        let buttons = format!(
            "<actions><action content=\"{}\" activationType=\"protocol\" arguments=\"retail-file:accept/{id}\"/>\
             <action content=\"{}\" activationType=\"protocol\" arguments=\"retail-file:decline/{id}\"/></actions>",
            xml(tr("Accept")),
            xml(tr("Decline")),
            id = offer.id
        );
        toast(&question(offer), Some(&buttons))
    }

    pub fn toast(text: &str, actions: Option<&str>) -> Result<(), ()> {
        register();
        let scenario = if actions.is_some() {
            " scenario=\"reminder\""
        } else {
            ""
        };
        let doc = format!(
            "<toast{scenario}><visual><binding template=\"ToastGeneric\"><text>retail</text><text>{}</text></binding></visual>{}</toast>",
            xml(text),
            actions.unwrap_or("")
        );
        let script = format!(
            "$ErrorActionPreference='Stop'\n\
             $null=[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]\n\
             $null=[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime]\n\
             $x=New-Object Windows.Data.Xml.Dom.XmlDocument\n\
             $x.LoadXml('{}')\n\
             $n=[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{AUMID}')\n\
             if ($n.Setting -ne 'Enabled') {{ exit 1 }}\n\
             $n.Show([Windows.UI.Notifications.ToastNotification]::new($x))\n",
            doc.replace('\'', "''")
        );
        let encoded: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let b64 = base64(&encoded);
        let status = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-EncodedCommand",
                &b64,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        if status.is_ok_and(|s| s.success()) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn base64(data: &[u8]) -> String {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub fn yes_no(text: &str) -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            IDYES, MB_ICONQUESTION, MB_YESNO, MessageBoxW,
        };
        // SAFETY: NUL-terminated wide strings
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide(text).as_ptr(),
                wide("retail").as_ptr(),
                MB_YESNO | MB_ICONQUESTION,
            ) == IDYES
        }
    }

    pub fn message(text: &str) {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
        // SAFETY: NUL-terminated wide strings
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                wide(text).as_ptr(),
                wide("retail").as_ptr(),
                MB_OK | MB_ICONINFORMATION,
            )
        };
    }

    pub fn open_dialog(prompt: &str) -> Option<PathBuf> {
        use windows_sys::Win32::UI::Controls::Dialogs::{
            GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_PATHMUSTEXIST, OPENFILENAMEW,
        };
        let mut buf = vec![0u16; 4096];
        let title = wide(prompt);
        // SAFETY: zero is a valid OPENFILENAMEW to fill in
        let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
        ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
        ofn.lpstrFile = buf.as_mut_ptr();
        ofn.nMaxFile = buf.len() as u32;
        ofn.lpstrTitle = title.as_ptr();
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        // SAFETY: the buffers outlive the call
        if unsafe { GetOpenFileNameW(&mut ofn) } == 0 {
            return None;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_never_overwrite() {
        let dir = std::env::temp_dir().join(format!("retail-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (part, path) = free_names(&dir, "a.txt");
        assert_eq!(path, dir.join("a.txt"));
        assert_eq!(part, dir.join("a.txt.part"));
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(free_names(&dir, "a.txt").1, dir.join("a (2).txt"));
        assert_eq!(free_names(&dir, "noext").1, dir.join("noext"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
