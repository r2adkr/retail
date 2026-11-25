//! Client packages: one executable per OS that installs retail and joins a
//! network. The server makes them without compiling anything: it appends the
//! other program files and an invite to a prebuilt tray executable.
//!
//! Layout: `tray executable | file payloads | manifest JSON | u64 LE manifest
//! length | MAGIC`. File offsets in the manifest count from the start.
//!
//! Appending breaks code signatures, which retail does not have yet; signed
//! releases will need the data placed where signatures allow it.
//!
//! The official installer of each release is a package without an invite
//! (`scripts/bundle.py`); for macOS it is a resource of `retail.app`, in a
//! zip. Daemons update themselves from it, and servers take other systems'
//! programs out of it for their packages.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 16] = b"RETAIL-PACKAGE-1";
const MAX_MANIFEST: u64 = 64 * 1024;

/// The installer's place in the macOS zip: a resource of `retail.app`, whose
/// own program is the plain tray app, so the app can be signed as a whole
pub const APP_PACKAGE: &str = "retail.app/Contents/Resources/retail.package";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Invite code the installed device joins with; empty in the official
    /// installer, which only installs
    pub invite: String,
    /// Shown by the installer
    #[serde(default)]
    pub network: String,
    pub files: Vec<PackedFile>,
    /// Length of the tray executable at the start
    pub base_len: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackedFile {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

/// Bytes appended after the payloads
pub fn trailer(manifest: &Manifest) -> Vec<u8> {
    let json = serde_json::to_vec(manifest).expect("manifest serializes");
    let mut out = json;
    let len = out.len() as u64;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(MAGIC);
    out
}

/// Reads the manifest from the end of `file`, if it is a package. Reads only
/// a bounded tail.
pub fn read_manifest<R: std::io::Read + std::io::Seek>(file: &mut R) -> Option<Manifest> {
    use std::io::SeekFrom;
    let total = file.seek(SeekFrom::End(0)).ok()?;
    let tail_len = (MAGIC.len() + 8) as u64;
    if total < tail_len {
        return None;
    }
    file.seek(SeekFrom::Start(total - tail_len)).ok()?;
    let mut tail = [0u8; 24];
    file.read_exact(&mut tail).ok()?;
    if &tail[8..] != MAGIC {
        return None;
    }
    let len = u64::from_le_bytes(tail[..8].try_into().ok()?);
    if len > MAX_MANIFEST || len + tail_len > total {
        return None;
    }
    file.seek(SeekFrom::Start(total - tail_len - len)).ok()?;
    let mut json = vec![0u8; len as usize];
    file.read_exact(&mut json).ok()?;
    let m: Manifest = serde_json::from_slice(&json).ok()?;
    let end = total - tail_len - len;
    let in_bounds = m.base_len <= end && m.files.iter().all(|f| f.offset.checked_add(f.len).is_some_and(|e| e <= end));
    in_bounds.then_some(m)
}

/// The tray app's name, which the package starts as: `.exe` for Windows packages
pub fn tray_name(m: &Manifest) -> &'static str {
    if m.files.iter().any(|f| f.name.ends_with(".exe")) { "retail-tray.exe" } else { "retail-tray" }
}

/// A package from `start` to `start + len` of a larger file (an installer in
/// a zip), seen as a file of its own
pub struct Window<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R: Seek> Window<R> {
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Window { inner, start, len, pos: 0 }
    }
}

impl<R: Read + Seek> Read for Window<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let got = self.inner.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl<R: Seek> Seek for Window<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = pos.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

/// Where an uncompressed (stored) file's bytes are in a zip: offset and length
pub fn zip_entry<R: Read + Seek>(r: &mut R, name: &str) -> Option<(u64, u64)> {
    let total = r.seek(SeekFrom::End(0)).ok()?;
    // The end record is the last 22 bytes when the zip has no comment
    let tail = total.min(22 + 0xFFFF);
    r.seek(SeekFrom::Start(total - tail)).ok()?;
    let mut buf = vec![0u8; tail as usize];
    r.read_exact(&mut buf).ok()?;
    let end = buf.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    let rec = buf.get(end..end + 22)?;
    let u16_at = |b: &[u8], i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as u64;
    let u32_at = |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as u64;
    let (count, dir_len, dir_at) = (u16_at(rec, 10), u32_at(rec, 12), u32_at(rec, 16));
    if dir_len > 1 << 20 || dir_at + dir_len > total {
        return None;
    }
    r.seek(SeekFrom::Start(dir_at)).ok()?;
    let mut dir = vec![0u8; dir_len as usize];
    r.read_exact(&mut dir).ok()?;
    let mut i = 0usize;
    for _ in 0..count {
        let h = dir.get(i..i + 46)?;
        if &h[..4] != b"PK\x01\x02" {
            return None;
        }
        let (method, size, raw) = (u16_at(h, 10), u32_at(h, 20), u32_at(h, 24));
        let (name_len, extra_len, comment_len) = (u16_at(h, 28) as usize, u16_at(h, 30) as usize, u16_at(h, 32) as usize);
        let local = u32_at(h, 42);
        let this = dir.get(i + 46..i + 46 + name_len)?;
        if this == name.as_bytes() {
            if method != 0 || size != raw {
                return None;
            }
            r.seek(SeekFrom::Start(local)).ok()?;
            let mut lh = [0u8; 30];
            r.read_exact(&mut lh).ok()?;
            if &lh[..4] != b"PK\x03\x04" {
                return None;
            }
            let data = local + 30 + u16_at(&lh, 26) + u16_at(&lh, 28);
            return (data + size <= total).then_some((data, size));
        }
        i += 46 + name_len + extra_len + comment_len;
    }
    None
}

/// Writes the programs of the package in `r` into `dir` under their own
/// names, those `want` picks, each replacing an older one atomically
pub fn extract<R: Read + Seek>(r: &mut R, m: &Manifest, dir: &Path, want: impl Fn(&str) -> bool) -> std::io::Result<Vec<String>> {
    let mut parts: Vec<(String, u64, u64)> = vec![(tray_name(m).to_string(), 0, m.base_len)];
    parts.extend(m.files.iter().map(|f| (f.name.clone(), f.offset, f.len)));
    let mut written = Vec::new();
    for (name, offset, len) in parts {
        if !safe_name(&name) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unexpected file name {name}")));
        }
        if !want(&name) {
            continue;
        }
        r.seek(SeekFrom::Start(offset))?;
        let tmp = dir.join(format!("{name}.part"));
        let mut out = std::fs::File::create(&tmp)?;
        let copied = std::io::copy(&mut r.by_ref().take(len), &mut out)?;
        if copied != len {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("{name} is cut short")));
        }
        drop(out);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp, dir.join(&name))?;
        written.push(name);
    }
    Ok(written)
}

/// File names the installer accepts, so a manifest cannot write elsewhere
pub fn safe_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) && !name.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut bytes = b"MZ-tray-binary".to_vec();
        let base_len = bytes.len() as u64;
        let mut files = Vec::new();
        for (name, data) in [("retaild.exe", &b"daemon"[..]), ("retail.exe", &b"cli"[..])] {
            files.push(PackedFile { name: name.into(), offset: bytes.len() as u64, len: data.len() as u64 });
            bytes.extend_from_slice(data);
        }
        let m = Manifest { invite: "retail1.abc".into(), network: "home".into(), files, base_len };
        bytes.extend_from_slice(&trailer(&m));
        let got = read_manifest(&mut std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(got, m);
        let f = &got.files[0];
        assert_eq!(&bytes[f.offset as usize..(f.offset + f.len) as usize], b"daemon");
        assert!(read_manifest(&mut std::io::Cursor::new(b"plain executable")).is_none());
        // A manifest pointing past its own data is refused
        let bad = Manifest { base_len: 1 << 40, ..m };
        let mut evil = b"x".to_vec();
        evil.extend_from_slice(&trailer(&bad));
        assert!(read_manifest(&mut std::io::Cursor::new(&evil)).is_none());
        assert!(safe_name("wintun.dll") && !safe_name("../evil") && !safe_name("a/b") && !safe_name(".x"));
    }

    /// An official installer inside a stored zip, as macOS gets it: found,
    /// read through a window, and its programs written out
    #[test]
    fn installer_in_a_zip() {
        let mut pkg = b"TRAY".to_vec();
        let files = vec![PackedFile { name: "retaild".into(), offset: 4, len: 6 }, PackedFile { name: "retail".into(), offset: 10, len: 3 }];
        pkg.extend_from_slice(b"daemoncli");
        let m = Manifest { invite: String::new(), network: String::new(), files, base_len: 4 };
        pkg.extend_from_slice(&trailer(&m));
        // A zip with one stored entry before it, as bundle.py writes them
        let mut zip = Vec::new();
        let mut central = Vec::new();
        for (name, data) in [("retail.app/Contents/Info.plist", &b"<plist/>"[..]), (APP_PACKAGE, &pkg[..])] {
            let at = zip.len() as u32;
            let mut local = b"PK\x03\x04".to_vec();
            local.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            zip.extend_from_slice(&local);
            zip.extend_from_slice(data);
            let mut c = b"PK\x01\x02".to_vec();
            c.extend_from_slice(&[20, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            c.extend_from_slice(&(data.len() as u32).to_le_bytes());
            c.extend_from_slice(&(data.len() as u32).to_le_bytes());
            c.extend_from_slice(&(name.len() as u16).to_le_bytes());
            c.extend_from_slice(&[0; 12]);
            c.extend_from_slice(&at.to_le_bytes());
            c.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&c);
        }
        let dir_at = zip.len() as u32;
        zip.extend_from_slice(&central);
        zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x02\0\x02\0");
        zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
        zip.extend_from_slice(&dir_at.to_le_bytes());
        zip.extend_from_slice(&[0, 0]);

        let mut cur = std::io::Cursor::new(&zip);
        let (start, len) = zip_entry(&mut cur, APP_PACKAGE).unwrap();
        assert_eq!(len, pkg.len() as u64);
        let mut w = Window::new(cur, start, len);
        let got = read_manifest(&mut w).unwrap();
        assert_eq!(got, m);
        let dir = std::env::temp_dir().join(format!("retail-extract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let written = extract(&mut w, &got, &dir, |n| n != "retail").unwrap();
        assert_eq!(written, ["retail-tray", "retaild"]);
        assert_eq!(std::fs::read(dir.join("retail-tray")).unwrap(), b"TRAY");
        assert_eq!(std::fs::read(dir.join("retaild")).unwrap(), b"daemon");
        let _ = std::fs::remove_dir_all(dir);
        assert!(zip_entry(&mut std::io::Cursor::new(&zip), "missing").is_none());
    }

    /// A macOS zip made by `scripts/bundle.py --app` (given in
    /// RETAIL_BUNDLE_ZIP, as the release workflow does) holds a readable installer
    #[test]
    fn bundle_py_zip() {
        let Some(path) = std::env::var_os("RETAIL_BUNDLE_ZIP") else { return };
        let mut f = std::fs::File::open(path).unwrap();
        let (start, len) = zip_entry(&mut f, APP_PACKAGE).expect("the installer is in the zip, stored");
        let m = read_manifest(&mut Window::new(f, start, len)).expect("it is a package");
        assert!(m.invite.is_empty() && m.files.iter().any(|f| f.name == "retaild"), "{m:?}");
    }
}
