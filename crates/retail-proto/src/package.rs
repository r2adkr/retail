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
//! (`scripts/bundle.py`). Daemons update themselves from it, and servers take
//! other systems' programs out of it for their packages. For macOS it is a
//! disk image holding `retail.app`, whose program is the plain tray app with
//! the package among its resources; the same package also sits in front of
//! the image's data (see `dmg_prefix`), where code can read it without
//! mounting anything. For Linux it is a Debian package whose (uncompressed)
//! data holds the installer at `DEB_INSTALLER` (see `deb_entry`).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 16] = b"RETAIL-PACKAGE-1";
const MAX_MANIFEST: u64 = 64 * 1024;


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

/// A package from `start` to `start + len` of a larger file (the one in
/// front of a disk image), seen as a file of its own
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

/// Where a Linux release's `.deb` keeps the installer, which its install
/// script runs
pub const DEB_INSTALLER: &str = "usr/lib/retail/retail-installer";

/// Where a file's bytes are in a Debian package: offset and length. The
/// package is an `ar` archive whose `data.tar` member must be uncompressed,
/// as `scripts/bundle.py --deb` makes it.
pub fn deb_entry<R: Read + Seek>(r: &mut R, path: &str) -> Option<(u64, u64)> {
    let total = r.seek(SeekFrom::End(0)).ok()?;
    r.seek(SeekFrom::Start(0)).ok()?;
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).ok()?;
    if &magic != b"!<arch>\n" {
        return None;
    }
    let mut at = 8u64;
    while at + 60 <= total {
        r.seek(SeekFrom::Start(at)).ok()?;
        let mut h = [0u8; 60];
        r.read_exact(&mut h).ok()?;
        let name = std::str::from_utf8(&h[..16]).ok()?.trim_end().trim_end_matches('/');
        let size: u64 = std::str::from_utf8(&h[48..58]).ok()?.trim().parse().ok()?;
        let body = at + 60;
        if body.checked_add(size)? > total {
            return None;
        }
        if name == "data.tar" {
            return tar_entry(r, body, size, path);
        }
        at = body + size + size % 2;
    }
    None
}

/// A file in an uncompressed tar from `start` to `start + len`
fn tar_entry<R: Read + Seek>(r: &mut R, start: u64, len: u64, path: &str) -> Option<(u64, u64)> {
    let octal = |b: &[u8]| -> Option<u64> {
        let s = std::str::from_utf8(b).ok()?.trim_matches(|c: char| c == '\0' || c == ' ');
        if s.is_empty() { Some(0) } else { u64::from_str_radix(s, 8).ok() }
    };
    let text = |b: &[u8]| String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or(&[])).into_owned();
    let mut at = start;
    while at + 512 <= start + len {
        r.seek(SeekFrom::Start(at)).ok()?;
        let mut h = [0u8; 512];
        r.read_exact(&mut h).ok()?;
        if h.iter().all(|&b| b == 0) {
            return None;
        }
        let size = octal(&h[124..136])?;
        let mut name = text(&h[..100]);
        let prefix = text(&h[345..500]);
        if &h[257..262] == b"ustar" && !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let data = at + 512;
        if name.trim_start_matches("./") == path && matches!(h[156], b'0' | 0) {
            return (data + size <= start + len).then_some((data, size));
        }
        at = data + size.div_ceil(512) * 512;
    }
    None
}

/// The length of what comes before a disk image's data: the package
/// `scripts/bundle.py --dmg` puts there. A disk image (UDIF) ends in a
/// 512-byte `koly` record that says where its data starts, so data put in
/// front is skipped when the image is opened.
pub fn dmg_prefix<R: Read + Seek>(r: &mut R) -> Option<u64> {
    let total = r.seek(SeekFrom::End(0)).ok()?;
    if total < 512 {
        return None;
    }
    r.seek(SeekFrom::Start(total - 512)).ok()?;
    let mut koly = [0u8; 512];
    r.read_exact(&mut koly).ok()?;
    if &koly[..4] != b"koly" {
        return None;
    }
    let data_at = u64::from_be_bytes(koly[24..32].try_into().ok()?);
    (data_at > 0 && data_at < total).then_some(data_at)
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

    /// A package in front of a disk image, as macOS gets it: found through
    /// the image's own record, read through a window, its programs written out
    #[test]
    fn installer_in_front_of_a_dmg() {
        let mut pkg = b"TRAY".to_vec();
        let files = vec![PackedFile { name: "retaild".into(), offset: 4, len: 6 }, PackedFile { name: "retail".into(), offset: 10, len: 3 }];
        pkg.extend_from_slice(b"daemoncli");
        let m = Manifest { invite: String::new(), network: String::new(), files, base_len: 4 };
        pkg.extend_from_slice(&trailer(&m));
        // Image data, then its record pointing at where the data now starts
        let mut file = pkg.clone();
        file.extend_from_slice(&[0xAB; 1000]);
        let mut koly = [0u8; 512];
        koly[..4].copy_from_slice(b"koly");
        koly[24..32].copy_from_slice(&(pkg.len() as u64).to_be_bytes());
        file.extend_from_slice(&koly);

        let mut cur = std::io::Cursor::new(&file);
        let len = dmg_prefix(&mut cur).unwrap();
        assert_eq!(len, pkg.len() as u64);
        let mut w = Window::new(cur, 0, len);
        let got = read_manifest(&mut w).unwrap();
        assert_eq!(got, m);
        let dir = std::env::temp_dir().join(format!("retail-extract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let written = extract(&mut w, &got, &dir, |n| n != "retail").unwrap();
        assert_eq!(written, ["retail-tray", "retaild"]);
        assert_eq!(std::fs::read(dir.join("retail-tray")).unwrap(), b"TRAY");
        assert_eq!(std::fs::read(dir.join("retaild")).unwrap(), b"daemon");
        let _ = std::fs::remove_dir_all(dir);
        assert!(dmg_prefix(&mut std::io::Cursor::new(&pkg)).is_none(), "not an image");
    }

    /// A Debian package made by `scripts/bundle.py --deb` (given in
    /// RETAIL_BUNDLE_DEB, as the release workflow and the tests do) holds a
    /// readable installer where the install script looks
    #[test]
    fn bundle_py_deb() {
        let Some(path) = std::env::var_os("RETAIL_BUNDLE_DEB") else { return };
        let mut f = std::fs::File::open(path).unwrap();
        let (start, len) = deb_entry(&mut f, DEB_INSTALLER).expect("the installer in the package's data");
        let m = read_manifest(&mut Window::new(f, start, len)).expect("it is a package");
        assert!(m.invite.is_empty() && m.files.iter().any(|f| f.name == "retaild"), "{m:?}");
    }

    /// A disk image made by `scripts/bundle.py --dmg` (given in
    /// RETAIL_BUNDLE_DMG, as the release workflow does) carries a readable installer
    #[test]
    fn bundle_py_dmg() {
        let Some(path) = std::env::var_os("RETAIL_BUNDLE_DMG") else { return };
        let mut f = std::fs::File::open(path).unwrap();
        let len = dmg_prefix(&mut f).expect("an image with a package in front");
        let m = read_manifest(&mut Window::new(f, 0, len)).expect("it is a package");
        assert!(m.invite.is_empty() && m.files.iter().any(|f| f.name == "retaild"), "{m:?}");
    }
}
