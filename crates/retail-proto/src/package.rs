//! Client packages: one executable per OS that installs retail and joins a
//! network. The server makes them without compiling anything: it appends the
//! other program files and an invite to a prebuilt tray executable.
//!
//! Layout: `tray executable | file payloads | manifest JSON | u64 LE manifest
//! length | MAGIC`. File offsets in the manifest count from the start.
//!
//! Appending breaks code signatures, which retail does not have yet; signed
//! releases will need the data placed where signatures allow it.

use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 16] = b"RETAIL-PACKAGE-1";
const MAX_MANIFEST: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Invite code the installed device joins with
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
}
