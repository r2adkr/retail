//! Server backups: the hosted server's data directory (devices, invites,
//! access rules, settings, and the TLS and REALITY keys that devices pin) in
//! one passphrase-encrypted file.
//!
//! Whoever holds a backup and its passphrase can pose as the server, so the
//! contents are sealed with AES-256-GCM under a key derived from the
//! passphrase (PBKDF2-HMAC-SHA256).

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

const FORMAT: &str = "retail-server-backup";
const VERSION: u32 = 1;
const ITERATIONS: u32 = 600_000;
pub const MIN_PASSPHRASE: usize = 8;
/// Files bigger than this are not server data
const MAX_FILE: u64 = 16 << 20;

#[derive(Serialize, Deserialize)]
struct Sealed {
    format: String,
    version: u32,
    created_at: i64,
    iterations: u32,
    salt: String,
    nonce: String,
    data: String,
}

/// Relative path (with `/`) to contents
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Files(pub BTreeMap<String, String>);

impl Files {
    pub fn insert(&mut self, path: &str, bytes: &[u8]) {
        self.0.insert(path.to_string(), STANDARD.encode(bytes));
    }

    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        STANDARD.decode(self.0.get(path)?).ok()
    }

    /// Every regular file under `dir`, except those `skip` names
    pub fn read_dir(dir: &Path, skip: &[&str]) -> Result<Files> {
        let mut files = Files::default();
        let mut stack = vec![PathBuf::new()];
        while let Some(rel) = stack.pop() {
            let entries = match std::fs::read_dir(dir.join(&rel)) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && rel.as_os_str().is_empty() => return Ok(files),
                Err(e) => return Err(e).with_context(|| format!("reading {}", dir.join(&rel).display())),
            };
            for entry in entries {
                let entry = entry?;
                let path = rel.join(entry.file_name());
                let name = path.to_string_lossy().replace('\\', "/");
                let kind = entry.file_type()?;
                if skip.contains(&name.as_str()) || name.ends_with(".tmp") {
                    continue;
                }
                if kind.is_dir() {
                    stack.push(path);
                } else if kind.is_file() && entry.metadata()?.len() <= MAX_FILE {
                    let bytes = std::fs::read(dir.join(&path)).with_context(|| format!("reading {name}"))?;
                    files.insert(&name, &bytes);
                }
            }
        }
        Ok(files)
    }

    /// Writes into an empty `dir`. Paths stay inside it.
    pub fn write_dir(&self, dir: &Path) -> Result<()> {
        for name in self.0.keys() {
            let rel = Path::new(name);
            let safe = !name.is_empty()
                && rel.components().all(|c| matches!(c, std::path::Component::Normal(_)));
            if !safe {
                bail!("the backup names an unsafe path: {name}");
            }
            let path = dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = self.get(name).with_context(|| format!("the backup's {name} is damaged"))?;
            write_private(&path, &bytes)?;
        }
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn key(passphrase: &str, salt: &[u8], iterations: u32) -> Result<LessSafeKey> {
    let mut key = [0u8; 32];
    let iterations = NonZeroU32::new(iterations).context("bad backup parameters")?;
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, passphrase.as_bytes(), &mut key);
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| anyhow::anyhow!("key setup failed"))?))
}

pub fn seal(files: &Files, passphrase: &str, created_at: i64) -> Result<String> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        bail!("the passphrase needs at least {MIN_PASSPHRASE} characters");
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut salt).map_err(|_| anyhow::anyhow!("no randomness"))?;
    rng.fill(&mut nonce).map_err(|_| anyhow::anyhow!("no randomness"))?;
    let mut data = serde_json::to_vec(files)?;
    key(passphrase, &salt, ITERATIONS)?
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(FORMAT), &mut data)
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let sealed = Sealed {
        format: FORMAT.into(),
        version: VERSION,
        created_at,
        iterations: ITERATIONS,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        data: STANDARD.encode(data),
    };
    Ok(serde_json::to_string_pretty(&sealed)? + "\n")
}

pub fn open(text: &str, passphrase: &str) -> Result<Files> {
    let sealed: Sealed = serde_json::from_str(text.trim()).ok().filter(|s: &Sealed| s.format == FORMAT).context("this is not a retail server backup")?;
    if sealed.version > VERSION {
        bail!("this backup comes from a newer retail; update this device first");
    }
    if !(1..=10_000_000).contains(&sealed.iterations) {
        bail!("bad backup parameters");
    }
    let salt = STANDARD.decode(&sealed.salt).context("the backup is damaged")?;
    let nonce: [u8; NONCE_LEN] = STANDARD.decode(&sealed.nonce).ok().and_then(|n| n.try_into().ok()).context("the backup is damaged")?;
    let mut data = STANDARD.decode(&sealed.data).context("the backup is damaged")?;
    let plain = key(passphrase, &salt, sealed.iterations)?
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(FORMAT), &mut data)
        .map_err(|_| anyhow::anyhow!("wrong passphrase, or the backup is damaged"))?;
    serde_json::from_slice(plain).context("the backup is damaged")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_passphrase() {
        let mut files = Files::default();
        files.insert("retail.json", b"{}");
        files.insert("tls/key.pem", b"secret");
        assert!(seal(&files, "short", 0).is_err());
        let text = seal(&files, "correct horse", 1).unwrap();
        assert!(!text.contains("secret") && !text.contains("c2VjcmV0"));
        let back = open(&text, "correct horse").unwrap();
        assert_eq!(back.get("tls/key.pem").unwrap(), b"secret");
        assert!(open(&text, "wrong horse!").unwrap_err().to_string().contains("wrong passphrase"));
        assert!(open("{}", "correct horse").is_err());

        let dir = std::env::temp_dir().join(format!("retail-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        back.write_dir(&dir).unwrap();
        assert_eq!(std::fs::read(dir.join("tls/key.pem")).unwrap(), b"secret");
        let again = Files::read_dir(&dir, &[]).unwrap();
        assert_eq!(again.0.len(), 2);
        let mut evil = Files::default();
        evil.insert("../x", b"no");
        assert!(evil.write_dir(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
