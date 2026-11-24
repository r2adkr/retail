use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::RngCore;
use retail_proto::Key;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Persisted {
    /// WireGuard private key, standard base64
    pub private_key: Option<String>,
    pub server: Option<String>,
    pub token: Option<String>,
    pub node_id: Option<i64>,
    pub ip: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    pub hostname: Option<String>,
    /// Whether the user wants the tunnel up (`retail up` vs `retail down`)
    #[serde(default)]
    pub want_running: bool,
    #[serde(default)]
    pub prefs: retail_proto::api::Prefs,
    /// SPKI SHA-256, base64url, of a server joined by invite
    #[serde(default)]
    pub server_pin: Option<String>,
    #[serde(default)]
    pub server_alts: Vec<String>,
    #[serde(default)]
    pub server_reality: Option<retail_proto::invite::RealityInvite>,
    #[serde(default)]
    pub server_fronts: Vec<String>,
}

impl Persisted {
    pub fn target(&self) -> Option<crate::http::Target> {
        Some(crate::http::Target {
            url: self.server.clone()?,
            pin: self.server_pin.as_deref().and_then(retail_proto::invite::decode_pin),
            alts: self.server_alts.clone(),
            reality: self.server_reality.as_ref().and_then(crate::reality::Params::from_invite),
            fronts: self.server_fronts.clone(),
        })
    }
}

impl Persisted {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            secure_dir(dir);
        }
        let tmp: PathBuf = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(self)?;
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    pub fn ensure_private_key(&mut self) -> StaticSecret {
        if let Some(secret) = self.secret() {
            return secret;
        }
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        self.private_key = Some(STANDARD.encode(bytes));
        StaticSecret::from(bytes)
    }

    pub fn secret(&self) -> Option<StaticSecret> {
        let raw = STANDARD.decode(self.private_key.as_deref()?).ok()?;
        let bytes: [u8; 32] = raw.try_into().ok()?;
        Some(StaticSecret::from(bytes))
    }

    pub fn public_key(&self) -> Option<Key> {
        self.secret().map(|s| Key(PublicKey::from(&s).to_bytes()))
    }
}

/// Restricts a state directory (private key, tokens, the hosted server's
/// database and key) to administrators, or the owner on Unix. `%ProgramData%`
/// is readable by every local user by default, which would let any of them
/// impersonate this device. Applied on every save so existing directories get
/// fixed too.
pub fn secure_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!("restricting {}: {e}", dir.display());
        }
    }
    #[cfg(windows)]
    {
        use std::sync::Mutex;
        // Once per directory and process since icacls is slow
        static DONE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
        let mut done = DONE.lock().unwrap();
        if done.iter().any(|d| d == dir) {
            return;
        }
        // SYSTEM and Administrators by SID, since account names are localized
        let ok = std::process::Command::new("icacls")
            .arg(dir)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T", "/Q"])
            .output()
            .is_ok_and(|o| o.status.success());
        // Also the account this runs as, so a daemon started by an administrator
        // without elevation does not lock itself out
        if let (Ok(domain), Ok(user)) = (std::env::var("USERDOMAIN"), std::env::var("USERNAME"))
            && !user.ends_with('$')
        {
            let _ = std::process::Command::new("icacls")
                .arg(dir)
                .args(["/grant", &format!("{domain}\\{user}:(OI)(CI)F"), "/T", "/Q"])
                .output();
        }
        if ok {
            done.push(dir.to_path_buf());
        } else {
            tracing::warn!("could not restrict access to {}", dir.display());
        }
    }
}

pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("retail")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/retail")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/retail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("retail-state-{}", std::process::id()));
        let path = dir.join("state.json");
        let mut p = Persisted::default();
        let secret = p.ensure_private_key();
        p.server = Some("http://example".into());
        p.ip = Some(Ipv4Addr::new(100, 64, 0, 9));
        p.save(&path).unwrap();

        let loaded = Persisted::load(&path).unwrap();
        assert_eq!(loaded.server, p.server);
        assert_eq!(loaded.ip, p.ip);
        assert_eq!(loaded.public_key(), Some(Key(PublicKey::from(&secret).to_bytes())));

        let mut again = loaded.clone();
        again.ensure_private_key();
        assert_eq!(again.private_key, p.private_key);
        let _ = std::fs::remove_dir_all(dir);
    }
}
