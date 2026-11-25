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
    /// The invite this device joined the current server with, kept to join
    /// again should the server have forgotten the device
    #[serde(default)]
    pub invite: Option<String>,
    /// Every server joined, the current one included, to switch between
    #[serde(default)]
    pub saved: Vec<Profile>,
}

/// One server's registration: everything needed to reconnect without an invite.
/// Each server gets its own key, so networks cannot link a device across them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub server: String,
    pub private_key: Option<String>,
    pub token: Option<String>,
    pub node_id: Option<i64>,
    pub ip: Option<Ipv4Addr>,
    pub prefix_len: Option<u8>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub server_pin: Option<String>,
    #[serde(default)]
    pub server_alts: Vec<String>,
    #[serde(default)]
    pub server_reality: Option<retail_proto::invite::RealityInvite>,
    #[serde(default)]
    pub server_fronts: Vec<String>,
    #[serde(default)]
    pub invite: Option<String>,
}

impl Persisted {
    /// The current registration as a profile
    pub fn current(&self) -> Option<Profile> {
        Some(Profile {
            server: self.server.clone()?,
            private_key: self.private_key.clone(),
            token: Some(self.token.clone()?),
            node_id: self.node_id,
            ip: self.ip,
            prefix_len: self.prefix_len,
            hostname: self.hostname.clone(),
            server_pin: self.server_pin.clone(),
            server_alts: self.server_alts.clone(),
            server_reality: self.server_reality.clone(),
            server_fronts: self.server_fronts.clone(),
            invite: self.invite.clone(),
        })
    }

    /// Records the current registration in `saved`, replacing an older one
    /// for the same server
    pub fn remember_current(&mut self) {
        if let Some(cur) = self.current() {
            match self.saved.iter_mut().find(|s| s.server == cur.server) {
                Some(s) => *s = cur,
                None => self.saved.push(cur),
            }
        }
    }

    /// Makes `p` the current registration. Exit-node choices belong to the
    /// network being left, so they go.
    pub fn load_profile(&mut self, p: &Profile) {
        self.server = Some(p.server.clone());
        self.private_key = p.private_key.clone();
        self.token = p.token.clone();
        self.node_id = p.node_id;
        self.ip = p.ip;
        self.prefix_len = p.prefix_len;
        self.hostname = p.hostname.clone();
        self.server_pin = p.server_pin.clone();
        self.server_alts = p.server_alts.clone();
        self.server_reality = p.server_reality.clone();
        self.server_fronts = p.server_fronts.clone();
        self.invite = p.invite.clone();
        self.prefs.exit_node = None;
    }

    /// Leaves no current registration (and no key), keeping settings and
    /// the saved servers
    pub fn clear_current(&mut self) {
        let keep = Persisted { prefs: self.prefs.clone(), saved: std::mem::take(&mut self.saved), ..Default::default() };
        *self = keep;
        self.prefs.exit_node = None;
    }

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
/// A folder under %ProgramData% may have been made by any user before retail
/// first ran, and its maker stays its owner, who can always change who may
/// read it. Administrators become the owner of it and everything in it, and
/// every permission added by hand goes (the caller then sets its own). Only
/// works elevated; a daemon run by a plain user keeps what it has.
#[cfg(windows)]
pub fn take_over(dir: &Path) {
    for args in [&["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"][..], &["/reset", "/T", "/C", "/Q"][..]] {
        let _ = std::process::Command::new("icacls").arg(dir).args(args).output();
    }
}

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
        take_over(dir);
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

    #[test]
    fn profiles_switch_without_losing_keys() {
        let mut p = Persisted::default();
        p.ensure_private_key();
        p.server = Some("https://a.example".into());
        p.token = Some("ta".into());
        p.ip = Some(Ipv4Addr::new(100, 64, 0, 2));
        p.remember_current();
        let key_a = p.private_key.clone();

        // Joining another server: the first is kept, the new one has its own key
        p.clear_current();
        p.ensure_private_key();
        p.server = Some("https://b.example".into());
        p.token = Some("tb".into());
        p.remember_current();
        assert_eq!(p.saved.len(), 2);
        assert_ne!(p.private_key, key_a);

        let a = p.saved.iter().find(|s| s.server == "https://a.example").unwrap().clone();
        p.remember_current();
        p.load_profile(&a);
        assert_eq!((p.token.as_deref(), p.private_key.clone(), p.ip), (Some("ta"), key_a, Some(Ipv4Addr::new(100, 64, 0, 2))));
        // Remembering again replaces rather than duplicates
        p.remember_current();
        assert_eq!(p.saved.len(), 2);
    }
}
