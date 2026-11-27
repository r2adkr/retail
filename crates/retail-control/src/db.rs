//! Nodes and auth keys in one JSON file, rewritten atomically on every change
//! that matters across restarts.
//!
//! The data is small and the hosting daemon is its only writer, so a database
//! engine would only add code and memory. Endpoints and last-seen times change
//! often and stay in memory. Nodes report endpoints again whenever they connect.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use retail_proto::api::{RegisterRequest, RegisterResponse};
use retail_proto::route::Ipv4Net;
use retail_proto::{Key, MESH_NETWORK, MESH_PREFIX_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AUTH_KEY_PREFIX: &str = "rtl-auth-";

#[derive(Clone)]
pub struct Db {
    inner: Arc<Mutex<Store>>,
}

struct Store {
    path: PathBuf,
    data: Data,
    /// When this server started: devices count as seen then at the latest,
    /// so downtime or an old backup never makes them all look inactive
    started_at: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct Data {
    #[serde(default)]
    next_id: i64,
    #[serde(default)]
    nodes: Vec<NodeRec>,
    #[serde(default)]
    keys: Vec<KeyRec>,
    /// `None`: every device reaches every other
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acl: Option<retail_proto::acl::AclPolicy>,
    /// The member device that is this server's helper node
    #[serde(default, skip_serializing_if = "Option::is_none")]
    helper_device: Option<i64>,
    /// Device keys expire this many days after joining or renewal
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_expiry_days: Option<u32>,
    /// Devices not seen for this many days are removed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remove_inactive_days: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
struct NodeRec {
    id: i64,
    node_key: Key,
    token_hash: String,
    hostname: String,
    os: String,
    ip: Ipv4Addr,
    created_at: i64,
    #[serde(skip)]
    endpoints: Vec<SocketAddr>,
    #[serde(default)]
    last_seen: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    /// MagicDNS label, unique, kept once given so a later rename cannot take
    /// another device's name
    #[serde(default)]
    label: String,
    /// When the key expires, `None` for never
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    /// Exempt from key expiry (the hosting device, or by the administrator)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    no_expiry: bool,
    /// Exempt while it is the helper device; ends with that role
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    helper_exempt: bool,
    /// The invite it joined with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite_id: Option<i64>,
    /// Networks the administrator lets it route
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    routes: Vec<Ipv4Net>,
    /// Its local networks as last reported, for waking it
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lan: Vec<retail_proto::api::LanPort>,
}

impl NodeRec {
    /// Exempt from key expiry and inactivity removal
    fn exempt(&self) -> bool {
        self.no_expiry || self.helper_exempt
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyRec {
    id: i64,
    key_hash: String,
    reusable: bool,
    used: bool,
    expires_at: i64,
    created_at: i64,
    /// Named invites are reusable, at most one live code per name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Kept in the clear for named invites only, so client downloads can
    /// embed the code later. The data directory is admin-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(default)]
    uses: u64,
    /// The hosting device's own invite: who joins with it never expires
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    host: bool,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub node_key: Key,
    pub hostname: String,
    pub os: String,
    pub ip: Ipv4Addr,
    pub endpoints: Vec<SocketAddr>,
    pub last_seen: Option<i64>,
    pub tags: Vec<String>,
    /// `<label>.retail.internal`
    pub dns_name: String,
    pub expires_at: Option<i64>,
    /// The invite it joined with, while that invite exists
    pub invite_id: Option<i64>,
    pub approved_routes: Vec<Ipv4Net>,
    pub lan: Vec<retail_proto::api::LanPort>,
}

impl NodeRow {
    pub fn expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PreauthRow {
    pub id: i64,
    pub reusable: bool,
    pub used: bool,
    pub expires_at: i64,
    pub created_at: i64,
    pub name: Option<String>,
    pub uses: u64,
}

/// Expiry of invites that never expire
pub const NEVER: i64 = i64::MAX;

#[derive(Debug)]
pub enum RegisterError {
    InvalidAuthKey,
    /// The key belongs to a node and the request lacks its token
    KeyInUse,
    AddressSpaceExhausted,
    Internal(anyhow::Error),
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Tokens and auth keys are 256-bit random values, so a fast unsalted hash is sufficient
/// Seconds in a "day" of the expiry settings. `RETAIL_DAY_SECONDS` shortens
/// it for tests.
pub fn day_secs() -> i64 {
    static DAY: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *DAY.get_or_init(|| std::env::var("RETAIL_DAY_SECONDS").ok().and_then(|v| v.parse().ok()).filter(|v| *v > 0).unwrap_or(86_400))
}

fn expiry(days: Option<u32>, exempt: bool, now: i64) -> Option<i64> {
    days.filter(|_| !exempt).map(|d| now.saturating_add(i64::from(d) * day_secs()))
}

/// Checks a database file, for restoring a backup
pub fn check(bytes: &[u8]) -> Result<()> {
    serde_json::from_slice::<Data>(bytes).context("the server data in the backup is damaged")?;
    Ok(())
}

fn hash_secret(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_secret() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn ip_range() -> (u32, u32) {
    let base = u32::from(MESH_NETWORK);
    let size = 1u32 << (32 - MESH_PREFIX_LEN);
    (base + 1, base + size - 2)
}

impl Store {
    fn next_id(&mut self) -> i64 {
        self.data.next_id += 1;
        self.data.next_id
    }

    /// Owner-only on Unix. On Windows the daemon restricts the directory instead.
    fn save(&self) -> Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.data)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path).with_context(|| format!("replacing {}", self.path.display()))?;
        Ok(())
    }
}

impl Db {
    pub async fn open(path: &Path) -> Result<Self> {
        let data = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut data: Data = data;
        // Labels for nodes from before they were stored, oldest first
        data.nodes.sort_by_key(|n| n.id);
        for i in 0..data.nodes.len() {
            if data.nodes[i].label.is_empty() {
                let base = data.nodes[i].hostname.clone();
                data.nodes[i].label = unique_label(&data.nodes, &base, data.nodes[i].id);
            }
        }
        data.next_id = data.next_id.max(data.nodes.iter().map(|n| n.id).chain(data.keys.iter().map(|k| k.id)).max().unwrap_or(0));
        Ok(Db { inner: Arc::new(Mutex::new(Store { path: path.to_path_buf(), data, started_at: now_unix() })) })
    }

    /// Only the hash of the returned key is stored
    pub async fn create_preauth(&self, reusable: bool, ttl: Duration) -> Result<String> {
        self.create_key(reusable, ttl, false)
    }

    /// For the hosting device itself, which never expires
    pub async fn create_host_key(&self, ttl: Duration) -> Result<String> {
        self.create_key(false, ttl, true)
    }

    fn create_key(&self, reusable: bool, ttl: Duration, host: bool) -> Result<String> {
        let key = format!("{AUTH_KEY_PREFIX}{}", random_secret());
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        // Prune expired keys, except used single-use ones within a week of expiry
        s.data.keys.retain(|k| k.expires_at > now || (k.used && !k.reusable && k.expires_at > now - 7 * 86400));
        let id = s.next_id();
        s.data.keys.push(KeyRec {
            id,
            key_hash: hash_secret(&key),
            reusable,
            used: false,
            expires_at: now + ttl.as_secs() as i64,
            created_at: now,
            name: None,
            secret: None,
            uses: 0,
            host,
        });
        s.save()?;
        Ok(key)
    }

    /// Creates the named invite, or gives it a new code, which voids the old
    /// one in the same write. Devices that already joined are unaffected.
    pub async fn set_named(&self, name: &str, ttl: Option<Duration>) -> Result<(i64, String)> {
        let key = format!("{AUTH_KEY_PREFIX}{}", random_secret());
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        s.data.keys.retain(|k| k.name.as_deref() != Some(name));
        let id = s.next_id();
        s.data.keys.push(KeyRec {
            id,
            key_hash: hash_secret(&key),
            reusable: true,
            used: false,
            expires_at: ttl.map_or(NEVER, |t| now.saturating_add(t.as_secs() as i64)),
            created_at: now,
            name: Some(name.to_string()),
            secret: Some(key.clone()),
            uses: 0,
            host: false,
        });
        s.save()?;
        Ok((id, key))
    }

    /// The live code of a named invite
    pub async fn named_secret(&self, id: i64) -> Result<Option<String>> {
        let now = now_unix();
        let s = self.inner.lock().unwrap();
        Ok(s.data.keys.iter().find(|k| k.id == id && k.expires_at > now).and_then(|k| k.secret.clone()))
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, RegisterError> {
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        let key_hash = hash_secret(req.auth_key.trim());
        if !s.data.keys.iter().any(|k| k.key_hash == key_hash && k.expires_at > now && (k.reusable || !k.used)) {
            return Err(RegisterError::InvalidAuthKey);
        }
        // A key everyone can read in their netmap is no proof: re-registering
        // a node needs its current token too, checked before the invite counts
        if let Some(n) = s.data.nodes.iter().find(|n| n.node_key == req.node_key)
            && req.token.as_deref().map(hash_secret).as_deref() != Some(n.token_hash.as_str())
        {
            return Err(RegisterError::KeyInUse);
        }
        let key = s
            .data
            .keys
            .iter_mut()
            .find(|k| k.key_hash == key_hash)
            .ok_or(RegisterError::InvalidAuthKey)?;
        key.used = true;
        key.uses += 1;
        let (key_id, host_key) = (key.id, key.host);
        let policy = s.data.key_expiry_days;

        let token = random_secret();
        let token_hash = hash_secret(&token);
        let hostname = sanitize_hostname(&req.hostname);
        let os = sanitize_os(&req.os);
        let existing = s.data.nodes.iter().position(|n| n.node_key == req.node_key);
        let (node_id, ip) = match existing {
            Some(i) => {
                let id = s.data.nodes[i].id;
                // A new name gets a free label; it never takes one in use
                let label = if s.data.nodes[i].hostname == hostname { s.data.nodes[i].label.clone() } else { unique_label(&s.data.nodes, &hostname, id) };
                let n = &mut s.data.nodes[i];
                n.token_hash = token_hash;
                n.hostname = hostname;
                n.os = os;
                n.label = label;
                n.no_expiry |= host_key;
                // Joining again with an invite renews the key
                n.expires_at = expiry(policy, n.exempt(), now);
                n.invite_id = Some(key_id);
                (n.id, n.ip)
            }
            None => {
                let ip = allocate_ip(&s.data.nodes)?;
                let id = s.next_id();
                let label = unique_label(&s.data.nodes, &hostname, id);
                s.data.nodes.push(NodeRec {
                    id,
                    node_key: req.node_key,
                    token_hash,
                    hostname,
                    label,
                    os,
                    ip,
                    created_at: now,
                    endpoints: Vec::new(),
                    last_seen: None,
                    tags: Vec::new(),
                    expires_at: expiry(policy, host_key, now),
                    no_expiry: host_key,
                    helper_exempt: false,
                    invite_id: Some(key_id),
                    routes: Vec::new(),
                    lan: Vec::new(),
                });
                (id, ip)
            }
        };
        s.save().map_err(RegisterError::Internal)?;
        Ok(RegisterResponse { node_id, ip, prefix_len: MESH_PREFIX_LEN, token })
    }

    pub async fn list_preauth(&self) -> Result<Vec<PreauthRow>> {
        let s = self.inner.lock().unwrap();
        let mut rows: Vec<PreauthRow> = s
            .data
            .keys
            .iter()
            .map(|k| PreauthRow {
                id: k.id,
                reusable: k.reusable,
                used: k.used,
                expires_at: k.expires_at,
                created_at: k.created_at,
                name: k.name.clone(),
                uses: k.uses,
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.id));
        Ok(rows)
    }

    pub async fn delete_preauth(&self, id: i64) -> Result<bool> {
        let mut s = self.inner.lock().unwrap();
        let before = s.data.keys.len();
        s.data.keys.retain(|k| k.id != id);
        let deleted = s.data.keys.len() != before;
        if deleted {
            s.save()?;
        }
        Ok(deleted)
    }

    pub async fn node_id_by_token(&self, token: &str) -> Result<Option<i64>> {
        let hash = hash_secret(token);
        let s = self.inner.lock().unwrap();
        Ok(s.data.nodes.iter().find(|n| n.token_hash == hash).map(|n| n.id))
    }

    pub async fn all_nodes(&self) -> Result<Vec<NodeRow>> {
        let s = self.inner.lock().unwrap();
        let mut rows: Vec<NodeRow> = s
            .data
            .nodes
            .iter()
            .map(|n| NodeRow {
                id: n.id,
                node_key: n.node_key,
                hostname: n.hostname.clone(),
                os: n.os.clone(),
                ip: n.ip,
                endpoints: n.endpoints.clone(),
                last_seen: n.last_seen,
                tags: n.tags.clone(),
                dns_name: format!("{}.{}", n.label, retail_proto::MAGIC_DNS_DOMAIN),
                expires_at: n.expires_at,
                invite_id: n.invite_id.filter(|id| s.data.keys.iter().any(|k| k.id == *id)),
                approved_routes: n.routes.clone(),
                lan: n.lan.clone(),
            })
            .collect();
        rows.sort_by_key(|r| r.id);
        Ok(rows)
    }

    /// Returns whether the stored endpoints changed
    pub async fn set_endpoints(&self, id: i64, endpoints: &[SocketAddr]) -> Result<bool> {
        let mut s = self.inner.lock().unwrap();
        let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) else { return Ok(false) };
        n.last_seen = Some(now_unix());
        if n.endpoints == endpoints {
            return Ok(false);
        }
        n.endpoints = endpoints.to_vec();
        Ok(true)
    }

    pub async fn touch(&self, id: i64) -> Result<()> {
        let mut s = self.inner.lock().unwrap();
        if let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) {
            n.last_seen = Some(now_unix());
        }
        Ok(())
    }

    /// The whole database as saved, last-seen times included
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(&self.inner.lock().unwrap().data)?)
    }

    /// Saves last-seen times now and then, so a crash loses little
    pub fn save(&self) -> Result<()> {
        self.inner.lock().unwrap().save()
    }

    pub fn expiry_settings(&self) -> (Option<u32>, Option<u32>) {
        let s = self.inner.lock().unwrap();
        (s.data.key_expiry_days, s.data.remove_inactive_days)
    }

    /// A new key lifetime starts now for every device it applies to, so
    /// turning it on never cuts off devices that joined long ago
    pub fn set_expiry_settings(&self, key_days: Option<u32>, inactive_days: Option<u32>) -> Result<()> {
        let check = |d: Option<u32>| d.is_none_or(|d| (1..=3650).contains(&d));
        if !check(key_days) || !check(inactive_days) {
            anyhow::bail!("days are 1 to 3650");
        }
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        if s.data.key_expiry_days != key_days {
            s.data.key_expiry_days = key_days;
            // Keys that expired stay expired until renewed: a new setting
            // must not bring back a device that was cut off
            for n in s.data.nodes.iter_mut().filter(|n| n.expires_at.is_none_or(|t| t > now)) {
                n.expires_at = expiry(key_days, n.exempt(), now);
            }
        }
        s.data.remove_inactive_days = inactive_days;
        s.save()
    }

    /// A new key lifetime from now, or none at all with `never`. `false` if
    /// there is no such device.
    pub fn renew(&self, id: i64, never: bool) -> Result<bool> {
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        let policy = s.data.key_expiry_days;
        let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) else { return Ok(false) };
        n.no_expiry = never;
        n.expires_at = expiry(policy, n.exempt(), now);
        s.save()?;
        Ok(true)
    }

    /// Exempts a device from key expiry, changing nothing else
    /// Only while id still names the device with key: an id kept from an
    /// earlier database may belong to someone else now
    pub fn keep_forever(&self, id: i64, key: &Key) -> Result<()> {
        let mut s = self.inner.lock().unwrap();
        if let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id && n.node_key == *key)
            && !n.no_expiry
        {
            n.no_expiry = true;
            n.expires_at = None;
            s.save()?;
        }
        Ok(())
    }

    /// The networks a device may route. `false` if there is no such device.
    /// Returns whether it changed
    pub fn set_lan(&self, id: i64, lan: &[retail_proto::api::LanPort]) -> Result<bool> {
        let mut lan: Vec<_> = lan.iter().copied().filter(retail_proto::api::LanPort::valid).take(retail_proto::api::LanPort::MAX).collect();
        lan.sort_by_key(|p| (p.addr, p.mac));
        let mut s = self.inner.lock().unwrap();
        let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) else { return Ok(false) };
        if n.lan == lan {
            return Ok(false);
        }
        n.lan = lan;
        s.save()?;
        Ok(true)
    }

    pub fn set_routes(&self, id: i64, routes: &[Ipv4Net]) -> Result<bool> {
        for r in routes {
            r.check_route().map_err(anyhow::Error::msg)?;
        }
        if routes.len() > retail_proto::route::MAX_ROUTES {
            anyhow::bail!("at most {} networks", retail_proto::route::MAX_ROUTES);
        }
        let mut routes = routes.to_vec();
        routes.sort();
        routes.dedup();
        let mut s = self.inner.lock().unwrap();
        let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) else { return Ok(false) };
        n.routes = routes;
        s.save()?;
        Ok(true)
    }

    /// Removes devices not seen within the configured time, except those
    /// online now, never seen and exempt from expiry (the hosting device).
    /// Returns the ids removed.
    pub fn remove_inactive(&self, online: &dyn Fn(i64) -> bool) -> Result<Vec<i64>> {
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        let Some(days) = s.data.remove_inactive_days else { return Ok(Vec::new()) };
        let cutoff = now - i64::from(days) * day_secs();
        let started = s.started_at;
        let stale: Vec<i64> = s
            .data
            .nodes
            .iter()
            .filter(|n| !n.exempt() && !online(n.id) && n.last_seen.is_some_and(|t| t.max(started) < cutoff))
            .map(|n| n.id)
            .collect();
        if !stale.is_empty() {
            s.data.nodes.retain(|n| !stale.contains(&n.id));
            if s.data.helper_device.is_some_and(|h| stale.contains(&h)) {
                s.data.helper_device = None;
            }
            s.save()?;
        }
        Ok(stale)
    }

    /// Persists last-seen times, which are not saved as they change
    pub async fn close(&self) {
        let s = self.inner.lock().unwrap();
        if let Err(e) = s.save() {
            tracing::warn!("saving the server state: {e:#}");
        }
    }

    pub fn acl(&self) -> Option<retail_proto::acl::AclPolicy> {
        self.inner.lock().unwrap().data.acl.clone()
    }

    pub fn set_acl(&self, acl: Option<retail_proto::acl::AclPolicy>) -> Result<()> {
        if let Some(a) = &acl {
            a.check().map_err(anyhow::Error::msg)?;
        }
        let mut s = self.inner.lock().unwrap();
        s.data.acl = acl;
        s.save()
    }

    /// `false` if there is no such device
    pub fn set_tags(&self, id: i64, tags: &[String]) -> Result<bool> {
        let mut tags: Vec<String> = tags.iter().map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect();
        for t in &tags {
            retail_proto::acl::check_tag(t).map_err(anyhow::Error::msg)?;
        }
        tags.sort();
        tags.dedup();
        let mut s = self.inner.lock().unwrap();
        let Some(n) = s.data.nodes.iter_mut().find(|n| n.id == id) else { return Ok(false) };
        n.tags = tags;
        s.save()?;
        Ok(true)
    }

    pub fn helper_device(&self) -> Option<i64> {
        self.inner.lock().unwrap().data.helper_device
    }

    /// The helper device never expires: losing it would cut off the server.
    /// The exemption ends with the role, when the previous helper gets a new
    /// key lifetime from now (unless it is exempt for another reason).
    pub fn set_helper_device(&self, id: Option<i64>) -> Result<()> {
        let now = now_unix();
        let mut s = self.inner.lock().unwrap();
        if let Some(id) = id
            && !s.data.nodes.iter().any(|n| n.id == id)
        {
            anyhow::bail!("there is no device {id}");
        }
        let policy = s.data.key_expiry_days;
        for n in s.data.nodes.iter_mut() {
            let helper = Some(n.id) == id;
            if n.helper_exempt && !helper {
                n.helper_exempt = false;
                n.expires_at = expiry(policy, n.exempt(), now);
            } else if helper {
                n.helper_exempt = true;
                n.expires_at = None;
            }
        }
        s.data.helper_device = id;
        s.save()
    }

    /// With `revoke_invite`, the invite it joined with goes too
    pub async fn delete_node(&self, id: i64, revoke_invite: bool) -> Result<bool> {
        let mut s = self.inner.lock().unwrap();
        let invite = s.data.nodes.iter().find(|n| n.id == id).and_then(|n| n.invite_id);
        if revoke_invite && let Some(k) = invite {
            s.data.keys.retain(|x| x.id != k);
        }
        let before = s.data.nodes.len();
        s.data.nodes.retain(|n| n.id != id);
        let deleted = s.data.nodes.len() != before;
        if s.data.helper_device == Some(id) {
            s.data.helper_device = None;
        }
        if deleted {
            s.save()?;
        }
        Ok(deleted)
    }
}

fn allocate_ip(nodes: &[NodeRec]) -> Result<Ipv4Addr, RegisterError> {
    let (first, last) = ip_range();
    let mut used: Vec<u32> = nodes.iter().map(|n| u32::from(n.ip)).collect();
    used.sort_unstable();
    // The MagicDNS address is never a device's
    used.push(u32::from(retail_proto::MAGIC_DNS_IP));
    used.sort_unstable();
    let mut candidate = first;
    for ip in used {
        if ip > candidate {
            break;
        }
        if ip == candidate {
            candidate += 1;
        }
    }
    if candidate > last {
        return Err(RegisterError::AddressSpaceExhausted);
    }
    Ok(Ipv4Addr::from(candidate))
}

/// `base`, or `base-2`, `base-3`, … if another node has it
fn unique_label(nodes: &[NodeRec], base: &str, id: i64) -> String {
    let base = if base.is_empty() { "node" } else { base };
    let taken = |l: &str| nodes.iter().any(|n| n.id != id && n.label == l);
    let mut label = base.to_string();
    let mut i = 2;
    while taken(&label) {
        label = format!("{base}-{i}");
        i += 1;
    }
    label
}

/// Shown to every member, so short and plain
fn sanitize_os(os: &str) -> String {
    let s: String = os.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(16).collect();
    if s.is_empty() { "unknown".into() } else { s }
}

fn sanitize_hostname(name: &str) -> String {
    let s: String = name
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .take(63)
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "node".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("retail-test-{}.json", random_secret()));
        (Db::open(&path).await.unwrap(), path)
    }

    fn req(auth_key: &str, key_byte: u8) -> RegisterRequest {
        RegisterRequest {
            auth_key: auth_key.into(),
            node_key: Key([key_byte; 32]),
            hostname: "My Laptop".into(),
            os: "linux".into(),
            token: None,
        }
    }

    #[tokio::test]
    async fn names_are_unique_and_kept() {
        let (db, path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();
        let host = |name: &str, byte: u8| RegisterRequest { hostname: name.into(), ..req(&key, byte) };
        let a = db.register(&host("nas", 1)).await.unwrap();
        db.register(&host("nas", 2)).await.unwrap();
        let c = db.register(&host("laptop", 3)).await.unwrap();
        let names = |db: &Db| {
            let db = db.clone();
            async move { db.all_nodes().await.unwrap().into_iter().map(|n| n.dns_name).collect::<Vec<_>>() }
        };
        assert_eq!(names(&db).await, ["nas.retail.internal", "nas-2.retail.internal", "laptop.retail.internal"]);
        // Renaming to a name in use gets a free one instead of taking it
        db.register(&RegisterRequest { token: Some(c.token.clone()), ..host("nas", 3) }).await.unwrap();
        assert_eq!(names(&db).await[2], "nas-3.retail.internal");
        // a keeps its name when it registers again with the same hostname
        db.register(&RegisterRequest { token: Some(a.token.clone()), ..host("nas", 1) }).await.unwrap();
        assert_eq!(names(&Db::open(&path).await.unwrap()).await[0], "nas.retail.internal");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn register_allocates_and_reuses_ips() {
        let (db, path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();

        let a = db.register(&req(&key, 1)).await.unwrap();
        let b = db.register(&req(&key, 2)).await.unwrap();
        assert_eq!(a.ip, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(b.ip, Ipv4Addr::new(100, 64, 0, 2));

        // Someone else with an invite and a's public key cannot take a over
        assert!(matches!(db.register(&req(&key, 1)).await, Err(RegisterError::KeyInUse)));
        let wrong = RegisterRequest { token: Some("rtl-guess".into()), ..req(&key, 1) };
        assert!(matches!(db.register(&wrong).await, Err(RegisterError::KeyInUse)));
        assert_eq!(db.node_id_by_token(&a.token).await.unwrap(), Some(a.node_id));
        // a itself can, with its token
        let a2 = db.register(&RegisterRequest { token: Some(a.token.clone()), ..req(&key, 1) }).await.unwrap();
        assert_eq!((a2.node_id, a2.ip), (a.node_id, a.ip));
        assert_ne!(a2.token, a.token);
        assert_eq!(db.node_id_by_token(&a.token).await.unwrap(), None);
        assert_eq!(db.node_id_by_token(&a2.token).await.unwrap(), Some(a.node_id));

        assert!(db.delete_node(a.node_id, false).await.unwrap());
        let c = db.register(&req(&key, 3)).await.unwrap();
        assert_eq!(c.ip, Ipv4Addr::new(100, 64, 0, 1));

        let nodes = db.all_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].hostname, "my-laptop");

        // Everything but endpoints survives a restart
        let reopened = Db::open(&path).await.unwrap();
        assert_eq!(reopened.all_nodes().await.unwrap().len(), 2);
        assert_eq!(reopened.node_id_by_token(&a2.token).await.unwrap(), None, "a was deleted");
        let d = reopened.register(&req(&key, 4)).await.unwrap();
        assert!(d.node_id > c.node_id, "ids are never reused");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn single_use_and_expired_keys() {
        let (db, path) = temp_db().await;
        let once = db.create_preauth(false, Duration::from_secs(60)).await.unwrap();
        assert!(db.register(&req(&once, 1)).await.is_ok());
        assert!(matches!(db.register(&req(&once, 2)).await, Err(RegisterError::InvalidAuthKey)));

        let expired = db.create_preauth(true, Duration::from_secs(0)).await.unwrap();
        assert!(matches!(db.register(&req(&expired, 3)).await, Err(RegisterError::InvalidAuthKey)));
        assert!(matches!(db.register(&req("rtl-auth-bogus", 4)).await, Err(RegisterError::InvalidAuthKey)));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_registrations_and_writes() {
        let (db, path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();
        let first = db.register(&req(&key, 200)).await.unwrap();

        let writer = {
            let db = db.clone();
            tokio::spawn(async move {
                let ep: SocketAddr = "1.2.3.4:5".parse().unwrap();
                for _ in 0..200 {
                    db.set_endpoints(first.node_id, &[ep]).await.unwrap();
                }
            })
        };
        let mut regs = Vec::new();
        for i in 0..32u8 {
            let db = db.clone();
            let key = key.clone();
            regs.push(tokio::spawn(async move { db.register(&req(&key, i)).await }));
        }
        let mut ips = std::collections::HashSet::new();
        for r in regs {
            let resp = r.await.unwrap().expect("registration must not fail under contention");
            assert!(ips.insert(resp.ip), "duplicate IP {}", resp.ip);
        }
        writer.await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn named_invites_regenerate_and_keep_devices() {
        let (db, _dir) = temp_db().await;
        let (id1, old) = db.set_named("family", None).await.unwrap();
        assert!(db.register(&req(&old, 1)).await.is_ok());
        assert!(db.register(&req(&old, 2)).await.is_ok(), "reusable");
        let (id2, new) = db.set_named("family", Some(Duration::from_secs(3600))).await.unwrap();
        assert!(matches!(db.register(&req(&old, 3)).await, Err(RegisterError::InvalidAuthKey)), "old code void");
        assert!(db.register(&req(&new, 3)).await.is_ok());
        assert_eq!(db.all_nodes().await.unwrap().len(), 3, "joined devices stay");
        assert_eq!(db.named_secret(id1).await.unwrap(), None);
        assert_eq!(db.named_secret(id2).await.unwrap(), Some(new.clone()));
        let (_, work) = db.set_named("work", None).await.unwrap();
        assert!(db.register(&req(&work, 4)).await.is_ok(), "several names coexist");
        assert!(db.register(&req(&new, 5)).await.is_ok());
        assert!(db.delete_preauth(id2).await.unwrap());
        assert!(matches!(db.register(&req(&new, 6)).await, Err(RegisterError::InvalidAuthKey)), "revoked");
        let rows = db.list_preauth().await.unwrap();
        assert!(rows.iter().any(|r| r.name.as_deref() == Some("work") && r.uses == 1 && r.expires_at == NEVER));
    }

    #[tokio::test]
    async fn keeping_forever_needs_the_same_device() {
        let (db, _path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();
        db.set_expiry_settings(Some(30), None).unwrap();
        let a = db.register(&req(&key, 2)).await.unwrap();
        let exp = |id| db.inner.lock().unwrap().data.nodes.iter().find(|n| n.id == id).unwrap().expires_at;
        let theirs = db.inner.lock().unwrap().data.nodes[0].node_key;
        db.keep_forever(a.node_id, &Key([0xee; 32])).unwrap();
        assert!(exp(a.node_id).is_some(), "an id from another database names someone else");
        db.keep_forever(a.node_id, &theirs).unwrap();
        assert_eq!(exp(a.node_id), None);
    }

    #[tokio::test]
    async fn helper_exemption_ends_with_the_role() {
        let (db, path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();
        let a = db.register(&req(&key, 2)).await.unwrap();
        let b = db.register(&req(&key, 3)).await.unwrap();
        db.set_expiry_settings(Some(30), Some(1)).unwrap();
        let exp = |id| db.inner.lock().unwrap().data.nodes.iter().find(|n| n.id == id).unwrap().expires_at;
        db.set_helper_device(Some(a.node_id)).unwrap();
        assert_eq!(exp(a.node_id), None, "the helper never expires");
        db.renew(a.node_id, false).unwrap();
        assert_eq!(exp(a.node_id), None, "not even when renewed with the network's time");
        // Moving the role, then ending it, gives each former helper a lifetime again
        db.set_helper_device(Some(b.node_id)).unwrap();
        assert!(exp(a.node_id).is_some(), "a kept the helper's exemption");
        assert_eq!(exp(b.node_id), None);
        db.set_helper_device(None).unwrap();
        assert!(exp(b.node_id).is_some(), "b kept the helper's exemption");
        // An administrator's 'never' survives the role ending
        db.renew(a.node_id, true).unwrap();
        db.set_helper_device(Some(a.node_id)).unwrap();
        db.set_helper_device(None).unwrap();
        assert_eq!(exp(a.node_id), None);
        // And former helpers are removed for inactivity like anyone else
        {
            let mut s = db.inner.lock().unwrap();
            let now = now_unix();
            for n in &mut s.data.nodes {
                n.last_seen = Some(now - 2 * day_secs());
            }
            s.started_at = now - 3 * day_secs();
        }
        assert_eq!(db.remove_inactive(&|_| false).unwrap(), vec![b.node_id]);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn key_expiry_and_inactive_devices() {
        let (db, path) = temp_db().await;
        let key = db.create_preauth(true, Duration::from_secs(60)).await.unwrap();
        let host = db.create_host_key(Duration::from_secs(60)).await.unwrap();
        let h = db.register(&req(&host, 1)).await.unwrap();
        let a = db.register(&req(&key, 2)).await.unwrap();
        let row = |db: &Db, id| {
            let db = db.clone();
            async move { db.all_nodes().await.unwrap().into_iter().find(|n| n.id == id).unwrap() }
        };
        assert_eq!(row(&db, a.node_id).await.expires_at, None, "no expiry by default");
        assert!(row(&db, a.node_id).await.invite_id.is_some());
        // Turning it on starts the clock now for everyone but the host
        db.set_expiry_settings(Some(30), None).unwrap();
        let now = now_unix();
        let exp = row(&db, a.node_id).await.expires_at.unwrap();
        assert!((exp - now - 30 * day_secs()).abs() < 5);
        assert_eq!(row(&db, h.node_id).await.expires_at, None);
        assert!(!row(&db, a.node_id).await.expired(now));
        assert!(row(&db, a.node_id).await.expired(exp));
        // Renewal: never, then back to the network's time
        db.renew(a.node_id, true).unwrap();
        assert_eq!(row(&db, a.node_id).await.expires_at, None);
        db.renew(a.node_id, false).unwrap();
        assert!(row(&db, a.node_id).await.expires_at.is_some());
        assert!(db.set_expiry_settings(Some(0), None).is_err());
        // An expired key stays expired when the setting changes
        db.inner.lock().unwrap().data.nodes.iter_mut().find(|n| n.id == a.node_id).unwrap().expires_at = Some(now - 10);
        db.set_expiry_settings(Some(60), None).unwrap();
        assert!(row(&db, a.node_id).await.expired(now_unix()), "a new setting revived an expired key");
        db.set_expiry_settings(None, None).unwrap();
        assert!(row(&db, a.node_id).await.expired(now_unix()), "turning expiry off revived an expired key");
        db.renew(a.node_id, false).unwrap();
        assert_eq!(row(&db, a.node_id).await.expires_at, None, "renewed with expiry off: never");
        db.set_expiry_settings(Some(30), None).unwrap();
        // Inactive devices go, unless online, exempt or never seen
        let b = db.register(&req(&key, 3)).await.unwrap();
        db.set_expiry_settings(Some(30), Some(1)).unwrap();
        {
            let mut s = db.inner.lock().unwrap();
            for n in &mut s.data.nodes {
                n.last_seen = Some(now - 2 * day_secs());
            }
        }
        // Not right after the server started, whatever the last-seen times say
        assert!(db.remove_inactive(&|_| false).unwrap().is_empty(), "nothing goes at start");
        db.inner.lock().unwrap().started_at = now - 3 * day_secs();
        assert_eq!(db.remove_inactive(&|id| id == b.node_id).unwrap(), vec![a.node_id]);
        assert_eq!(db.all_nodes().await.unwrap().len(), 2, "host and online b stay");
        // Routes are checked
        assert!(db.set_routes(b.node_id, &["0.0.0.0/0".parse().unwrap()]).is_err());
        assert!(db.set_routes(b.node_id, &["192.168.1.0/24".parse().unwrap()]).unwrap());
        assert_eq!(row(&db, b.node_id).await.approved_routes.len(), 1);
        // Removing a device can revoke the invite it used
        assert!(db.delete_node(b.node_id, true).await.unwrap());
        assert!(matches!(db.register(&req(&key, 4)).await, Err(RegisterError::InvalidAuthKey)));
        check(&db.snapshot().unwrap()).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hostnames() {
        assert_eq!(sanitize_hostname("DESKTOP_ABC.local"), "desktop-abc-local");
        assert_eq!(sanitize_hostname("--"), "node");
    }
}
