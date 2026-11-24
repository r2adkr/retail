use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use retail_proto::DEFAULT_STUN_PORT;
use retail_proto::api::{InviteRequest, InviteResponse, ServerInvite, ServerNode, ServerStartRequest, ServerStatus};
use retail_proto::invite::{Invite, encode_pin};
use serde::{Deserialize, Serialize};

use crate::portmap::{self, Proto};

const DEFAULT_PORT: u16 = 443;
/// Also served, for networks that let only web ports out
const HTTP_PORT: u16 = 80;
/// The server, STUN and WireGuard ports; port 80 is extra
const REQUIRED_PORTS: usize = 3;
const INVITE_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HostConfig {
    enabled: bool,
    port: Option<u16>,
    domain: Option<String>,
    #[serde(default)]
    insecure_http: bool,
    #[serde(default)]
    reality: Option<HostReality>,
    /// CDN URLs in front of the server
    #[serde(default)]
    fronts: Vec<String>,
    /// Helper node code
    #[serde(default)]
    helper: Option<String>,
    /// Nodes allowed to open the web admin page over the network
    #[serde(default)]
    web_admins: Vec<i64>,
}

/// Persisted so the keys survive restarts and existing invites keep working
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostReality {
    /// X25519, base64url
    private_key: String,
    /// 16 hex digits
    short_id: String,
    server_name: String,
    /// `host:port` of the camouflage website
    dest: String,
}

impl HostReality {
    /// `site` is `name`, `name:port`, or `name=host:port` to reach the website
    /// at another address than its name resolves to
    fn new(site: &str) -> Result<Self> {
        let (name, dest) = match site.split_once('=') {
            Some((n, d)) => (n.to_string(), d.to_string()),
            None => match site.rsplit_once(':') {
                Some((n, p)) if p.parse::<u16>().is_ok() => (n.to_string(), site.to_string()),
                _ => (site.to_string(), format!("{site}:443")),
            },
        };
        if name.is_empty() || name.contains('/') {
            bail!("REALITY needs a website name such as www.example.com");
        }
        let mut key = [0u8; 32];
        let mut id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        Ok(HostReality { private_key: encode_pin(&key), short_id: hex(&id), server_name: name.to_ascii_lowercase(), dest })
    }

    fn server_config(&self) -> Option<retail_control::reality::ServerConfig> {
        Some(retail_control::reality::ServerConfig {
            private_key: retail_proto::invite::decode_pin(&self.private_key)?,
            short_ids: vec![unhex(&self.short_id)?],
            server_names: vec![self.server_name.clone()],
            dest: self.dest.clone(),
        })
    }

    fn invite(&self) -> Option<retail_proto::invite::RealityInvite> {
        let secret = boringtun::x25519::StaticSecret::from(retail_proto::invite::decode_pin(&self.private_key)?);
        let public = boringtun::x25519::PublicKey::from(&secret).to_bytes();
        Some(retail_proto::invite::RealityInvite {
            public_key: encode_pin(&public),
            short_id: self.short_id.clone(),
            server_name: self.server_name.clone(),
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[derive(Debug, Clone, Default)]
struct Reach {
    public_ip: Option<IpAddr>,
    /// External ports mapped on the router
    tcp: Option<u16>,
    stun: Option<u16>,
    wg: Option<u16>,
    mapping: Option<String>,
    warning: Option<String>,
    router: Option<retail_proto::api::RouterState>,
    notice: Option<retail_proto::api::ServerNotice>,
}

struct Running {
    server: retail_control::Server,
    reach: Arc<Mutex<Reach>>,
    portmap: Option<tokio::task::JoinHandle<()>>,
    mapped: Arc<Mutex<Option<portmap::Outcome>>>,
    firewall: bool,
    domain: Option<String>,
    reality: Option<HostReality>,
    fronts: Vec<String>,
    helper: Option<retail_proto::invite::HelperCode>,
    helper_link: Option<tokio::task::JoinHandle<()>>,
    helper_linked: Arc<std::sync::atomic::AtomicBool>,
    /// A member device as helper node: its code once it listens, and the
    /// task that links to whichever code is current
    device_helper: Arc<Mutex<Option<retail_proto::invite::HelperCode>>>,
    device_linked: Arc<std::sync::atomic::AtomicBool>,
    device_watch: Option<tokio::task::JoinHandle<()>>,
}

pub struct Host {
    dir: PathBuf,
    running: tokio::sync::Mutex<Option<Running>>,
    last_error: Mutex<Option<String>>,
    /// Public WireGuard endpoint as mapped on the router, offered as a candidate
    /// because this device's own STUN only sees loopback or the LAN
    pub public_wg: tokio::sync::watch::Sender<Option<SocketAddr>>,
}

impl Host {
    pub fn new(state_dir: &std::path::Path) -> Self {
        Host {
            dir: state_dir.join("server"),
            running: tokio::sync::Mutex::default(),
            last_error: Mutex::default(),
            public_wg: tokio::sync::watch::channel(None).0,
        }
    }

    fn config(&self) -> HostConfig {
        std::fs::read(self.dir.join("host.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_config(&self, c: &HostConfig) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        crate::state::secure_dir(&self.dir);
        std::fs::write(self.dir.join("host.json"), serde_json::to_vec_pretty(c)?)?;
        Ok(())
    }

    pub async fn resume(&self, wg_port: u16) {
        let c = self.config();
        if c.enabled {
            let req = ServerStartRequest {
                join: false,
                port: c.port,
                domain: c.domain.clone(),
                insecure_http: c.insecure_http,
                reality: None,
                fronts: None,
                helper: None,
            };
            if let Err(e) = self.start(&req, wg_port).await {
                tracing::error!("could not resume the server: {e:#}");
                *self.last_error.lock().unwrap() = Some(format!("{e:#}"));
            }
        }
    }

    pub async fn start(&self, req: &ServerStartRequest, wg_port: u16) -> Result<()> {
        let mut running = self.running.lock().await;
        if running.is_some() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
        crate::state::secure_dir(&self.dir);
        let saved = self.config();
        // Left out, the port and domain stay as they were (a restored backup's)
        let port = req.port.or(saved.port).unwrap_or(DEFAULT_PORT);
        let domain = match req.domain.as_deref().map(str::trim) {
            Some("") | Some("off") => None,
            Some(d) => Some(d.to_string()),
            None => saved.domain.clone(),
        };
        let tls = if req.insecure_http { retail_control::Tls::Off } else { retail_control::Tls::SelfSigned };
        let previous = self.config().reality;
        let reality = match req.reality.as_deref().map(str::trim) {
            Some("off") | Some("") => None,
            Some(site) => match previous {
                // Same site keeps the keys so earlier invites still work
                Some(r) if HostReality::new(site).is_ok_and(|n| n.server_name == r.server_name && n.dest == r.dest) => Some(r),
                _ => Some(HostReality::new(site)?),
            },
            None => previous,
        };
        let fronts = match &req.fronts {
            Some(f) => f.iter().map(|u| normalize_front(u)).collect::<Result<Vec<_>>>()?,
            None => saved.fronts.clone(),
        };
        let helper_code = match req.helper.as_deref().map(str::trim) {
            Some("off") | Some("") => None,
            Some(code) => Some(code.to_string()),
            None => saved.helper.clone(),
        };
        let helper = match &helper_code {
            Some(code) => Some(retail_proto::invite::HelperCode::decode(code).map_err(anyhow::Error::msg)?),
            None => None,
        };
        let extra_listen = if port == HTTP_PORT || req.insecure_http {
            Vec::new()
        } else {
            vec![SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, HTTP_PORT))]
        };
        let server = retail_control::Server::start(retail_control::Config {
            data_dir: self.dir.clone(),
            listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
            extra_listen,
            stun_listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_STUN_PORT)),
            stun_advertise: Vec::new(),
            tls,
            reality: reality.as_ref().and_then(HostReality::server_config),
        })
        .await
        .context("starting the server")?;

        let firewall = crate::firewall::allow_inbound();
        let reach = Arc::new(Mutex::new(Reach::default()));
        let mapped = Arc::new(Mutex::new(None));
        let stun = Stun {
            adv: server.stun_advertiser(),
            port: server.stun_port(),
            reach: reach.clone(),
            helper: helper.iter().flat_map(helper_stun).collect(),
            device: Arc::default(),
        };
        stun.advertise();
        // RETAIL_NO_PORTMAP leaves the router alone (tests, or a VPS with a public address)
        let use_portmap = !req.insecure_http && std::env::var_os("RETAIL_NO_PORTMAP").is_none();
        let portmap = use_portmap.then(|| {
            let mut ports = vec![(Proto::Tcp, server.port()), (Proto::Udp, server.stun_port()), (Proto::Udp, wg_port)];
            ports.extend(server.extra_ports().iter().map(|p| (Proto::Tcp, *p)));
            let public_wg = self.public_wg.clone();
            tokio::spawn(keep_ports_open(ports, reach.clone(), mapped.clone(), stun.clone(), public_wg))
        });
        let helper_linked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let helper_link = match (&helper, server.injector()) {
            (Some(h), Some(inject)) => Some(tokio::spawn(crate::helper_link::run(h.clone(), inject, helper_linked.clone()))),
            _ => None,
        };
        let device_helper = Arc::new(Mutex::new(None));
        let device_linked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let device_watch = server.injector().map(|inject| {
            tokio::spawn(follow_device_helper(server.helper_device_code(), inject, device_helper.clone(), device_linked.clone(), stun.clone()))
        });
        *running = Some(Running {
            server,
            reach,
            portmap,
            mapped,
            firewall,
            domain: domain.clone(),
            reality: reality.clone(),
            fronts: fronts.clone(),
            helper,
            helper_link,
            helper_linked,
            device_helper,
            device_linked,
            device_watch,
        });
        self.save_config(&HostConfig {
            enabled: true,
            port: Some(port),
            domain,
            insecure_http: req.insecure_http,
            reality,
            fronts,
            helper: helper_code,
            web_admins: saved.web_admins.clone(),
        })?;
        *self.last_error.lock().unwrap() = None;
        drop(running);
        self.publish_addrs().await;
        Ok(())
    }

    /// Tells devices where the server is reachable now, so they follow a
    /// change of its public address. Cheap when nothing changed.
    pub async fn publish_addrs(&self) {
        let running = self.running.lock().await;
        if let Some(r) = running.as_ref() {
            r.server.set_addrs(Self::invite_addrs(r));
        }
    }

    /// The server's data in a passphrase-encrypted file
    pub async fn backup(&self, passphrase: &str) -> Result<String> {
        let running = self.running.lock().await;
        let mut files = crate::backup::Files::read_dir(&self.dir, &[retail_control::DATA_FILE])?;
        match running.as_ref() {
            // From memory, which has the latest last-seen times
            Some(r) => files.insert(retail_control::DATA_FILE, &r.server.snapshot()?),
            None => {
                let data = std::fs::read(self.dir.join(retail_control::DATA_FILE)).context("this device has no server to back up")?;
                files.insert(retail_control::DATA_FILE, &data);
            }
        }
        crate::backup::seal(&files, passphrase, retail_control::now_unix())
    }

    /// Replaces this device's server data with a backup's. The server must
    /// be stopped; the data it had is kept in `server.bak`.
    pub async fn restore(&self, backup: &str, passphrase: &str) -> Result<()> {
        let running = self.running.lock().await;
        if running.is_some() {
            bail!("stop the server first (retail server stop)");
        }
        let files = crate::backup::open(backup, passphrase)?;
        let data = files.get(retail_control::DATA_FILE).context("the backup has no server data")?;
        retail_control::check_data(&data)?;
        let parent = self.dir.parent().context("no state directory")?;
        let incoming = parent.join("server.restore");
        let previous = parent.join("server.bak");
        let _ = std::fs::remove_dir_all(&incoming);
        std::fs::create_dir_all(&incoming)?;
        crate::state::secure_dir(&incoming);
        if let Err(e) = files.write_dir(&incoming) {
            let _ = std::fs::remove_dir_all(&incoming);
            return Err(e);
        }
        let _ = std::fs::remove_dir_all(&previous);
        if self.dir.exists() {
            std::fs::rename(&self.dir, &previous).with_context(|| format!("moving {} aside", self.dir.display()))?;
        }
        if let Err(e) = std::fs::rename(&incoming, &self.dir) {
            let _ = std::fs::rename(&previous, &self.dir);
            return Err(e).context("putting the restored data in place");
        }
        crate::state::secure_dir(&self.dir);
        // It starts when the user starts it, not on its own at the next boot
        let mut c = self.config();
        c.enabled = false;
        self.save_config(&c)?;
        tracing::info!("server data restored from a backup");
        Ok(())
    }

    async fn with_server<T>(&self, f: impl FnOnce(&retail_control::Server) -> Result<T>) -> Result<T> {
        let running = self.running.lock().await;
        let r = running.as_ref().context("the server is not running")?;
        f(&r.server)
    }

    /// `None` lets every device reach every other
    pub async fn set_acl(&self, acl: Option<retail_proto::acl::AclPolicy>) -> Result<()> {
        self.with_server(|s| s.set_acl(acl)).await
    }

    pub async fn set_tags(&self, id: i64, tags: &[String]) -> Result<()> {
        if !self.with_server(|s| s.set_tags(id, tags)).await? {
            anyhow::bail!("there is no device {id}");
        }
        Ok(())
    }

    /// A member device becomes the helper node (`None`: none)
    pub async fn set_helper_device(&self, id: Option<i64>) -> Result<()> {
        self.with_server(|s| s.set_helper_device(id)).await
    }

    pub async fn keep_forever(&self, id: i64) -> Result<()> {
        self.with_server(|s| s.keep_forever(id)).await
    }

    pub async fn set_expiry(&self, key_days: Option<u32>, inactive_days: Option<u32>) -> Result<()> {
        self.with_server(|s| s.set_expiry_settings(key_days, inactive_days)).await
    }

    pub async fn renew(&self, id: i64, never: bool) -> Result<()> {
        if !self.with_server(|s| s.renew(id, never)).await? {
            bail!("there is no device {id}");
        }
        Ok(())
    }

    pub async fn set_routes(&self, id: i64, routes: &[retail_proto::route::Ipv4Net]) -> Result<()> {
        if !self.with_server(|s| s.set_routes(id, routes)).await? {
            bail!("there is no device {id}");
        }
        Ok(())
    }

    pub fn web_admins(&self) -> Vec<i64> {
        self.config().web_admins
    }

    pub fn set_web_admin(&self, id: i64, allowed: bool) -> Result<()> {
        let mut c = self.config();
        c.web_admins.retain(|x| *x != id);
        if allowed {
            c.web_admins.push(id);
        }
        self.save_config(&c)
    }

    pub async fn stop(&self) -> Result<()> {
        let mut c = self.config();
        c.enabled = false;
        self.save_config(&c)?;
        if let Some(r) = self.running.lock().await.take() {
            if let Some(t) = r.portmap {
                t.abort();
            }
            if let Some(t) = r.helper_link {
                t.abort();
            }
            if let Some(t) = r.device_watch {
                t.abort();
            }
            let mapped = r.mapped.lock().unwrap().take();
            if let Some(m) = mapped {
                portmap::close(&m).await;
            }
            if r.firewall {
                crate::firewall::remove_inbound();
            }
            self.public_wg.send_replace(None);
            r.server.stop().await;
        }
        Ok(())
    }

    fn addresses(r: &Running) -> (Option<String>, Vec<String>) {
        let port = r.server.port();
        let reach = r.reach.lock().unwrap().clone();
        let public = match (&r.domain, reach.public_ip, reach.tcp) {
            (Some(d), _, _) => Some(format!("{d}:{port}")),
            (None, Some(ip), Some(p)) if !portmap::is_private(ip) => Some(SocketAddr::new(ip, p).to_string()),
            _ => None,
        };
        let lan = lan_ips().into_iter().map(|ip| SocketAddr::new(ip, port).to_string()).collect();
        (public, lan)
    }

    /// Public first, then the helpers, then global IPv6 (often reachable even
    /// behind CGNAT), then the rest of the LAN
    fn invite_addrs(r: &Running) -> Vec<String> {
        let (public, lan) = Self::addresses(r);
        let helper = r.helper.iter().flat_map(|h| h.addrs.iter().cloned());
        let device = r.device_helper.lock().unwrap().clone();
        let device = device.iter().flat_map(|h| h.addrs.iter().cloned()).collect::<Vec<_>>();
        let (global, private): (Vec<String>, Vec<String>) = lan.into_iter().partition(|a| {
            a.parse::<SocketAddr>().is_ok_and(|sa| sa.is_ipv6() && !portmap::is_private(sa.ip()))
        });
        let mut out: Vec<String> = Vec::new();
        for a in public.into_iter().chain(helper).chain(device).chain(global).chain(private) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    pub async fn status(&self) -> ServerStatus {
        let running = self.running.lock().await;
        let last_error = self.last_error.lock().unwrap().clone();
        let Some(r) = running.as_ref() else {
            return ServerStatus { last_error, ..Default::default() };
        };
        let (public, lan) = Self::addresses(r);
        let reach = r.reach.lock().unwrap().clone();
        let nodes = r.server.nodes().await.unwrap_or_default();
        // Either helper makes the server reachable whatever the router does
        let reachable = r.helper_linked.load(std::sync::atomic::Ordering::Relaxed)
            || r.device_linked.load(std::sync::atomic::Ordering::Relaxed);
        let invites = r.server.keys().await.unwrap_or_default();
        let (key_expiry_days, remove_inactive_days) = r.server.expiry_settings();
        ServerStatus {
            key_expiry_days,
            remove_inactive_days,
            running: true,
            port: Some(r.server.port()),
            public,
            lan,
            port_mapping: reach.mapping,
            warning: reach.warning.filter(|_| !reachable),
            router: reach.router,
            notice: reach.notice.filter(|_| !reachable),
            domain: r.domain.clone(),
            reality: r.reality.as_ref().map(|x| x.server_name.clone()),
            fronts: r.fronts.clone(),
            helper: r.helper.as_ref().and_then(|h| h.addrs.first().cloned()),
            helper_linked: r.helper_linked.load(std::sync::atomic::Ordering::Relaxed),
            helper_device: r.server.helper_device(),
            helper_device_linked: r.device_linked.load(std::sync::atomic::Ordering::Relaxed),
            acl: r.server.acl(),
            nodes: nodes
                .into_iter()
                .map(|n| ServerNode {
                    id: n.id,
                    hostname: n.hostname,
                    os: n.os,
                    ip: n.ip,
                    online: n.online,
                    exit_node: n.exit_node,
                    last_seen: n.last_seen,
                    dns_name: n.dns_name,
                    tags: n.tags,
                    advertised_routes: n.advertised_routes,
                    approved_routes: n.approved_routes,
                    expires_at: n.expires_at,
                    expired: n.expired,
                    invite_id: n.invite_id,
                })
                .collect(),
            invites: invites
                .into_iter()
                .map(|k| ServerInvite {
                    id: k.id,
                    reusable: k.reusable,
                    used: k.used,
                    expires_at: k.expires_at,
                    created_at: k.created_at,
                    name: k.name,
                    uses: k.uses,
                })
                .collect(),
            last_error,
        }
    }

    /// Single-use and valid for 24 h unless the request says otherwise. With
    /// a name: the named invite, reusable, with a new code that voids its old one.
    pub async fn invite(&self, req: &InviteRequest) -> Result<InviteResponse> {
        let running = self.running.lock().await;
        let r = running.as_ref().context("the server is not running")?;
        let max = |h: u64| Duration::from_secs(h.clamp(1, 24 * 365) * 3600);
        let (key, expires_at) = match req.name.as_deref().map(str::trim) {
            Some(name) => {
                if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
                    bail!("an invite name is 1 to 40 characters");
                }
                let ttl = req.ttl_hours.map(max);
                let (_, key) = r.server.set_named_key(name, ttl).await?;
                let expires = ttl.map_or(i64::MAX, |t| retail_control::now_unix() + t.as_secs() as i64);
                (key, expires)
            }
            None => {
                let ttl = req.ttl_hours.map_or(INVITE_TTL, max);
                let key = r.server.create_key(req.reusable, ttl).await?;
                (key, retail_control::now_unix() + ttl.as_secs() as i64)
            }
        };
        Ok(InviteResponse { code: Self::invite_code(r, key)?, expires_at })
    }

    fn invite_code(r: &Running, key: String) -> Result<String> {
        let addrs = Self::invite_addrs(r);
        if addrs.is_empty() {
            bail!("this device has no network address to invite others to");
        }
        let reality = r.reality.as_ref().and_then(HostReality::invite);
        let invite =
            Invite { addrs, pin: r.server.pin().as_ref().map(encode_pin), key, reality, fronts: r.fronts.clone() };
        Ok(invite.encode())
    }

    /// The current code of a named invite, with today's addresses
    pub async fn named_code(&self, id: i64) -> Result<String> {
        let running = self.running.lock().await;
        let r = running.as_ref().context("the server is not running")?;
        let key = r.server.named_key(id).await?.context("no such named invite, or it expired")?;
        Self::invite_code(r, key)
    }

    pub async fn local_url(&self) -> Option<String> {
        let running = self.running.lock().await;
        running.as_ref().map(|r| format!("https://127.0.0.1:{}", r.server.port()))
    }

    pub async fn self_invite(&self) -> Result<String> {
        let running = self.running.lock().await;
        let r = running.as_ref().context("the server is not running")?;
        let key = r.server.create_host_key(Duration::from_secs(600)).await?;
        let invite = Invite {
            addrs: vec![format!("127.0.0.1:{}", r.server.port())],
            pin: r.server.pin().as_ref().map(encode_pin),
            key,
            reality: None,
            fronts: Vec::new(),
        };
        Ok(invite.encode())
    }

    pub async fn delete_node(&self, id: i64, revoke_invite: bool) -> Result<bool> {
        let running = self.running.lock().await;
        running.as_ref().context("the server is not running")?.server.delete_node(id, revoke_invite).await
    }

    pub async fn revoke_invite(&self, id: i64) -> Result<bool> {
        let running = self.running.lock().await;
        running.as_ref().context("the server is not running")?.server.revoke_key(id).await
    }
}

/// Links to the member device acting as helper node, following its code
async fn follow_device_helper(
    mut code: tokio::sync::watch::Receiver<Option<String>>,
    inject: retail_control::Injector,
    current: Arc<Mutex<Option<retail_proto::invite::HelperCode>>>,
    linked: Arc<std::sync::atomic::AtomicBool>,
    stun: Stun,
) {
    let mut link: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        let decoded = code.borrow_and_update().as_deref().and_then(|c| retail_proto::invite::HelperCode::decode(c).ok());
        if let Some(t) = link.take() {
            t.abort();
        }
        linked.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = &decoded {
            tracing::info!(helper = ?h.addrs.first(), "linking to the helper device");
            link = Some(tokio::spawn(crate::helper_link::run(h.clone(), inject.clone(), linked.clone())));
        }
        *stun.device.lock().unwrap() = decoded.iter().flat_map(helper_stun).collect();
        stun.advertise();
        *current.lock().unwrap() = decoded;
        if code.changed().await.is_err() {
            break;
        }
    }
    if let Some(t) = link {
        t.abort();
    }
}

/// What the STUN servers advertised to devices come from: the router's
/// mapping, helper nodes (which answer STUN too, reachable from elsewhere),
/// and the LAN
#[derive(Clone)]
struct Stun {
    adv: retail_control::StunAdvertiser,
    port: u16,
    reach: Arc<Mutex<Reach>>,
    helper: Vec<String>,
    device: Arc<Mutex<Vec<String>>>,
}

impl Stun {
    fn advertise(&self) {
        let reach = self.reach.lock().unwrap().clone();
        let mut stun = Vec::new();
        if let (Some(ip), Some(port)) = (reach.public_ip.filter(|ip| !portmap::is_private(*ip)), reach.stun) {
            stun.push(SocketAddr::new(ip, port).to_string());
        }
        stun.extend(self.helper.iter().cloned());
        stun.extend(self.device.lock().unwrap().iter().cloned());
        stun.extend(lan_ips().into_iter().map(|ip| SocketAddr::new(ip, self.port).to_string()));
        self.adv.set(stun);
    }
}

/// `host:3478` for each address of a helper code
fn helper_stun(code: &retail_proto::invite::HelperCode) -> Vec<String> {
    code.addrs.iter().filter_map(|a| a.rsplit_once(':').map(|(host, _)| format!("{host}:{DEFAULT_STUN_PORT}"))).collect()
}

/// An `https://` URL without a trailing slash
fn normalize_front(url: &str) -> Result<String> {
    let url = url.trim().trim_end_matches('/');
    let rest = url.strip_prefix("https://").context("a CDN address starts with https://")?;
    if rest.is_empty() || rest.contains(['/', '?', '#', ' ']) {
        bail!("a CDN address is https://name, with no path");
    }
    Ok(url.to_string())
}

async fn keep_ports_open(
    ports: Vec<(Proto, u16)>,
    reach: Arc<Mutex<Reach>>,
    mapped: Arc<Mutex<Option<portmap::Outcome>>>,
    stun_servers: Stun,
    public_wg: tokio::sync::watch::Sender<Option<SocketAddr>>,
) {
    loop {
        let previous = mapped.lock().unwrap().clone();
        let result = match &previous {
            Some(o) => portmap::renew(o, REQUIRED_PORTS).await,
            None => portmap::open(&ports, REQUIRED_PORTS).await,
        };
        match result {
            Ok(o) => {
                let tcp = o.external(Proto::Tcp, ports[0].1);
                let stun = o.external(Proto::Udp, ports[1].1);
                let now = Reach {
                    public_ip: o.external_ip,
                    tcp,
                    stun,
                    wg: o.external(Proto::Udp, ports[2].1),
                    mapping: Some(format!(
                        "opened by {} (TCP {}, UDP {})",
                        o.method_name(),
                        tcp.unwrap_or(0),
                        stun.unwrap_or(0)
                    )),
                    router: Some(retail_proto::api::RouterState::Opened {
                        method: o.method_name().to_string(),
                        tcp: tcp.unwrap_or(0),
                        udp: stun.unwrap_or(0),
                    }),
                    notice: o
                        .external_ip
                        .filter(|ip| portmap::is_private(*ip))
                        .map(|router_ip| retail_proto::api::ServerNotice::Cgnat { router_ip }),
                    warning: o.external_ip.filter(|ip| portmap::is_private(*ip)).map(|ip| {
                        format!(
                            "Your router's own internet address ({ip}) is private: your provider or another router \
                             shares one public address (CGNAT). Devices on other networks cannot reach this server \
                             unless a helper node on a public machine relays for it (`retail helper start` there, \
                             then `retail server start --helper CODE` here); devices on this network can still join."
                        )
                    }),
                };
                if previous.is_none() {
                    tracing::info!(method = o.method_name(), external_ip = ?o.external_ip, "router ports opened");
                }
                *mapped.lock().unwrap() = Some(o);
                *reach.lock().unwrap() = now.clone();
                stun_servers.advertise();
                let wg = now.public_ip.filter(|ip| !portmap::is_private(*ip)).zip(now.wg);
                public_wg.send_replace(wg.map(|(ip, port)| SocketAddr::new(ip, port)));
                tokio::time::sleep(portmap::LEASE / 2).await;
                continue;
            }
            Err(e) => {
                tracing::info!("router port forwarding: {e:#}");
                *mapped.lock().unwrap() = None;
                let failed = Reach {
                    mapping: Some("not available".into()),
                    router: Some(retail_proto::api::RouterState::Unavailable),
                    notice: Some(retail_proto::api::ServerNotice::ForwardPorts { tcp: ports[0].1, udp: ports[1].1 }),
                    warning: Some(format!(
                        "The router did not open the ports automatically (UPnP/NAT-PMP is off or unsupported). \
                         Devices on other networks can join after you forward TCP {} and UDP {} to this computer, \
                         or use a domain name.",
                        ports[0].1, ports[1].1
                    )),
                    ..Reach::default()
                };
                *reach.lock().unwrap() = failed;
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Whether `ip` is one of this machine's addresses (refreshed every few seconds)
pub fn is_own(ip: std::net::Ipv4Addr) -> bool {
    static CACHE: Mutex<Option<(std::time::Instant, Vec<IpAddr>)>> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap();
    if c.as_ref().is_none_or(|(at, _)| at.elapsed() > Duration::from_secs(5)) {
        let all = if_addrs::get_if_addrs().map(|v| v.into_iter().map(|i| i.ip()).collect()).unwrap_or_default();
        *c = Some((std::time::Instant::now(), all));
    }
    c.as_ref().is_some_and(|(_, all)| all.contains(&IpAddr::V4(ip)))
}

/// The IPv4 networks this machine's interfaces are on, outside the mesh
pub fn local_networks() -> Vec<retail_proto::route::Ipv4Net> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else { return Vec::new() };
    ifaces
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !retail_proto::in_mesh(v4.ip) => {
                let len = u32::from(v4.netmask).leading_ones() as u8;
                retail_proto::route::Ipv4Net::new(v4.ip, len)
            }
            _ => None,
        })
        .collect()
}

pub fn lan_ips() -> Vec<IpAddr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else { return Vec::new() };
    let mut ips: Vec<IpAddr> = ifaces
        .into_iter()
        .map(|i| i.ip())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !retail_proto::in_mesh(*v4),
            IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 && !v6.is_unspecified(),
        })
        .collect();
    // The default-route address first (not a VM or container adapter), then
    // IPv4 before IPv6, the common case for devices nearby
    let primary = portmap::default_gateway().and_then(|gw| portmap::local_ipv4_towards(IpAddr::V4(gw))).map(IpAddr::V4);
    ips.sort_by_key(|ip| (Some(*ip) != primary, ip.is_ipv6(), *ip));
    ips.dedup();
    ips
}
