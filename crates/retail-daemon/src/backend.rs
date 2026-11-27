use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use boringtun::x25519::PublicKey;
use retail_proto::api::{
    BackendState, InviteRequest, InviteResponse, Prefs, PrefsRequest, RegisterRequest, SelfStatus, ServerStartRequest,
    ServerStatus, StatusResponse, UpRequest,
};
use retail_proto::{Key, MESH_PREFIX_LEN};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinSet;

use crate::control;
use crate::engine::{DataPlaneTask, Engine, EngineConfig};
use crate::exit::{ClientRoutes, Gateway, SubnetRoutes};
use crate::state::Persisted;

pub struct Options {
    pub state_dir: PathBuf,
    pub listen_port: u16,
    pub tun_name: Option<String>,
    /// Memory limit in MiB, used unless the user set one (`retail set --memory-limit`)
    pub memory_limit_mb: Option<u32>,
}

/// How long the session's cleanup (closing router ports) may take
const GRACEFUL_STOP: std::time::Duration = std::time::Duration::from_secs(5);

struct Session {
    engine: Arc<Engine>,
    started: Instant,
    tasks: JoinSet<()>,
    /// Tasks that watch `stop` and undo what they set up (router ports), so
    /// they are given a moment to finish before the rest is cut short
    graceful: JoinSet<()>,
    threads: Vec<std::thread::JoinHandle<()>>,
    stop: watch::Sender<bool>,
    /// Exit-node routing (we use an exit), undone on drop
    exit_routes: Option<ClientRoutes>,
    /// Forwarding for the mesh (we are an exit node or route networks)
    gateway: Arc<std::sync::Mutex<Gateway>>,
    /// The system sends MagicDNS names to us while this lives
    _dns: Option<crate::magicdns::SystemDns>,
}

pub struct Backend {
    opts: Options,
    state_path: PathBuf,
    persisted: Arc<Mutex<Persisted>>,
    session: Mutex<Option<Session>>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
    /// Fatal errors of session tasks, on which the supervisor restarts the session
    failures: mpsc::UnboundedSender<&'static str>,
    failures_rx: Mutex<Option<mpsc::UnboundedReceiver<&'static str>>>,
    /// A network hosted on this device
    pub host: crate::host::Host,
    /// This device as a helper node for a server elsewhere
    pub helper: crate::helper_host::HelperHost,
    /// This device's own port on the router, when the user allows it
    device_port: crate::device_port::DevicePort,
    /// Set once the web admin page listens
    pub web: std::sync::OnceLock<retail_web::WebAdmin>,
    pub updater: Arc<crate::update::Updater>,
    usage: crate::usage::Usage,
    /// An administrator asked the daemon to exit (`POST /shutdown`)
    pub stop_requested: tokio::sync::Notify,
    /// Held while a stopped session winds down, so the next one waits for
    /// its TUN device but nothing else does
    teardown: Mutex<()>,
    last_status: std::sync::Mutex<Option<StatusResponse>>,
}

const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long `status` waits for a session being started or stopped
const STATUS_WAIT: Duration = Duration::from_secs(1);
/// A session that ran this long before failing resets the restart backoff
const HEALTHY_RUN: Duration = Duration::from_secs(60);

fn default_hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

impl Backend {
    pub fn new(opts: Options) -> Result<Self> {
        let state_path = opts.state_dir.join("state.json");
        let mut persisted = Persisted::load(&state_path)?;
        // 1.0.2 and earlier saved it even where it cannot work
        if persisted.prefs.advertise_exit_node
            && let Err(e) = crate::exit::can_offer_exit()
        {
            tracing::warn!("no longer offering this device as an exit node: {e:#}");
            persisted.prefs.advertise_exit_node = false;
            if let Err(e) = persisted.save(&state_path) {
                tracing::warn!("saving settings: {e:#}");
            }
        }
        crate::proxy::set_preference(persisted.prefs.proxy.as_deref(), persisted.prefs.proxy_sign_in);
        let host = crate::host::Host::new(&opts.state_dir);
        let helper = crate::helper_host::HelperHost::new(&opts.state_dir);
        let updater = Arc::new(crate::update::Updater::new(&opts.state_dir));
        let usage = crate::usage::Usage::load(&opts.state_dir);
        let device_port = crate::device_port::DevicePort::default();
        device_port.set_wanted(persisted.prefs.open_router_port);
        let (failures, failures_rx) = mpsc::unbounded_channel();
        Ok(Backend {
            opts,
            state_path,
            persisted: Arc::new(Mutex::new(persisted)),
            session: Mutex::new(None),
            last_error: Arc::default(),
            failures,
            failures_rx: Mutex::new(Some(failures_rx)),
            host,
            helper,
            device_port,
            web: std::sync::OnceLock::new(),
            updater,
            usage,
            stop_requested: tokio::sync::Notify::new(),
            teardown: Mutex::new(()),
            last_status: std::sync::Mutex::default(),
        })
    }

    /// Restarts the session, with exponential backoff, whenever one of its
    /// tasks dies (for example the TUN device disappeared).
    pub fn spawn_supervisor(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let Some(mut rx) = me.failures_rx.lock().await.take() else {
                return;
            };
            let mut backoff = Duration::from_secs(1);
            let mut last_restart = Instant::now();
            while let Some(task) = rx.recv().await {
                if last_restart.elapsed() > HEALTHY_RUN {
                    backoff = Duration::from_secs(1);
                }
                tracing::warn!("session task '{task}' failed; restarting the session in {backoff:?}");
                loop {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
                    // Without the settings locked: winding down can take long
                    me.stop_session().await;
                    let p = me.persisted.lock().await;
                    // Turned off, or connected again meanwhile
                    if !(p.want_running && p.token.is_some()) || me.session.lock().await.is_some() {
                        break;
                    }
                    match me.start_locked(&p).await {
                        Ok(()) => {
                            tracing::info!("session restarted");
                            break;
                        }
                        Err(e) => tracing::warn!("session restart failed: {e:#}"),
                    }
                }
                last_restart = Instant::now();
                // Other tasks of the same failed session may have reported too
                while rx.try_recv().is_ok() {}
            }
        });
    }

    fn set_error(&self, e: Option<String>) {
        *self.last_error.lock().unwrap() = e;
    }

    /// Brings the tunnel back up after a restart if the user left it up
    pub async fn start_if_wanted(&self) -> Result<()> {
        let p = self.persisted.lock().await;
        if p.want_running && p.token.is_some() {
            self.start_locked(&p).await?;
        }
        Ok(())
    }

    pub async fn up(&self, mut req: UpRequest) -> Result<()> {
        let mut invite_reality = None;
        let mut target = match req.invite.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(code) => {
                let invite = retail_proto::invite::Invite::decode(code).map_err(|e| anyhow!(e))?;
                req.auth_key = Some(invite.key.clone());
                // The address ends up in terminals and status: host:port, nothing else
                if invite.addrs.iter().any(|a| a.chars().any(|c| c.is_control() || c.is_whitespace() || c == '/')) {
                    anyhow::bail!("the invite code is damaged");
                }
                let pin = match &invite.pin {
                    Some(p) => Some(retail_proto::invite::decode_pin(p).context("the invite code is damaged")?),
                    None => None,
                };
                invite_reality = invite.reality.clone();
                crate::http::Target {
                    url: format!("https://{}", invite.addrs[0]),
                    pin,
                    alts: invite.addrs[1..].to_vec(),
                    reality: invite.reality.as_ref().and_then(crate::reality::Params::from_invite),
                    fronts: invite.fronts.clone(),
                }
            }
            None => crate::http::Target::url(control::normalize_server(&req.server)?),
        };
        let server = target.url.clone();
        let mut p = self.persisted.lock().await;
        let previous = p.clone();
        // The same server at a new address (moved, or restored from a backup
        // on another device) has the same key: this device stays the same
        // member, with its address and name, rather than joining anew
        if let Some(pin) = target.pin.map(|k| retail_proto::invite::encode_pin(&k))
            && p.server.as_deref() != Some(server.as_str())
        {
            let current = p.token.is_some() && p.server_pin.as_deref() == Some(pin.as_str());
            let saved = p.saved.iter().find(|s| s.server_pin.as_deref() == Some(pin.as_str()) && s.token.is_some()).cloned();
            if current || saved.is_some() {
                let old = if current { p.server.clone().unwrap_or_default() } else { saved.as_ref().map(|s| s.server.clone()).unwrap_or_default() };
                tracing::info!("{old} is now at {server}");
                if !current {
                    self.stop_session().await;
                    p.remember_current();
                    p.clear_current();
                    if let Some(s) = &saved {
                        p.load_profile(s);
                    }
                }
                p.saved.retain(|s| s.server != old);
                p.server = Some(server.clone());
            }
        }
        // Joining another server keeps the current one in the saved list, to
        // switch back to, and goes back to it if joining fails
        if p.token.is_some() && p.server.as_deref() != Some(server.as_str()) {
            self.stop_session().await;
            p.remember_current();
            p.clear_current();
        }
        // A server joined before: same key, so it keeps this device's node and address
        if p.token.is_none()
            && let Some(saved) = p.saved.iter().find(|s| s.server == server).cloned()
        {
            p.load_profile(&saved);
        }
        let secret = p.ensure_private_key();

        let registered_here = p.token.is_some() && p.server.as_deref() == Some(server.as_str());
        if registered_here
            && req.invite.as_deref().is_none_or(|s| s.trim().is_empty())
            && let Some(t) = p.target()
        {
            // Keep the pin and addresses from the original invite, also with a new key
            target = t;
        }
        if !registered_here || req.auth_key.is_some() {
            let auth_key = req.auth_key.clone().ok_or_else(|| {
                anyhow!("this node is not registered with {server}; pass --auth-key or an invite code")
            })?;
            let hostname = req
                .hostname
                .clone()
                .or_else(|| p.hostname.clone())
                .unwrap_or_else(default_hostname);
            // Proves this device is the one registered with the key
            let token = p.token.clone().filter(|_| p.server.as_deref() == Some(server.as_str()));
            if token.is_some() {
                // A stored token goes only to the server it belongs to: one that
                // proves the stored pin, or holds the REALITY key saved with the
                // registration. An invite can name any pin and any REALITY key
                // next to this server's address, so neither may come from it.
                if target.pin.as_ref().map(retail_proto::invite::encode_pin) != p.server_pin {
                    anyhow::bail!("this invite names a different server key than the one {server} had when this device joined");
                }
                invite_reality = p.server_reality.clone();
                target.reality = invite_reality.as_ref().and_then(crate::reality::Params::from_invite);
            }
            let registered = control::register(
                &target,
                &RegisterRequest {
                    auth_key,
                    node_key: Key(PublicKey::from(&secret).to_bytes()),
                    hostname: hostname.clone(),
                    os: std::env::consts::OS.to_string(),
                    token,
                },
            )
            .await;
            let resp = match registered {
                Ok(r) => r,
                Err(e) => {
                    if previous.server != p.server || previous.token != p.token {
                        *p = previous;
                        if p.want_running && p.token.is_some() && self.session.lock().await.is_none() {
                            let _ = self.start_locked(&p).await;
                        }
                    }
                    return Err(e);
                }
            };
            tracing::info!(ip = %resp.ip, node_id = resp.node_id, "registered with {server}");
            p.server = Some(server);
            p.server_pin = target.pin.as_ref().map(retail_proto::invite::encode_pin);
            p.server_alts = target.alts.clone();
            p.server_reality = invite_reality;
            p.server_fronts = target.fronts.clone();
            p.token = Some(resp.token);
            p.node_id = Some(resp.node_id);
            p.ip = Some(resp.ip);
            p.prefix_len = Some(resp.prefix_len);
            p.hostname = Some(hostname);
            if let Some(code) = req.invite.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                p.invite = Some(code.to_string());
            }
        }
        p.want_running = true;
        p.remember_current();
        p.save(&self.state_path)?;

        self.stop_session().await;
        self.start_locked(&p).await
    }

    pub async fn down(&self) -> Result<()> {
        let mut p = self.persisted.lock().await;
        p.want_running = false;
        p.save(&self.state_path)?;
        self.stop_session().await;
        Ok(())
    }

    /// Disconnects and forgets the current registration and its key (it
    /// leaves the saved servers too), so the next `up` creates a new node
    pub async fn logout(&self) -> Result<()> {
        let mut p = self.persisted.lock().await;
        self.stop_session().await;
        if let Some(server) = p.server.clone() {
            p.saved.retain(|s| s.server != server);
        }
        let _ = std::fs::remove_dir_all(helper_dir(&self.opts.state_dir, &p));
        p.clear_current();
        p.save(&self.state_path)?;
        self.set_error(None);
        Ok(())
    }

    /// Leaves the current server (kept in the saved list) and connects to a
    /// saved one with its own registration, no invite needed
    pub async fn switch_server(&self, server: &str) -> Result<()> {
        let mut p = self.persisted.lock().await;
        if p.token.is_some() && p.server.as_deref() == Some(server) {
            p.want_running = true;
            p.save(&self.state_path)?;
            if self.session.lock().await.is_none() {
                self.start_locked(&p).await?;
            }
            return Ok(());
        }
        let target = p.saved.iter().find(|s| s.server == server).cloned().with_context(|| format!("{server} is not a saved server"))?;
        self.stop_session().await;
        p.remember_current();
        p.clear_current();
        p.load_profile(&target);
        p.want_running = true;
        p.save(&self.state_path)?;
        tracing::info!("switched to {server}");
        self.start_locked(&p).await
    }

    /// Removes a saved server; the current one is logged out of
    pub async fn forget_server(&self, server: &str) -> Result<()> {
        let current = self.persisted.lock().await.server.as_deref() == Some(server);
        if current {
            return self.logout().await;
        }
        let mut p = self.persisted.lock().await;
        let before = p.saved.len();
        p.saved.retain(|s| s.server != server);
        if p.saved.len() == before {
            anyhow::bail!("{server} is not a saved server");
        }
        p.save(&self.state_path)
    }

    /// Changes user settings, applied at once when the tunnel is up
    /// `admin`: the request came from an administrator/root
    pub async fn set_prefs(&self, req: PrefsRequest, admin: bool) -> Result<()> {
        let mut p = self.persisted.lock().await;
        let mut session = self.session.lock().await;
        let mut prefs = p.prefs.clone();
        if let Some(name) = req.exit_node.as_deref().map(str::trim) {
            prefs.exit_node = if name.is_empty() || name.eq_ignore_ascii_case("none") {
                None
            } else {
                let engine = &session.as_ref().context("connect first: exit nodes are looked up in the network")?.engine;
                let (key, hostname, offers) = engine.find_peer(name)?;
                if !offers {
                    anyhow::bail!("{hostname} does not offer itself as an exit node (on it: retail set --advertise-exit-node)");
                }
                Some(key)
            };
        }
        if let Some(on) = req.advertise_exit_node {
            prefs.advertise_exit_node = on;
        }
        if let Some(on) = req.open_router_port {
            prefs.open_router_port = on;
        }
        if let Some(routes) = &req.advertise_routes {
            prefs.advertise_routes = retail_proto::route::parse_routes(routes).map_err(anyhow::Error::msg)?;
        }
        if let Some(mb) = req.memory_limit_mb {
            prefs.memory_limit_mb = (mb > 0).then_some(mb);
        }
        if let Some(mbit) = req.upload_limit_mbit {
            prefs.upload_limit_mbit = (mbit > 0).then_some(mbit);
        }
        if let Some(proxy) = req.proxy.as_deref().map(str::trim) {
            prefs.proxy = match proxy {
                "" | "auto" => None,
                "off" | "none" | "direct" => Some("off".into()),
                url => {
                    crate::proxy::Proxy::parse(url).with_context(|| format!("not a proxy address: {url}"))?;
                    Some(url.to_string())
                }
            };
            // Any user who may control retail can set a proxy; only an
            // administrator's may receive a Windows sign-in, which would
            // otherwise be another user's or the computer's
            prefs.proxy_sign_in = admin && prefs.proxy.as_deref().is_some_and(|p| p != "off");
            crate::proxy::set_preference(prefs.proxy.as_deref(), prefs.proxy_sign_in);
        }
        if let Some(on) = req.auto_update {
            prefs.auto_update = on;
            // Turned on with a newer release already known: install it now
            if on && !p.prefs.auto_update && self.updater.status().available {
                let _ = self.updater.start_install();
            }
        }
        if prefs.exit_node.is_some() && prefs.advertise_exit_node {
            anyhow::bail!("a device cannot use an exit node and be one at the same time");
        }
        // Refused before it is saved, so the switch does not stay on
        if prefs.advertise_exit_node && !p.prefs.advertise_exit_node {
            crate::exit::can_offer_exit().context("offering this device as an exit node")?;
        }
        let restart = prefs.memory_limit_mb != p.prefs.memory_limit_mb;
        p.prefs = prefs;
        p.save(&self.state_path)?;
        self.device_port.set_wanted(p.prefs.open_router_port);
        if let Some(s) = session.as_mut()
            && !restart
        {
            let result = apply_exit_prefs(s, &p.prefs);
            drop(session);
            return result;
        }
        drop(session);
        if restart && p.want_running && p.token.is_some() {
            // Buffer sizes are fixed when the data plane starts
            self.stop_session().await;
            self.start_locked(&p).await?;
        }
        Ok(())
    }

    pub async fn auto_update(&self) -> bool {
        self.persisted.lock().await.prefs.auto_update
    }

    pub async fn server_status(&self) -> ServerStatus {
        self.host.status().await
    }

    /// Starts the server on this device and, unless told otherwise, makes
    /// this device the network's first member.
    pub async fn server_start(&self, req: ServerStartRequest) -> Result<()> {
        self.host.start(&req, self.opts.listen_port).await?;
        if !req.join {
            return Ok(());
        }
        let own = self.host.local_url().await;
        let pin = self.host.pin().await;
        // Its own server at the same address may hold other data now (a
        // restored backup): only the same certificate is the same network
        let joined = {
            let p = self.persisted.lock().await;
            p.token.is_some() && own.is_some() && p.server == own && p.server_pin == pin
        };
        if joined {
            {
                let p = self.persisted.lock().await;
                if self.session.lock().await.is_none() && p.want_running {
                    self.start_locked(&p).await?;
                }
            }
            self.exempt_own_node().await;
            return Ok(());
        }
        let code = self.host.self_invite().await?;
        self.up(UpRequest { invite: Some(code), ..Default::default() }).await?;
        self.exempt_own_node().await;
        Ok(())
    }

    /// The device hosting the network never expires from it, even when it
    /// joined before hosting devices were exempt
    pub async fn exempt_own_node(&self) {
        let Some(own) = self.host.local_url().await else { return };
        let id = {
            let p = self.persisted.lock().await;
            if p.server.as_deref() != Some(own.as_str()) {
                return;
            }
            p.node_id.zip(p.public_key())
        };
        if let Some((id, key)) = id
            && let Err(e) = self.host.keep_forever(id, &key).await
        {
            tracing::debug!("exempting this device from key expiry: {e:#}");
        }
    }

    /// This device's mesh address while it is a member of the network it hosts
    pub async fn own_mesh_ip(&self) -> Option<std::net::Ipv4Addr> {
        let own = self.host.local_url().await?;
        let p = self.persisted.lock().await;
        let running = self.session.lock().await.is_some();
        (running && p.server.as_deref() == Some(own.as_str())).then_some(p.ip).flatten()
    }

    pub async fn server_stop(&self) -> Result<()> {
        self.host.stop().await
    }

    pub async fn server_invite(&self, req: InviteRequest) -> Result<InviteResponse> {
        self.host.invite(&req).await
    }

    /// The daemon is exiting: the session ends, and hosting and the helper
    /// node stop without being turned off, so their router ports and firewall
    /// rule go now and come back at the next start
    /// Samples traffic for the totals, and saves them now and then
    pub fn spawn_usage(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            for n in 0u64.. {
                tick.tick().await;
                if let Some(s) = me.session.lock().await.as_ref() {
                    me.usage.record(&s.engine.peer_status());
                }
                if n % 10 == 9 {
                    me.usage.save();
                }
            }
        });
    }

    pub async fn shutdown(&self) {
        self.stop_session().await;
        self.usage.save();
        self.host.halt().await;
        self.helper.halt().await;
    }

    async fn stop_session(&self) {
        let _teardown = self.teardown.lock().await;
        // Out of its slot first, so status and settings do not wait for the teardown
        let Some(mut s) = self.session.lock().await.take() else { return };
        self.usage.record(&s.engine.peer_status());
        self.usage.end_session();
        let _ = s.stop.send(true);
        let graceful = &mut s.graceful;
        let _ = tokio::time::timeout(GRACEFUL_STOP, async { while graceful.join_next().await.is_some() {} }).await;
        s.graceful.shutdown().await;
        // Wait for every task so the TUN device is released before a new session reuses its name
        s.tasks.shutdown().await;
        for t in s.threads {
            let _ = tokio::task::spawn_blocking(move || t.join()).await;
        }
        drop(s.engine);
        tracing::info!("session stopped");
    }

    async fn start_locked(&self, p: &Persisted) -> Result<()> {
        self.set_error(None);
        match self.start_session(p).await {
            Ok(s) => {
                *self.session.lock().await = Some(s);
                Ok(())
            }
            Err(e) => {
                self.set_error(Some(format!("{e:#}")));
                Err(e)
            }
        }
    }

    async fn start_session(&self, p: &Persisted) -> Result<Session> {
        drop(self.teardown.lock().await);
        let target = p.target().context("not registered")?;
        let server = target.url.clone();
        let token = p.token.clone().context("not registered")?;
        let engine = Arc::new(
            Engine::new(EngineConfig {
                private_key: p.secret().context("missing private key")?,
                ip: p.ip.context("no IP assigned")?,
                prefix_len: p.prefix_len.unwrap_or(MESH_PREFIX_LEN),
                listen_port: self.opts.listen_port,
                tun_name: self.opts.tun_name.clone(),
                memory_limit_mb: p.prefs.memory_limit_mb.or(self.opts.memory_limit_mb),
            })
            .await?,
        );

        let mut tasks = JoinSet::new();
        let stun = control::default_stun_server(&server);
        let (stop, _) = watch::channel(false);
        let mut threads = Vec::new();
        for (name, task) in engine.data_plane_tasks() {
            threads.push(self.spawn_thread(name, task, stop.subscribe())?);
        }
        self.spawn(&mut tasks, "timers", engine.clone().timer_loop(), stop.subscribe());
        self.spawn(&mut tasks, "magicdns", engine.clone().dns_loop(), stop.subscribe());
        let mut graceful = JoinSet::new();
        self.spawn(&mut graceful, "helper-role", crate::helper_role::run(engine.clone(), helper_dir(&self.opts.state_dir, p), stop.subscribe()), stop.subscribe());
        self.spawn(&mut tasks, "discovery", engine.clone().discovery_loop(stun), stop.subscribe());
        self.spawn(&mut tasks, "control", control::control_loop(engine.clone(), target, token), stop.subscribe());
        tasks.spawn(self.device_port.run(engine.listen_port(), self.host.hosting.subscribe()));
        // The router's mapping (the hosted network's, or this device's own) is
        // this device's public endpoint
        let (mut public_wg, mut own) = (self.host.public_wg.subscribe(), self.device_port.public.subscribe());
        let e = engine.clone();
        tasks.spawn(async move {
            loop {
                let hosted = *public_wg.borrow_and_update();
                let eps: Vec<std::net::SocketAddr> = hosted.or(*own.borrow_and_update()).into_iter().collect();
                e.set_extra_endpoints(eps);
                tokio::select! {
                    r = public_wg.changed() => if r.is_err() { break },
                    r = own.changed() => if r.is_err() { break },
                }
            }
        });
        // Registering the domain runs system tools, which can take a moment
        let tun = engine.tun_device().0;
        let dns = tokio::task::spawn_blocking(move || crate::magicdns::SystemDns::configure(&tun)).await.ok().flatten();
        let (tun, tun_index) = engine.tun_device();
        // Weak: the session's end must free the engine and its TUN device
        let weak = Arc::downgrade(&engine);
        let userspace: crate::exit::Userspace = Box::new(move |on| match weak.upgrade() {
            Some(engine) => engine.set_userspace_forwarding(on),
            None => Ok(()),
        });
        let gateway = Arc::new(std::sync::Mutex::new(Gateway::new(&tun, tun_index, userspace)));
        // Routes and forwarding follow the netmap: what peers route, and what
        // the server approved for this device
        let mut routes = engine.subscribe_routes();
        let (gw, last_error) = (gateway.clone(), self.last_error.clone());
        tasks.spawn(async move {
            let mut subnets = SubnetRoutes::new(&tun, tun_index);
            loop {
                let state = routes.borrow_and_update().clone();
                let gw = gw.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut g = gw.lock().unwrap();
                    let exit = g.exit();
                    let forwarding = g.set(exit, &state.own).context("routing networks for the mesh");
                    drop(g);
                    let routes = subnets.set(&state.accepted);
                    (forwarding.and(routes), subnets)
                })
                .await;
                let Ok((result, back)) = result else { break };
                subnets = back;
                if let Err(e) = result {
                    tracing::warn!("{e:#}");
                    *last_error.lock().unwrap() = Some(format!("{e:#}"));
                }
                if routes.changed().await.is_err() {
                    break;
                }
            }
        });
        // The server's addresses as it reports them, kept for the next start
        let mut addrs = engine.subscribe_server_addrs();
        let (persisted, state_path) = (self.persisted.clone(), self.state_path.clone());
        tasks.spawn(async move {
            while addrs.changed().await.is_ok() {
                let fresh = addrs.borrow_and_update().clone();
                let mut p = persisted.lock().await;
                if p.server.as_deref() != Some(server.as_str()) {
                    continue;
                }
                let merged = crate::control::merge_alts(&server, &fresh, &p.server_alts);
                if merged != p.server_alts {
                    p.server_alts = merged;
                    p.remember_current();
                    if let Err(e) = p.save(&state_path) {
                        tracing::warn!("saving the server's addresses: {e:#}");
                    }
                }
            }
        });
        // The same for the URLs that forward to it
        let mut fronts = engine.subscribe_server_fronts();
        let (persisted, state_path, server) = (self.persisted.clone(), self.state_path.clone(), p.server.clone());
        tasks.spawn(async move {
            while fronts.changed().await.is_ok() {
                let Some(fresh) = fronts.borrow_and_update().clone() else { continue };
                let mut p = persisted.lock().await;
                if p.server != server || p.server_fronts == fresh {
                    continue;
                }
                p.server_fronts = fresh;
                p.remember_current();
                if let Err(e) = p.save(&state_path) {
                    tracing::warn!("saving the server's addresses: {e:#}");
                }
            }
        });
        let mut session = Session { engine, started: Instant::now(), tasks, graceful, threads, stop, exit_routes: None, gateway, _dns: dns };
        if let Err(e) = apply_exit_prefs(&mut session, &p.prefs) {
            // The mesh still works, so only report the exit-node problem
            tracing::warn!("{e:#}");
            self.set_error(Some(format!("{e:#}")));
        }
        Ok(session)
    }

    /// Runs a data-plane stage on its own OS thread with a single-threaded
    /// runtime, so the stage never migrates between cores and per-thread CPU
    /// in `top -H` maps directly to a stage.
    fn spawn_thread(
        &self,
        name: &'static str,
        fut: DataPlaneTask,
        mut stop: watch::Receiver<bool>,
    ) -> Result<std::thread::JoinHandle<()>> {
        let last_error = self.last_error.clone();
        let failures = self.failures.clone();
        let handle = std::thread::Builder::new()
            .name(format!("retail-{name}"))
            .stack_size(512 * 1024)
            .spawn(move || {
                // Time only, since I/O resources stay on the main runtime's reactor
                let rt = match tokio::runtime::Builder::new_current_thread().enable_time().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        *last_error.lock().unwrap() = Some(format!("{name}: {e}"));
                        let _ = failures.send(name);
                        return;
                    }
                };
                let run = std::panic::AssertUnwindSafe(|| {
                    rt.block_on(async {
                        tokio::select! {
                            r = fut => r.and_then(|()| Err(anyhow::anyhow!("ended without an error"))),
                            r = stop.wait_for(|s| *s) => match r {
                                Ok(_) => Ok(()),
                                Err(_) => Err(anyhow::anyhow!("its session went away")),
                            },
                        }
                    })
                });
                // Stages have died with nothing in the log: say which and how
                let result = std::panic::catch_unwind(run).unwrap_or_else(|p| {
                    let what = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned());
                    Err(anyhow::anyhow!("panicked: {}", what.unwrap_or_default()))
                });
                if let Err(e) = result {
                    // One stage stopping on purpose ends the others' channels
                    if *stop.borrow() {
                        tracing::debug!("{name} stopped with its session: {e:#}");
                        return;
                    }
                    tracing::error!("{name} stopped: {e:#}");
                    *last_error.lock().unwrap() = Some(format!("{name}: {e:#}"));
                    let _ = failures.send(name);
                }
            })
            .with_context(|| format!("starting thread {name}"))?;
        Ok(handle)
    }

    /// Runs a session task, recording its error (if it ever returns one) for `status`
    fn spawn<F>(&self, tasks: &mut JoinSet<()>, name: &'static str, fut: F, stop: watch::Receiver<bool>)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let last_error = self.last_error.clone();
        let failures = self.failures.clone();
        tasks.spawn(async move {
            if let Err(e) = fut.await {
                if *stop.borrow() {
                    tracing::debug!("{name} stopped with its session: {e:#}");
                    return;
                }
                tracing::error!("{name} stopped: {e:#}");
                *last_error.lock().unwrap() = Some(format!("{name}: {e:#}"));
                let _ = failures.send(name);
            }
        });
    }

    pub async fn status(&self) -> StatusResponse {
        let locks = || async { (self.persisted.lock().await, self.session.lock().await) };
        // While a session starts the settings stay locked for seconds; the
        // tray gives up after 3 s and would report retaild as not running
        let (p, session) = match tokio::time::timeout(STATUS_WAIT, locks()).await {
            Ok(l) => l,
            Err(_) => {
                let last = self.last_status.lock().unwrap().clone();
                match last {
                    // The last answer, as reconnecting
                    Some(last) => return StatusResponse { control_connected: false, ..last },
                    None => locks().await,
                }
            }
        };
        let st = self.status_of(&p, session.as_ref());
        *self.last_status.lock().unwrap() = Some(st.clone());
        st
    }

    fn status_of(&self, p: &Persisted, session: Option<&Session>) -> StatusResponse {
        let engine = session.map(|s| &s.engine);
        let state = if p.token.is_none() {
            BackendState::NeedsLogin
        } else if engine.is_some() {
            BackendState::Running
        } else {
            BackendState::Stopped
        };
        let self_node = match (p.ip, p.public_key()) {
            (Some(ip), Some(node_key)) if p.token.is_some() => Some(SelfStatus {
                hostname: p.hostname.clone().unwrap_or_default(),
                ip,
                node_key,
                endpoints: engine.map(|e| e.current_endpoints()).unwrap_or_default(),
                dns_name: engine.map(|e| e.self_dns_name()).unwrap_or_default(),
            }),
            _ => None,
        };
        StatusResponse {
            state,
            server: p.server.clone(),
            control_connected: engine.is_some_and(|e| e.control_connected.load(Ordering::Relaxed)),
            self_node,
            peers: engine.map_or_else(Vec::new, |e| {
                let mut peers = e.peer_status();
                self.usage.record(&peers);
                self.usage.fill(&mut peers);
                peers
            }),
            last_error: self.last_error.lock().unwrap().clone(),
            prefs: Prefs {
                // Without the password: status needs no token
                proxy: p.prefs.proxy.as_deref().map(|u| crate::proxy::Proxy::parse(u).map_or_else(|| u.to_string(), |x| x.label())),
                ..p.prefs.clone()
            },
            memory_peak: crate::memory::peak(),
            control_via: engine.and_then(|e| e.control_via()),
            servers: saved_servers(p),
            update: self.updater.status(),
            key_expires_at: engine.and_then(|e| e.key_state().0),
            key_expired: engine.is_some_and(|e| e.key_state().1),
            problem: engine.filter(|e| !e.control_connected.load(Ordering::Relaxed)).and_then(|e| e.control_problem()),
            router_port: self.device_port.state().filter(|_| engine.is_some() && p.prefs.open_router_port),
            usage_total: Some(self.usage.total()),
            connected_secs: session.map(|s| s.started.elapsed().as_secs()),
        }
    }
}

/// The saved servers for `status`, with the current one marked (and listed
/// even when it was joined before servers were saved)
fn saved_servers(p: &Persisted) -> Vec<retail_proto::api::SavedServer> {
    let current = p.token.as_ref().and(p.server.as_deref());
    let mut out: Vec<_> = p
        .saved
        .iter()
        .map(|s| retail_proto::api::SavedServer {
            server: s.server.clone(),
            ip: if Some(s.server.as_str()) == current { p.ip } else { s.ip },
            current: Some(s.server.as_str()) == current,
        })
        .collect();
    if let Some(cur) = current
        && !out.iter().any(|s| s.current)
    {
        out.insert(0, retail_proto::api::SavedServer { server: cur.to_string(), ip: p.ip, current: true });
    }
    out
}

/// Brings exit-node routing and forwarding in line with `prefs`
fn apply_exit_prefs(s: &mut Session, prefs: &Prefs) -> Result<()> {
    let (tun, tun_index) = s.engine.tun_device();
    s.engine.upload.set_mbit(prefs.upload_limit_mbit);
    s.engine.set_exit_node(prefs.exit_node);
    let mut result = Ok(());
    match (prefs.exit_node.is_some(), s.exit_routes.is_some()) {
        (true, false) => match ClientRoutes::activate(&tun, tun_index) {
            Ok(r) => {
                s.exit_routes = Some(r);
                // Re-pin sockets to the physical interface (Windows/macOS)
                s.engine.refresh_bypass();
                s.engine.control_reset.notify_one();
            }
            Err(e) => {
                // Without the routes traffic keeps its normal path rather than failing closed, so report it
                result = Err(e.context("routing traffic through the exit node"));
            }
        },
        (false, true) => {
            s.exit_routes = None;
            s.engine.refresh_bypass();
            s.engine.control_reset.notify_one();
        }
        _ => {}
    }
    let own = s.engine.subscribe_routes().borrow().own.clone();
    let mut gateway = s.gateway.lock().unwrap();
    if gateway.exit() != prefs.advertise_exit_node
        && let Err(e) = gateway.set(prefs.advertise_exit_node, &own)
        && result.is_ok()
    {
        result = Err(e.context("offering this device as an exit node"));
    }
    s.engine.set_advertise_exit(gateway.exit());
    drop(gateway);
    s.engine.set_advertise_routes(prefs.advertise_routes.clone());
    result
}

/// The helper role's key and link secret, one set per registration: a network
/// this device helped before must not be able to link to it for the next one
fn helper_dir(state_dir: &std::path::Path, p: &Persisted) -> PathBuf {
    let base = state_dir.join("helper-device");
    // Shared by every network before 1.0.4
    let _ = std::fs::remove_dir_all(base.join("tls"));
    let _ = std::fs::remove_file(base.join("helper-secret"));
    let id: String = p.public_key().map(|k| k.0[..8].iter().map(|b| format!("{b:02x}")).collect()).unwrap_or_default();
    base.join(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_registration_has_its_own_helper_identity() {
        let dir = std::path::Path::new("state");
        let (mut a, mut b) = (Persisted::default(), Persisted::default());
        a.ensure_private_key();
        b.ensure_private_key();
        assert_ne!(helper_dir(dir, &a), helper_dir(dir, &b));
        assert_eq!(helper_dir(dir, &a), helper_dir(dir, &a.clone()));
    }

    /// An invite naming this server's address with another pin must not get the stored token
    #[tokio::test]
    async fn stored_token_needs_the_stored_pin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!("retail-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = serde_json::json!({
            "server": format!("https://{addr}"),
            "token": "stored-token",
            "node_id": 5,
            "server_pin": retail_proto::invite::encode_pin(&[7u8; 32]),
        });
        std::fs::write(dir.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
        let b = Backend::new(Options { state_dir: dir.clone(), listen_port: 0, tun_name: None, memory_limit_mb: None }).unwrap();
        let invite = retail_proto::invite::Invite {
            addrs: vec![addr.to_string()],
            pin: Some(retail_proto::invite::encode_pin(&[8u8; 32])),
            key: "other".into(),
            reality: None,
            fronts: vec![],
        }
        .encode();
        let err = b.up(UpRequest { invite: Some(invite), ..Default::default() }).await.unwrap_err();
        assert!(format!("{err:#}").contains("different server key"), "{err:#}");
        let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(accepted.is_err(), "nothing may be sent to a server proving another pin");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
