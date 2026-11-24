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

struct Session {
    engine: Arc<Engine>,
    tasks: JoinSet<()>,
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
    /// Set once the web admin page listens
    pub web: std::sync::OnceLock<retail_web::WebAdmin>,
    pub updater: Arc<crate::update::Updater>,
}

const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A session that ran this long before failing resets the restart backoff
const HEALTHY_RUN: Duration = Duration::from_secs(60);

fn default_hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

impl Backend {
    pub fn new(opts: Options) -> Result<Self> {
        let state_path = opts.state_dir.join("state.json");
        let persisted = Persisted::load(&state_path)?;
        crate::proxy::set_preference(persisted.prefs.proxy.as_deref());
        let host = crate::host::Host::new(&opts.state_dir);
        let helper = crate::helper_host::HelperHost::new(&opts.state_dir);
        let updater = Arc::new(crate::update::Updater::new(&opts.state_dir));
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
            web: std::sync::OnceLock::new(),
            updater,
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
                    let p = me.persisted.lock().await;
                    if !(p.want_running && p.token.is_some()) {
                        break;
                    }
                    me.stop_session().await;
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
            && req.auth_key.is_none()
            && let Some(t) = p.target()
        {
            // Keep the pin and addresses from the original invite
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
            let registered = control::register(
                &target,
                &RegisterRequest {
                    auth_key,
                    node_key: Key(PublicKey::from(&secret).to_bytes()),
                    hostname: hostname.clone(),
                    os: std::env::consts::OS.to_string(),
                    // Proves this device is the one registered with the key
                    token: p.token.clone().filter(|_| p.server.as_deref() == Some(server.as_str())),
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
    pub async fn set_prefs(&self, req: PrefsRequest) -> Result<()> {
        let mut p = self.persisted.lock().await;
        let mut session = self.session.lock().await;
        let mut prefs = p.prefs.clone();
        if let Some(name) = req.exit_node.as_deref().map(str::trim) {
            prefs.exit_node = if name.is_empty() || name.eq_ignore_ascii_case("none") {
                None
            } else {
                let engine = &session.as_ref().context("connect first: exit nodes are looked up in the network")?.engine;
                let (key, hostname, offers) = engine.find_peer(name).with_context(|| format!("no device named {name}"))?;
                if !offers {
                    anyhow::bail!("{hostname} does not offer itself as an exit node (on it: retail set --advertise-exit-node)");
                }
                Some(key)
            };
        }
        if let Some(on) = req.advertise_exit_node {
            prefs.advertise_exit_node = on;
        }
        if let Some(routes) = &req.advertise_routes {
            let routes = retail_proto::route::parse_routes(routes).map_err(anyhow::Error::msg)?;
            if !routes.is_empty() && !cfg!(target_os = "linux") {
                anyhow::bail!("routing networks for the mesh is supported on Linux only");
            }
            prefs.advertise_routes = routes;
        }
        if let Some(mb) = req.memory_limit_mb {
            prefs.memory_limit_mb = (mb > 0).then_some(mb);
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
            crate::proxy::set_preference(prefs.proxy.as_deref());
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
        let restart = prefs.memory_limit_mb != p.prefs.memory_limit_mb;
        p.prefs = prefs;
        p.save(&self.state_path)?;
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
        let joined = {
            let p = self.persisted.lock().await;
            p.token.is_some() && own.is_some() && p.server == own
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
            p.node_id
        };
        if let Some(id) = id
            && let Err(e) = self.host.keep_forever(id).await
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

    pub async fn shutdown(&self) {
        self.stop_session().await;
    }

    async fn stop_session(&self) {
        if let Some(mut s) = self.session.lock().await.take() {
            // Wait for every task so the TUN device is released before a new session reuses its name
            let _ = s.stop.send(true);
            s.tasks.shutdown().await;
            for t in s.threads {
                let _ = tokio::task::spawn_blocking(move || t.join()).await;
            }
            drop(s.engine);
            tracing::info!("session stopped");
        }
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
        self.spawn(&mut tasks, "timers", engine.clone().timer_loop());
        self.spawn(&mut tasks, "magicdns", engine.clone().dns_loop());
        self.spawn(&mut tasks, "helper-role", crate::helper_role::run(engine.clone(), self.opts.state_dir.join("helper-device")));
        self.spawn(&mut tasks, "discovery", engine.clone().discovery_loop(stun));
        self.spawn(&mut tasks, "control", control::control_loop(engine.clone(), target, token));
        // While hosting, the router's mapping is this device's public endpoint
        let mut public_wg = self.host.public_wg.subscribe();
        let e = engine.clone();
        tasks.spawn(async move {
            loop {
                let eps: Vec<std::net::SocketAddr> = public_wg.borrow_and_update().iter().copied().collect();
                e.set_extra_endpoints(eps);
                if public_wg.changed().await.is_err() {
                    break;
                }
            }
        });
        // Registering the domain runs system tools, which can take a moment
        let tun = engine.tun_device().0;
        let dns = tokio::task::spawn_blocking(move || crate::magicdns::SystemDns::configure(&tun)).await.ok().flatten();
        let (tun, tun_index) = engine.tun_device();
        let gateway = Arc::new(std::sync::Mutex::new(Gateway::new(&tun, tun_index)));
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
        let mut session = Session { engine, tasks, threads, stop, exit_routes: None, gateway, _dns: dns };
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
                let result = rt.block_on(async {
                    tokio::select! {
                        r = fut => r,
                        _ = stop.wait_for(|s| *s) => Ok(()),
                    }
                });
                if let Err(e) = result {
                    tracing::error!("{name} stopped: {e:#}");
                    *last_error.lock().unwrap() = Some(format!("{name}: {e:#}"));
                    let _ = failures.send(name);
                }
            })
            .with_context(|| format!("starting thread {name}"))?;
        Ok(handle)
    }

    /// Runs a session task, recording its error (if it ever returns one) for `status`
    fn spawn<F>(&self, tasks: &mut JoinSet<()>, name: &'static str, fut: F)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let last_error = self.last_error.clone();
        let failures = self.failures.clone();
        tasks.spawn(async move {
            if let Err(e) = fut.await {
                tracing::error!("{name} stopped: {e:#}");
                *last_error.lock().unwrap() = Some(format!("{name}: {e:#}"));
                let _ = failures.send(name);
            }
        });
    }

    pub async fn status(&self) -> StatusResponse {
        let p = self.persisted.lock().await;
        let session = self.session.lock().await;
        let engine = session.as_ref().map(|s| &s.engine);
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
            peers: engine.map(|e| e.peer_status()).unwrap_or_default(),
            last_error: self.last_error.lock().unwrap().clone(),
            prefs: Prefs {
                // Without the password: status needs no token
                proxy: p.prefs.proxy.as_deref().map(|u| crate::proxy::Proxy::parse(u).map_or_else(|| u.to_string(), |x| x.label())),
                ..p.prefs.clone()
            },
            memory_peak: crate::memory::peak(),
            control_via: engine.and_then(|e| e.control_via()),
            servers: saved_servers(&p),
            update: self.updater.status(),
            key_expires_at: engine.and_then(|e| e.key_state().0),
            key_expired: engine.is_some_and(|e| e.key_state().1),
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
