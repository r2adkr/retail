//! Connects the web admin page (`retail_web`) to the daemon and keeps its
//! listeners: loopback always, the mesh address while this device hosts the
//! network, is a member of it, and has allowed at least one device.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use retail_proto::api::{InviteRequest, InviteResponse, ServerStartRequest, ServerStatus};
use retail_web::{BoxFut, ClientSource, WebAdmin};

use crate::backend::Backend;

struct Glue {
    backend: Arc<Backend>,
    state_dir: PathBuf,
}

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

impl retail_web::Backend for Glue {
    fn status(&self) -> BoxFut<'_, ServerStatus> {
        Box::pin(self.backend.server_status())
    }
    fn start(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async {
            let req = ServerStartRequest { join: true, ..Default::default() };
            self.backend.server_start(req).await.map_err(text)
        })
    }
    fn stop(&self) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async { self.backend.server_stop().await.map_err(text) })
    }
    fn invite(&self, req: InviteRequest) -> BoxFut<'_, Result<InviteResponse, String>> {
        Box::pin(async move { self.backend.server_invite(req).await.map_err(text) })
    }
    fn named_code(&self, id: i64) -> BoxFut<'_, Result<String, String>> {
        Box::pin(async move { self.backend.host.named_code(id).await.map_err(text) })
    }
    fn revoke(&self, id: i64) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move { self.backend.host.revoke_invite(id).await.map(|_| ()).map_err(text) })
    }
    fn delete_node(&self, id: i64) -> BoxFut<'_, Result<(), String>> {
        Box::pin(async move {
            self.backend.host.delete_node(id).await.map_err(text)?;
            let _ = self.backend.host.set_web_admin(id, false);
            Ok(())
        })
    }
    fn admins(&self) -> Vec<i64> {
        self.backend.host.web_admins()
    }
    fn set_admin(&self, id: i64, allowed: bool) -> Result<(), String> {
        self.backend.host.set_web_admin(id, allowed).map_err(text)
    }
    fn own_ip(&self) -> BoxFut<'_, Option<Ipv4Addr>> {
        Box::pin(self.backend.own_mesh_ip())
    }
    fn clients(&self) -> Vec<ClientSource> {
        clients(&self.state_dir)
    }
    fn upload_dir(&self, variant: &str) -> Option<PathBuf> {
        STANDARD.contains(&variant).then(|| retail_web::clients_dir(&self.state_dir).join(variant))
    }
    fn fetch_client(&self, variant: &str) -> BoxFut<'_, Result<(), String>> {
        let variant = variant.to_string();
        Box::pin(async move {
            if !STANDARD.contains(&variant.as_str()) {
                return Err("no official build of that client".into());
            }
            let (os, _) = variant.split_once('-').unwrap_or_default();
            // The whole set goes to the clients folder, which wins over this
            // device's own programs when those lack a file
            let dir = retail_web::clients_dir(&self.state_dir).join(&variant);
            crate::releases::fetch(&variant, &wanted(os), &dir).await.map_err(text)
        })
    }
}

fn exe(name: &str, os: &str) -> String {
    if os == "windows" { format!("{name}.exe") } else { name.to_string() }
}

/// The client for one `<os>-<arch>` from the files in `dir`
fn source(id: &str, dir: &Path) -> Option<ClientSource> {
    let (os, arch) = id.split_once('-')?;
    let label = match os {
        "windows" => "Windows",
        "linux" => "Linux",
        "macos" => "macOS",
        _ => return None,
    };
    let label = if arch == "x86_64" || (os == "macos" && arch == "aarch64") { label.to_string() } else { format!("{label} {arch}") };
    let tray = dir.join(exe("retail-tray", os));
    let mut missing = Vec::new();
    if !tray.is_file() {
        missing.push(exe("retail-tray", os));
    }
    let mut files = Vec::new();
    for name in wanted(os).into_iter().skip(1) {
        let path = dir.join(&name);
        if path.is_file() {
            files.push((name, path));
        } else {
            missing.push(name);
        }
    }
    let fetchable = STANDARD.contains(&id) && crate::releases::base().is_some();
    Some(ClientSource { id: id.to_string(), label, os: os.to_string(), tray, files, missing, fetchable })
}

/// The tray first, then what installs next to it
fn wanted(os: &str) -> Vec<String> {
    let mut w = vec![exe("retail-tray", os), exe("retaild", os), exe("retail", os)];
    if os == "windows" {
        w.push("wintun.dll".to_string());
    }
    w
}

/// Always offered, so the page can ask for the files of a missing one
const STANDARD: [&str; 3] = ["windows-x86_64", "linux-x86_64", "macos-aarch64"];

/// This device's own programs, then any in `<state>/clients/<os>-<arch>/`
fn clients(state_dir: &Path) -> Vec<ClientSource> {
    let own_id = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let mut out = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
        && let Some(s) = source(&own_id, &dir)
    {
        out.push(s);
    }
    if let Ok(entries) = std::fs::read_dir(retail_web::clients_dir(state_dir)) {
        let mut extra: Vec<ClientSource> = entries
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| source(&e.file_name().to_string_lossy(), &e.path()))
            .collect();
        extra.sort_by(|a, b| a.id.cmp(&b.id));
        for s in extra {
            // A complete set in the folder replaces this device's own if that lacks files
            match out.iter().position(|o| o.id == s.id) {
                Some(i) if !out[i].missing.is_empty() && s.missing.is_empty() => out[i] = s,
                Some(_) => {}
                None => out.push(s),
            }
        }
    }
    for id in STANDARD {
        if !out.iter().any(|o| o.id == id)
            && let Some(s) = source(id, &retail_web::clients_dir(state_dir).join(id))
        {
            out.push(s);
        }
    }
    let rank = |id: &str| STANDARD.iter().position(|s| *s == id).unwrap_or(STANDARD.len());
    out.sort_by_key(|o| rank(&o.id));
    out
}

/// Starts the loopback listener and the task that opens and closes the mesh
/// one. `port` 0 turns the page off.
pub async fn start(backend: Arc<Backend>, state_dir: PathBuf, port: u16) -> Option<WebAdmin> {
    if port == 0 {
        return None;
    }
    let glue = Arc::new(Glue { backend: backend.clone(), state_dir });
    let web = WebAdmin::new(glue, port);
    match tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await {
        Ok(l) => {
            let w = web.clone();
            tokio::spawn(async move {
                if let Err(e) = w.serve_local(l).await {
                    tracing::warn!("web admin stopped: {e}");
                }
            });
        }
        Err(e) => {
            tracing::warn!("web admin: not listening on 127.0.0.1:{port}: {e}");
            return None;
        }
    }
    let w = web.clone();
    tokio::spawn(async move {
        let mut serving: Option<(Ipv4Addr, tokio::task::JoinHandle<()>)> = None;
        loop {
            let ip = backend.own_mesh_ip().await;
            let wanted = ip.filter(|_| !backend.host.web_admins().is_empty());
            if serving.as_ref().map(|(ip, _)| *ip) != wanted {
                if let Some((_, task)) = serving.take() {
                    task.abort();
                }
                if let Some(ip) = wanted {
                    match tokio::net::TcpListener::bind(SocketAddr::from((ip, port))).await {
                        Ok(l) => {
                            tracing::info!("web admin open to allowed devices at http://{ip}:{port}");
                            let w = w.clone();
                            serving = Some((ip, tokio::spawn(async move {
                                if let Err(e) = w.serve_mesh(l, ip).await {
                                    tracing::warn!("web admin (network) stopped: {e}");
                                }
                            })));
                        }
                        Err(e) => tracing::debug!("web admin: not yet listening on {ip}:{port}: {e}"),
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    Some(web)
}
