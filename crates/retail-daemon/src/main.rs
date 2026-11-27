mod backend;
mod backup;
mod control;
mod crypto;
mod device_port;
mod engine;
mod failure;
mod exit;
mod filter;
mod cloudflared;
mod firewall;
mod forward;
mod gro;
mod happy;
mod helper_host;
mod helper_link;
mod helper_role;
mod host;
mod http;
mod http1;
mod local_api;
mod local_token;
mod logfile;
mod ping;
mod magicdns;
mod memory;
mod portmap;
mod proxy;
mod reality;
mod releases;
mod service;
mod shaper;
mod sspi;
mod state;
mod transport;
mod update;
mod usage;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use retail_proto::{DEFAULT_WG_PORT, LOCAL_API_ADDR};

#[derive(Parser)]
#[command(name = "retaild", version, about = "retail node daemon (run as Administrator/root)")]
struct Args {
    #[command(subcommand)]
    cmd: Option<service::Cmd>,
    /// Directory holding state.json (private key and registration)
    #[arg(long, env = "RETAIL_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// UDP port for WireGuard and STUN traffic
    #[arg(long, env = "RETAIL_PORT", default_value_t = DEFAULT_WG_PORT)]
    port: u16,
    /// TUN interface name. macOS always uses utunN.
    #[arg(long, env = "RETAIL_TUN")]
    tun_name: Option<String>,
    /// Local API listen address used by the `retail` CLI. Keep it on loopback.
    #[arg(long, env = "RETAIL_API", default_value = LOCAL_API_ADDR)]
    api: SocketAddr,
    /// Memory limit in MiB, used unless one is set with `retail set
    /// --memory-limit`. Smaller limits mean fewer buffers and crypto threads.
    #[arg(long, env = "RETAIL_MEMORY_LIMIT", value_name = "MIB")]
    memory_limit: Option<u32>,
    /// Host a network from startup without joining it (a server, e.g. in a
    /// container). Same as `retail server start --no-join`, which also persists.
    #[arg(long, env = "RETAIL_SERVE", value_parser = clap::builder::FalseyValueParser::new())]
    serve: bool,
    /// Port of the hosted server
    #[arg(long, env = "RETAIL_SERVE_PORT", requires = "serve")]
    serve_port: Option<u16>,
    /// Host name pointing at this server, used in invites
    #[arg(long, env = "RETAIL_SERVE_DOMAIN", requires = "serve")]
    serve_domain: Option<String>,
    /// REALITY camouflage website for the hosted server (or `off`)
    #[arg(long, env = "RETAIL_SERVE_REALITY", requires = "serve")]
    serve_reality: Option<String>,
    /// HTTPS URL of a CDN in front of the hosted server (repeatable)
    #[arg(long, env = "RETAIL_SERVE_FRONT", requires = "serve", value_delimiter = ',')]
    serve_front: Vec<String>,
    /// Helper node code for the hosted server (or `off`)
    #[arg(long, env = "RETAIL_SERVE_HELPER", requires = "serve")]
    serve_helper: Option<String>,
    /// Port of the web admin page on 127.0.0.1 (and, for allowed devices, on
    /// this device's network address while it hosts). 0 turns it off.
    #[arg(long, env = "RETAIL_WEB_PORT", default_value_t = retail_proto::WEB_ADMIN_PORT)]
    web_port: u16,
    /// Be a helper node from startup, for a server that other networks cannot
    /// reach. Same as `retail helper start`, which also persists.
    #[arg(long, env = "RETAIL_HELPER", value_parser = clap::builder::FalseyValueParser::new())]
    helper: bool,
    /// Public host name or address put in the helper code
    #[arg(long, env = "RETAIL_HELPER_PUBLIC", requires = "helper")]
    helper_public: Option<String>,
}

fn default_tun_name() -> Option<String> {
    if cfg!(target_os = "macos") {
        None
    } else if cfg!(windows) {
        Some("retail".into())
    } else {
        Some("retail0".into())
    }
}

// Two workers cover the control connection, local API and timers because the
// data plane runs on its own threads
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Task Scheduler and launchd keep nothing a service writes to stderr.
    // On Windows a task's stderr is a console nobody sees, so the file is
    // always written there.
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let log_file = (args.cmd.is_none() && (cfg!(windows) || (cfg!(target_os = "macos") && !terminal)))
        .then(|| args.state_dir.clone().unwrap_or_else(state::default_state_dir))
        .and_then(|dir| {
            // Its own folder before anything is written there
            std::fs::create_dir_all(&dir).ok()?;
            state::secure_dir(&dir);
            logfile::LogFile::open(&dir.join("retaild.log"))
        });
    init_logging(log_file);
    // rustls refuses to guess a provider when more than one is available
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(cmd) = args.cmd {
        return service::run(cmd, args.state_dir.as_deref(), args.api);
    }
    if !args.api.ip().is_loopback() {
        tracing::warn!("local API is listening on a non-loopback address; anyone who can reach it controls this node");
    }
    let state_dir = args.state_dir.unwrap_or_else(state::default_state_dir);
    tracing::info!("state directory: {}", state_dir.display());
    // Before anything in it is read: an earlier version (Windows) could leave
    // its files with no one allowed to read them
    if state_dir.is_dir() {
        state::secure_dir(&state_dir);
    }
    #[cfg(target_os = "macos")]
    service::leave_shared_folder();

    let backend = Arc::new(backend::Backend::new(backend::Options {
        state_dir: state_dir.clone(),
        listen_port: args.port,
        tun_name: args.tun_name.or_else(default_tun_name),
        memory_limit_mb: args.memory_limit.filter(|&mb| mb > 0).or_else(|| {
            let small = memory::default_limit_mb();
            if let Some(mb) = small {
                tracing::info!("small machine: data plane sized for {mb} MiB (`retail set --memory-limit` changes it)");
            }
            small
        }),
    })?);
    backend.spawn_supervisor();
    backend.spawn_usage();
    if let Some(web) = web::start(backend.clone(), state_dir.clone(), args.web_port).await {
        let _ = backend.web.set(web);
    }
    // The local API answers first, while what was running before comes back:
    // an installer or the tray app waits for it, and a hosted server, the
    // tunnel and the router's ports can take long to come up
    let listener = tokio::net::TcpListener::bind(args.api)
        .await
        .with_context(|| format!("binding local API on {}", args.api))?;
    tracing::info!("local API on http://{}", args.api);
    let token = Arc::new(local_token::write_new().context("writing the local API token")?);
    let admin = Arc::new(local_token::write_admin().context("writing the administrator token")?);

    let api = args.api;
    let b = backend.clone();
    let dir = state_dir.clone();
    let port = args.port;
    let resume = tokio::spawn(async move {
        // Before anything maps ports again: what a killed daemon left on the router
        portmap::init(&dir).await;
        // A network hosted here comes back first so this device can rejoin it
        b.host.resume(port).await;
        if args.serve {
            let req = retail_proto::api::ServerStartRequest {
                join: false,
                port: args.serve_port,
                domain: args.serve_domain.clone(),
                insecure_http: false,
                reality: args.serve_reality.clone(),
                fronts: (!args.serve_front.is_empty()).then(|| args.serve_front.clone()),
                tunnel: None,
                helper: args.serve_helper.clone(),
            };
            if let Err(e) = b.host.start(&req, port).await {
                tracing::error!("could not start the server: {e:#}");
            }
        }
        b.helper.resume().await;
        if args.helper {
            let req = retail_proto::api::HelperStartRequest { port: None, public: args.helper_public.clone() };
            match b.helper.start(&req).await {
                // The code lets a server use this node: not in the log, which
                // a container's operator tooling may collect and ship elsewhere
                Ok(()) => tracing::info!("helper node running; `retail helper status` prints its code"),
                Err(e) => tracing::error!("could not start the helper node: {e:#}"),
            }
        }
        if let Err(e) = b.start_if_wanted().await {
            tracing::error!("could not resume session: {e:#}");
        }
        b.exempt_own_node().await;
    });

    update::clean_up(&state_dir);
    #[cfg(windows)]
    tokio::task::spawn_blocking(service::update_task);
    update::spawn(backend.clone());
    // Devices learn the hosted server's current addresses, which change
    // with the router's public address or the LAN
    let b = backend.clone();
    tokio::spawn(async move {
        let (mut last, mut ticks) = (None, 0u32);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            // This device's mesh address as soon as it has one (a device
            // that lost the tunnel's address needs it), everything every 30 s
            let ip = b.own_mesh_ip().await;
            ticks += 1;
            if ip != last || ticks % 10 == 0 {
                last = ip;
                b.host.set_mesh_ip(ip);
                b.host.publish_addrs().await;
            }
        }
    });

    let shutdown_backend = backend.clone();
    let updater = backend.updater.clone();
    // The peer's address lets Linux tell who is asking (local_api::local_user)
    let app = local_api::router(backend, token, admin, api).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = shutdown_signal() => {}
                _ = shutdown_backend.updater.restart.notified() => {}
                _ = shutdown_backend.stop_requested.notified() => {}
            }
            tracing::info!("shutting down");
            // Nothing comes back up behind the shutdown
            resume.abort();
            shutdown_backend.shutdown().await;
        })
        .await?;
    if updater.restarting() {
        update::restart_after_exit();
    }
    Ok(())
}

/// `RUST_LOG` takes the `target=level,...` form (e.g. `retaild=debug`). The
/// regex-free filter keeps the binary and its resident size small.
fn init_logging(file: Option<logfile::LogFile>) {
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_target("retaild", tracing::Level::INFO));
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let to_stderr = (file.is_none() || terminal)
        .then(|| tracing_subscriber::fmt::layer().with_ansi(terminal).with_writer(std::io::stderr));
    let to_file = file.map(|f| tracing_subscriber::fmt::layer().with_ansi(false).with_writer(move || f.clone()));
    tracing_subscriber::registry().with(to_stderr).with(to_file).with(filter).init();
    // A panic says where, before the service manager's exit code is all that is left
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("panic: {info}");
        default(info);
    }));
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn serve_flag_from_the_environment() {
        // Containers set these as 1 / 0 as often as true / false
        for (value, want) in [("1", true), ("true", true), ("yes", true), ("0", false), ("false", false), ("no", false)] {
            // SAFETY: the only test that touches this variable
            unsafe { std::env::set_var("RETAIL_SERVE", value) };
            let args = super::Args::try_parse_from(["retaild"]).unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(args.serve, want, "{value}");
        }
        unsafe { std::env::remove_var("RETAIL_SERVE") };
    }
}
