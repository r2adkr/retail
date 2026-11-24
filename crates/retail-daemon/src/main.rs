mod backend;
mod control;
mod crypto;
mod engine;
mod exit;
mod firewall;
mod gro;
mod happy;
mod helper_host;
mod helper_link;
mod host;
mod http;
mod http1;
mod local_api;
mod local_token;
mod memory;
mod portmap;
mod proxy;
mod reality;
mod releases;
mod sspi;
mod state;
mod transport;
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
    #[arg(long, env = "RETAIL_SERVE")]
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
    #[arg(long, env = "RETAIL_HELPER")]
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
    init_logging();
    // rustls refuses to guess a provider when more than one is available
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    if !args.api.ip().is_loopback() {
        tracing::warn!("local API is listening on a non-loopback address; anyone who can reach it controls this node");
    }
    let state_dir = args.state_dir.unwrap_or_else(state::default_state_dir);
    tracing::info!("state directory: {}", state_dir.display());

    let backend = Arc::new(backend::Backend::new(backend::Options {
        state_dir: state_dir.clone(),
        listen_port: args.port,
        tun_name: args.tun_name.or_else(default_tun_name),
        memory_limit_mb: args.memory_limit.filter(|&mb| mb > 0),
    })?);
    backend.spawn_supervisor();
    if let Some(web) = web::start(backend.clone(), state_dir.clone(), args.web_port).await {
        let _ = backend.web.set(web);
    }
    // A network hosted here comes back first so this device can rejoin it
    backend.host.resume(args.port).await;
    if args.serve {
        let req = retail_proto::api::ServerStartRequest {
            join: false,
            port: args.serve_port,
            domain: args.serve_domain.clone(),
            insecure_http: false,
            reality: args.serve_reality.clone(),
            fronts: (!args.serve_front.is_empty()).then(|| args.serve_front.clone()),
            helper: args.serve_helper.clone(),
        };
        if let Err(e) = backend.host.start(&req, args.port).await {
            tracing::error!("could not start the server: {e:#}");
        }
    }
    backend.helper.resume().await;
    if args.helper {
        let req = retail_proto::api::HelperStartRequest { port: None, public: args.helper_public.clone() };
        match backend.helper.start(&req).await {
            Ok(()) => {
                if let Some(code) = backend.helper.status().await.code {
                    tracing::info!("helper code: {code}");
                }
            }
            Err(e) => tracing::error!("could not start the helper node: {e:#}"),
        }
    }
    if let Err(e) = backend.start_if_wanted().await {
        tracing::error!("could not resume session: {e:#}");
    }

    let listener = tokio::net::TcpListener::bind(args.api)
        .await
        .with_context(|| format!("binding local API on {}", args.api))?;
    tracing::info!("local API on http://{}", args.api);

    let shutdown_backend = backend.clone();
    let token = Arc::new(local_token::write_new().context("writing the local API token")?);
    axum::serve(listener, local_api::router(backend, token))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            shutdown_backend.shutdown().await;
        })
        .await?;
    Ok(())
}

/// `RUST_LOG` takes the `target=level,...` form (e.g. `retaild=debug`). The
/// regex-free filter keeps the binary and its resident size small.
fn init_logging() {
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_target("retaild", tracing::Level::INFO));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                .with_writer(std::io::stderr),
        )
        .with(filter)
        .init();
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
