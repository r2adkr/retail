mod tui;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use retail_proto::LOCAL_API_ADDR;
use retail_proto::acl::{AclPolicy, AclRule};
use retail_proto::api::{
    AclRequest, ApiError, BackendState, BackupRequest, BackupResponse, ExpiryRequest, HelperDeviceRequest, RemoveRequest, RenewRequest, RestoreRequest, RoutesRequest, HelperStartRequest, HelperStatus, InviteRequest, InviteResponse, PrefsRequest, ServerSelect, ServerStartRequest, ServerStatus,
    StatusResponse, TagsRequest, UpRequest,
};

#[derive(Parser)]
#[command(name = "retail", version, about = "Control the local retail daemon")]
struct Cli {
    /// Address of the daemon's local API
    #[arg(long, global = true, env = "RETAIL_API", default_value = LOCAL_API_ADDR)]
    api: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register (if needed) and connect to the mesh
    Up {
        /// Control server URL, e.g. https://retail.example.com
        #[arg(long, env = "RETAIL_SERVER", required_unless_present = "invite")]
        server: Option<String>,
        /// Invite code from the device hosting the network (`retail server invite`)
        #[arg(long, conflicts_with_all = ["server", "auth_key"])]
        invite: Option<String>,
        /// Auth key issued by the server. Needed on first login without an invite.
        #[arg(long, env = "RETAIL_AUTH_KEY")]
        auth_key: Option<String>,
        /// Name shown to other nodes. Defaults to the OS hostname.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Disconnect, keeping the registration
    Down,
    /// Disconnect and forget this node's key and registration with the current server
    Logout,
    /// Full-screen terminal view: devices, the server, saved servers
    Tui,
    /// List the servers this device has joined
    Servers,
    /// Leave the current server (it stays saved) and connect to a saved one
    Switch {
        /// The server's URL, or a unique part of it
        server: String,
    },
    /// Remove a saved server (logs out if it is the current one)
    Forget {
        /// The server's URL, or a unique part of it
        server: String,
    },
    /// Show connection state and peers
    Status {
        /// Print raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Print this node's mesh IP
    Ip,
    /// Change settings (only the options given are changed)
    Set {
        /// Send all internet traffic through this device (hostname, mesh IP
        /// or key), or `none` to stop.
        #[arg(long, value_name = "DEVICE|none")]
        exit_node: Option<String>,
        /// Offer this device as an exit node to the others
        #[arg(long, value_name = "true|false", num_args = 0..=1, default_missing_value = "true")]
        advertise_exit_node: Option<bool>,
        /// Memory budget of the daemon in MiB (`auto` for the default).
        /// Lower values use fewer buffers and crypto threads, at some cost in
        /// throughput. Changing it restarts the tunnel.
        #[arg(long, value_name = "MIB|auto")]
        memory_limit: Option<String>,
        /// Proxy for reaching the server: http://[user:password@]host:port,
        /// socks5://…, `off`, or `auto` to follow the system settings
        #[arg(long, value_name = "URL|off|auto")]
        proxy: Option<String>,
        /// Install new official releases on their own
        #[arg(long, value_name = "true|false", num_args = 0..=1, default_missing_value = "true")]
        auto_update: Option<bool>,
        /// Route these networks for the other devices (subnet router, e.g.
        /// 192.168.1.0/24,10.0.0.0/24), once the server's administrator
        /// approves them; `none` stops.
        #[arg(long, value_name = "NETWORKS|none")]
        advertise_routes: Option<String>,
    },
    /// Check for a new release and install it
    Update {
        /// Only check, do not install
        #[arg(long)]
        check: bool,
    },
    /// List devices that offer themselves as exit nodes
    ExitNodes,
    /// Host a network on this device
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Be a helper node: a public machine that makes a server behind CGNAT
    /// reachable from other networks
    Helper {
        #[command(subcommand)]
        cmd: HelperCmd,
    },
}

#[derive(Subcommand)]
enum HelperCmd {
    /// Start, and print the code to give the server's host (`retail server
    /// start --helper CODE`). It starts again with the daemon until stopped.
    Start {
        /// TCP port (default 443)
        #[arg(long)]
        port: Option<u16>,
        /// Public host name or address to put in the code, if this machine
        /// cannot tell (behind a cloud provider's NAT, for example)
        #[arg(long)]
        public: Option<String>,
    },
    Stop,
    Status,
}

#[derive(Subcommand)]
enum ServerCmd {
    /// Start the server (and join it, unless --no-join). It starts again
    /// with the daemon until stopped.
    Start {
        /// TCP port (default 443)
        #[arg(long)]
        port: Option<u16>,
        /// A host name pointing at this device (e.g. dynamic DNS) for invites
        /// to use instead of the current public address.
        #[arg(long)]
        domain: Option<String>,
        /// Do not make this device a member (server-only, e.g. on a VPS).
        #[arg(long)]
        no_join: bool,
        /// Plain HTTP, for tests only
        #[arg(long, hide = true)]
        insecure_http: bool,
        /// Also accept REALITY connections that look like ones to this
        /// website (e.g. www.example.com), for devices whose network blocks
        /// the server. `off` turns it off. Invites made afterwards carry it.
        #[arg(long, value_name = "WEBSITE|off")]
        reality: Option<String>,
        /// HTTPS address of a CDN that forwards to this server (repeatable),
        /// for devices on networks that block its address. `off` clears them.
        #[arg(long, value_name = "URL|off")]
        front: Vec<String>,
        /// Helper node code (`retail helper start` on a public machine), for a
        /// server behind CGNAT. `off` stops using it.
        #[arg(long, value_name = "CODE|off")]
        helper: Option<String>,
    },
    /// Stop the server. Devices stay registered for when it starts again.
    Stop,
    /// Show the server's addresses, devices and invites
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Create an invite code (single-use, valid 24 h)
    Invite {
        /// Let any number of devices join with it
        #[arg(long)]
        reusable: bool,
        /// Validity in hours (a named invite never expires without it)
        #[arg(long)]
        hours: Option<u64>,
        /// A named, reusable invite (e.g. family). Running it again gives the
        /// name a new code and voids the old one; devices that joined stay.
        #[arg(long)]
        name: Option<String>,
    },
    /// Print the current code of a named invite
    Code { id: i64 },
    /// Open the web admin page in this device's browser (a one-time link)
    Web {
        /// Only print the link
        #[arg(long)]
        print: bool,
    },
    /// Remove a device from the network (a lost laptop, say). It needs an
    /// invite to come back.
    Remove {
        /// Device: name, mesh IP or id
        device: String,
        /// Also expire the invite it joined with, so nobody can join with it again
        #[arg(long)]
        revoke_invite: bool,
    },
    /// Let a device route networks for the others (a subnet router). Without
    /// networks, approves all it offers.
    Routes {
        /// Device: name, mesh IP or id
        device: String,
        /// Networks such as 192.168.1.0/24
        networks: Vec<String>,
        /// Stop it routing any
        #[arg(long, conflicts_with = "networks")]
        off: bool,
    },
    /// Device key expiry and the removal of devices not seen for long: show,
    /// or change
    Expiry {
        /// Days a device key lasts after joining or renewal, or `never`
        #[arg(long, value_name = "DAYS|never")]
        keys: Option<String>,
        /// Remove devices not seen for this many days, or `never`
        #[arg(long, value_name = "DAYS|never")]
        inactive: Option<String>,
    },
    /// Give a device's key a new lifetime (also brings back one that expired)
    Renew {
        /// Device: name, mesh IP or id
        device: String,
        /// Its key never expires
        #[arg(long)]
        never: bool,
    },
    /// Save the server's data (devices, invites, rules, keys) to a
    /// passphrase-encrypted file, to move or restore the server
    Backup {
        file: String,
    },
    /// Replace this device's server data with a backup's (the server must be
    /// stopped); then `retail server start`
    Restore {
        file: String,
    },
    /// Revoke an invite (a named one stops working at once)
    Revoke { id: i64 },
    /// Access between devices: show the rules, or change them
    Acl {
        #[command(subcommand)]
        cmd: Option<AclCmd>,
    },
    /// Set a device's tags, which access rules can name (`tag:NAME`). No tags clears them.
    Tag {
        /// Device: name, mesh IP or id
        device: String,
        tags: Vec<String>,
    },
    /// Make a member device the helper node, for a server other networks
    /// cannot reach (CGNAT). The device must be reachable from the internet
    /// (a public address, or a router that opens ports). `off` stops it.
    HelperDevice {
        /// Device: name, mesh IP or id, or `off`
        device: String,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Allow FROM to reach TO (selectors: `*`, `tag:NAME`, a device name, IP or id).
    /// The first rule turns access control on: devices then reach only what a rule allows.
    Allow {
        #[arg(long, required = true, num_args = 1..)]
        from: Vec<String>,
        #[arg(long, required = true, num_args = 1..)]
        to: Vec<String>,
        /// Ports: `22`, `tcp:443`, `udp:5000-5100`, `icmp`, `*` (default: all)
        #[arg(long, num_args = 1..)]
        ports: Vec<String>,
    },
    /// Remove rule number N (as `retail server acl` lists them)
    Remove { n: usize },
    /// Replace the policy with a JSON file (`-` reads standard input)
    Set { file: String },
    /// Turn access control off: every device reaches every other
    Off,
}

struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    async fn call<T: serde::de::DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> Result<T> {
        let mut req = req.header("X-Retail-Local", "1");
        if let Some(token) = retail_proto::local::read_token() {
            req = req.header(retail_proto::local::TOKEN_HEADER, token);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("cannot reach retaild at {} (is it running?)", self.base))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let msg = resp.json::<ApiError>().await.map(|e| e.error).unwrap_or_default();
            bail!("{msg} ({status})");
        }
        Ok(resp.json().await?)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.call(self.http.get(format!("{}{path}", self.base))).await
    }

    /// Changes carry invite codes, passwords and backups, so they go only to
    /// the real daemon, not a program that took its port while it was down.
    /// From an administrator/root, they carry the administrator token too.
    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(&self, path: &str, body: Option<&T>) -> Result<R> {
        if let Ok(addr) = self.base.trim_start_matches("http://").parse::<std::net::SocketAddr>() {
            retail_proto::local::check_listener(addr).map_err(anyhow::Error::msg)?;
        }
        let mut req = self.http.post(format!("{}{path}", self.base));
        if let Some(admin) = retail_proto::local::read_admin_token() {
            req = req.header(retail_proto::local::ADMIN_HEADER, admin);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        self.call(req).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client {
        http: reqwest::Client::new(),
        base: format!("http://{}", cli.api),
    };

    match cli.cmd {
        Cmd::Up { server, invite, auth_key, hostname } => {
            let req = UpRequest { server: server.unwrap_or_default(), auth_key, hostname, invite };
            let st: StatusResponse = client.post("/up", Some(&req)).await?;
            print_status(&st);
        }
        Cmd::Down => print_status(&client.post::<(), StatusResponse>("/down", None).await?),
        Cmd::Logout => {
            client.post::<(), StatusResponse>("/logout", None).await?;
            println!("logged out");
        }
        Cmd::Tui => tui::run(&client).await?,
        Cmd::Servers => {
            let st: StatusResponse = client.get("/status").await?;
            if st.servers.is_empty() {
                println!("no saved servers");
            }
            for s in &st.servers {
                let ip = s.ip.map(|ip| ip.to_string()).unwrap_or_default();
                println!("{} {:<40} {ip}", if s.current { "*" } else { " " }, s.server);
            }
        }
        Cmd::Switch { server } => {
            let server = saved_server(&client, &server).await?;
            let st: StatusResponse = client.post("/servers/switch", Some(&ServerSelect { server })).await?;
            print_status(&st);
        }
        Cmd::Forget { server } => {
            let server = saved_server(&client, &server).await?;
            client.post::<_, StatusResponse>("/servers/forget", Some(&ServerSelect { server: server.clone() })).await?;
            println!("forgot {server}");
        }
        Cmd::Status { json } => {
            let st: StatusResponse = client.get("/status").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&st)?);
            } else {
                print_status(&st);
            }
        }
        Cmd::Ip => match client.get::<StatusResponse>("/status").await?.self_node {
            Some(n) => println!("{}", n.ip),
            None => bail!("not logged in"),
        },
        Cmd::Update { check } => {
            let st: StatusResponse = client.post::<(), _>("/update/check", None).await?;
            let u = &st.update;
            match (&u.latest, u.available) {
                (Some(latest), true) if !check => {
                    let st: StatusResponse = client.post::<(), _>("/update/install", None).await?;
                    if st.update.installing {
                        println!("installing retail {latest}; retaild restarts when it is done");
                    }
                }
                (Some(latest), true) => println!("retail {latest} is available (this is {}); `retail update` installs it", u.current),
                _ => println!("retail {} is the newest version", u.current),
            }
        }
        Cmd::Set { exit_node, advertise_exit_node, memory_limit, proxy, auto_update, advertise_routes } => {
            let advertise_routes = advertise_routes.map(|r| if r.trim() == "none" { Vec::new() } else { vec![r] });
            let memory_limit_mb = match memory_limit.as_deref() {
                None => None,
                Some("auto") | Some("0") => Some(0),
                Some(v) => Some(v.parse::<u32>().context("--memory-limit takes a number of MiB or `auto`")?),
            };
            let named_proxy = proxy.as_deref().is_some_and(|p| !matches!(p.trim(), "" | "auto" | "off" | "none" | "direct"));
            let req = PrefsRequest { exit_node, advertise_exit_node, memory_limit_mb, proxy, auto_update, advertise_routes };
            let st = client.post::<_, StatusResponse>("/prefs", Some(&req)).await?;
            print_status(&st);
            if cfg!(windows) && named_proxy && !st.prefs.proxy_sign_in {
                eprintln!("note: set from an administrator terminal, the proxy may also be given your Windows sign-in (NTLM/Kerberos)");
            }
        }
        Cmd::ExitNodes => {
            let st: StatusResponse = client.get("/status").await?;
            let exits: Vec<_> = st.peers.iter().filter(|p| p.exit_node).collect();
            if exits.is_empty() {
                println!("no device offers itself as an exit node");
            }
            for p in exits {
                let used = st.prefs.exit_node == Some(p.node_key);
                println!("{:<16} {:<20} {}{}", p.ip.to_string(), p.hostname, if p.online { "online" } else { "offline" }, if used { "  (in use)" } else { "" });
            }
        }
        Cmd::Server { cmd } => server(&client, cmd).await?,
        Cmd::Helper { cmd } => {
            let st: HelperStatus = match cmd {
                HelperCmd::Start { port, public } => {
                    client.post("/helper/start", Some(&HelperStartRequest { port, public })).await?
                }
                HelperCmd::Stop => client.post::<(), _>("/helper/stop", None).await?,
                HelperCmd::Status => client.post::<(), _>("/helper/status", None).await?,
            };
            if !st.running {
                println!("helper:  not running (retail helper start)");
            } else {
                println!("helper:  running on port {}", st.port.unwrap_or(0));
                println!("server:  {}", if st.linked { "linked" } else { "not linked yet" });
                if let Some(code) = &st.code {
                    println!("code:    {code}");
                    println!("         on the server's host: retail server start --helper {code}");
                }
            }
            if let Some(e) = &st.last_error {
                println!("error:   {e}");
            }
        }
    }
    Ok(())
}

async fn server(client: &Client, cmd: ServerCmd) -> Result<()> {
    let st: ServerStatus = match cmd {
        ServerCmd::Start { port, domain, no_join, insecure_http, reality, front, helper } => {
            let fronts = match front.as_slice() {
                [] => None,
                [off] if off == "off" => Some(Vec::new()),
                _ => Some(front),
            };
            let req = ServerStartRequest { join: !no_join, port, domain, insecure_http, reality, fronts, helper };
            client.post("/server/start", Some(&req)).await?
        }
        ServerCmd::Stop => client.post::<(), _>("/server/stop", None).await?,
        ServerCmd::Status { json } => {
            let st: ServerStatus = client.get("/server").await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&st)?);
                return Ok(());
            }
            st
        }
        ServerCmd::Invite { reusable, hours, name } => {
            let req = InviteRequest { reusable, ttl_hours: hours, name };
            let inv: InviteResponse = client.post("/server/invite", Some(&req)).await?;
            println!("{}", inv.code);
            eprintln!("On the other device: retail up --invite <code>  (or paste it in Settings)");
            return Ok(());
        }
        ServerCmd::Web { print } => {
            let r: serde_json::Value = client.post::<(), _>("/web/login", None).await?;
            let url = r["url"].as_str().context("no link in the answer")?.to_string();
            anyhow::ensure!(
                retail_proto::local::is_local_web_link(&url),
                "the answer on the local API port is not a link to this device's web page; is retaild the program listening there?"
            );
            // The browser gets a private page that posts the sign-in, so the
            // link is not on its command line for other users to see
            let opened = !print && retail_proto::local::sign_in_page(&url).is_ok_and(|page| open_browser(&page.display().to_string()));
            if !opened {
                println!("{url}");
                eprintln!("Open the link above in a browser on this device (valid once, for 2 minutes).");
            }
            return Ok(());
        }
        ServerCmd::Code { id } => {
            let inv: InviteResponse = client.post::<(), _>(&format!("/server/invites/{id}/code"), None).await?;
            println!("{}", inv.code);
            return Ok(());
        }
        ServerCmd::Remove { device, revoke_invite } => {
            let current: ServerStatus = client.get("/server").await?;
            let id = find_device(&current, &device)?;
            client.post(&format!("/server/nodes/{id}/delete"), Some(&RemoveRequest { revoke_invite })).await?
        }
        ServerCmd::Routes { device, networks, off } => {
            let current: ServerStatus = client.get("/server").await?;
            let id = find_device(&current, &device)?;
            let node = current.nodes.iter().find(|n| n.id == id).context("no such device")?;
            let routes = if off {
                Vec::new()
            } else if networks.is_empty() {
                if node.advertised_routes.is_empty() {
                    bail!("{} offers no networks (on it: retail set --advertise-routes 192.168.1.0/24)", node.hostname);
                }
                let mut all = node.approved_routes.clone();
                all.extend(node.advertised_routes.iter().filter(|r| !node.approved_routes.contains(r)));
                all
            } else {
                retail_proto::route::parse_routes(&networks).map_err(anyhow::Error::msg)?
            };
            client.post(&format!("/server/nodes/{id}/routes"), Some(&RoutesRequest { routes })).await?
        }
        ServerCmd::Renew { device, never } => {
            let current: ServerStatus = client.get("/server").await?;
            let id = find_device(&current, &device)?;
            client.post(&format!("/server/nodes/{id}/renew"), Some(&RenewRequest { never })).await?
        }
        ServerCmd::Expiry { keys, inactive } => {
            let current: ServerStatus = client.get("/server").await?;
            if keys.is_none() && inactive.is_none() {
                print_expiry(&current);
                return Ok(());
            }
            let days = |v: Option<String>, cur: Option<u32>| -> Result<Option<u32>> {
                match v.as_deref().map(str::trim) {
                    None => Ok(cur),
                    Some("never") | Some("off") => Ok(None),
                    Some(d) => Ok(Some(d.parse().context("days are a number, or `never`")?)),
                }
            };
            let req = ExpiryRequest {
                key_expiry_days: days(keys, current.key_expiry_days)?,
                remove_inactive_days: days(inactive, current.remove_inactive_days)?,
            };
            let st: ServerStatus = client.post("/server/expiry", Some(&req)).await?;
            print_expiry(&st);
            return Ok(());
        }
        ServerCmd::Backup { file } => {
            if std::path::Path::new(&file).exists() {
                bail!("{file} exists already; choose another name");
            }
            let passphrase = passphrase(true)?;
            let r: BackupResponse = client.post("/server/backup", Some(&BackupRequest { passphrase })).await?;
            write_private(&file, r.backup.as_bytes())?;
            println!("saved the server's backup to {file}");
            eprintln!("Keep the file and its passphrase safe: together they let anyone pose as this server.");
            return Ok(());
        }
        ServerCmd::Restore { file } => {
            let backup = std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
            let passphrase = passphrase(false)?;
            client.post::<_, ServerStatus>("/server/restore", Some(&RestoreRequest { backup, passphrase })).await?;
            println!("restored the server's data; start it with `retail server start`");
            eprintln!("Stop the old server for good if it still runs: two servers with the same keys confuse the devices.");
            eprintln!("If its address changed and has no domain, give each device a new invite: it keeps its address and name.");
            return Ok(());
        }
        ServerCmd::Revoke { id } => client.post::<(), _>(&format!("/server/invites/{id}/revoke"), None).await?,
        ServerCmd::Tag { device, tags } => {
            let current: ServerStatus = client.get("/server").await?;
            let id = find_device(&current, &device)?;
            client.post(&format!("/server/nodes/{id}/tags"), Some(&TagsRequest { tags })).await?
        }
        ServerCmd::HelperDevice { device } => {
            let current: ServerStatus = client.get("/server").await?;
            let id = if device == "off" { None } else { Some(find_device(&current, &device)?) };
            client.post("/server/helper-device", Some(&HelperDeviceRequest { id })).await?
        }
        ServerCmd::Acl { cmd } => {
            let current: ServerStatus = client.get("/server").await?;
            let acl = match cmd {
                None => {
                    print_acl(&current);
                    return Ok(());
                }
                Some(AclCmd::Off) => None,
                Some(AclCmd::Set { file }) => {
                    let text = if file == "-" {
                        let mut s = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                        s
                    } else {
                        std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?
                    };
                    Some(serde_json::from_str::<AclPolicy>(&text).context("not an access policy (JSON with \"rules\")")?)
                }
                Some(AclCmd::Allow { from, to, ports }) => {
                    let mut acl = current.acl.clone().unwrap_or_default();
                    let sel = |s: &String| selector(&current, s);
                    acl.rules.push(AclRule {
                        from: from.iter().map(sel).collect::<Result<_>>()?,
                        to: to.iter().map(sel).collect::<Result<_>>()?,
                        ports,
                    });
                    Some(acl)
                }
                Some(AclCmd::Remove { n }) => {
                    let mut acl = current.acl.clone().context("access control is off: there are no rules")?;
                    if n == 0 || n > acl.rules.len() {
                        anyhow::bail!("there is no rule {n}");
                    }
                    acl.rules.remove(n - 1);
                    Some(acl)
                }
            };
            let st: ServerStatus = client.post("/server/acl", Some(&AclRequest { acl })).await?;
            print_acl(&st);
            return Ok(());
        }
    };
    print_server(&st);
    Ok(())
}

/// Reads a passphrase without showing it, from `RETAIL_BACKUP_PASSPHRASE` if set
fn passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("RETAIL_BACKUP_PASSPHRASE") {
        return Ok(p);
    }
    let first = read_hidden("Passphrase: ")?;
    if confirm {
        if first.chars().count() < 8 {
            bail!("the passphrase needs at least 8 characters");
        }
        if read_hidden("Again: ")? != first {
            bail!("the passphrases differ");
        }
    }
    Ok(first)
}

fn read_hidden(prompt: &str) -> Result<String> {
    use ratatui::crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
    use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    enable_raw_mode().context("no terminal to type a passphrase in (set RETAIL_BACKUP_PASSPHRASE)")?;
    let mut s = String::new();
    let result = loop {
        match read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => break Err(anyhow::anyhow!("cancelled")),
                KeyCode::Char(c) => s.push(c),
                KeyCode::Backspace => {
                    s.pop();
                }
                KeyCode::Esc => break Err(anyhow::anyhow!("cancelled")),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    let _ = disable_raw_mode();
    eprintln!();
    result.map(|()| s)
}

/// Readable by the owner only, where the system has such permissions
fn write_private(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {path}"))?;
    f.write_all(bytes)?;
    Ok(())
}

fn print_expiry(st: &ServerStatus) {
    let days = |d: Option<u32>| d.map_or("never".to_string(), |d| format!("{d} days"));
    println!("keys:     expire after {} (`retail server renew DEVICE` renews one)", days(st.key_expiry_days));
    println!("inactive: devices not seen for {} are removed", days(st.remove_inactive_days));
}

/// A device by name (`laptop` or `laptop.retail.internal`), mesh IP or id
fn find_device(st: &ServerStatus, device: &str) -> Result<i64> {
    let d = device.trim().to_ascii_lowercase();
    st.nodes
        .iter()
        .find(|n| n.hostname == d || n.dns_name == d || n.dns_name.split('.').next() == Some(d.as_str()) || n.ip.to_string() == d || n.id.to_string() == d)
        .map(|n| n.id)
        .with_context(|| format!("no device {device} (see `retail server status`)"))
}

/// `*` and `tag:` as they are, devices to `id:N`
fn selector(st: &ServerStatus, s: &str) -> Result<String> {
    let s = s.trim();
    if s == "*" || s.starts_with("tag:") || s.starts_with("id:") {
        retail_proto::acl::check_selector(s).map_err(anyhow::Error::msg)?;
        return Ok(s.to_string());
    }
    Ok(format!("id:{}", find_device(st, s)?))
}

fn print_acl(st: &ServerStatus) {
    let Some(acl) = &st.acl else {
        println!("access:  open, every device reaches every other (`retail server acl allow` adds a rule)");
        return;
    };
    let name = |sel: &String| match sel.strip_prefix("id:").and_then(|id| id.parse::<i64>().ok()) {
        Some(id) => st.nodes.iter().find(|n| n.id == id).map_or(sel.clone(), |n| n.hostname.clone()),
        None => sel.clone(),
    };
    println!("access:  only what these rules allow (replies always return)");
    if acl.rules.is_empty() {
        println!("         no rules: devices reach nothing");
    }
    for (i, r) in acl.rules.iter().enumerate() {
        let ports = if r.ports.is_empty() { "all ports".to_string() } else { r.ports.join(", ") };
        println!(
            "{:>4}.  {} -> {}  ({ports})",
            i + 1,
            r.from.iter().map(name).collect::<Vec<_>>().join(", "),
            r.to.iter().map(name).collect::<Vec<_>>().join(", ")
        );
    }
    let tagged: Vec<String> = st.nodes.iter().filter(|n| !n.tags.is_empty()).map(|n| format!("{}: {}", n.hostname, n.tags.join(", "))).collect();
    if !tagged.is_empty() {
        println!("tags:    {}", tagged.join("; "));
    }
}

fn print_server(st: &ServerStatus) {
    if !st.running {
        println!("server:  not running (retail server start)");
        if let Some(e) = &st.last_error {
            println!("error:   {e}");
        }
        return;
    }
    println!("server:  running on port {}", st.port.unwrap_or(0));
    match &st.public {
        Some(p) => println!("public:  {p}"),
        None => println!("public:  unknown"),
    }
    if !st.lan.is_empty() {
        println!("lan:     {}", st.lan.join(", "));
    }
    if let Some(m) = &st.port_mapping {
        println!("router:  {m}");
    }
    if let Some(r) = &st.reality {
        println!("reality: on, looks like {r}");
    }
    if let Some(h) = &st.helper {
        println!("helper:  {h} ({})", if st.helper_linked { "linked" } else { "not linked" });
    }
    if let Some(id) = st.helper_device {
        let name = st.nodes.iter().find(|n| n.id == id).map_or_else(|| format!("#{id}"), |n| n.hostname.clone());
        println!("helper:  device {name} ({})", if st.helper_device_linked { "linked" } else { "not linked yet" });
    }
    if st.acl.is_some() {
        println!("access:  limited by rules (`retail server acl`)");
    }
    if let Some(d) = st.key_expiry_days {
        println!("keys:    expire after {d} days (`retail server expiry`)");
    }
    if let Some(d) = st.remove_inactive_days {
        println!("cleanup: devices not seen for {d} days are removed");
    }
    if !st.fronts.is_empty() {
        println!("cdn:     {}", st.fronts.join(", "));
    }
    if let Some(w) = &st.warning {
        println!("warning: {w}");
    }
    if !st.nodes.is_empty() {
        println!();
        println!("{:<5} {:<16} {:<30} {:<8} STATUS", "ID", "IP", "NAME", "OS");
        for n in &st.nodes {
            let status = if n.online { "online" } else { "offline" };
            let exit = if n.exit_node { " exit node" } else { "" };
            let tags = if n.tags.is_empty() { String::new() } else { format!(" [{}]", n.tags.join(", ")) };
            let name = if n.dns_name.is_empty() { &n.hostname } else { &n.dns_name };
            let key = match (n.expired, n.expires_at) {
                (true, _) => " KEY EXPIRED".to_string(),
                (false, Some(at)) => format!(" key {}d", (at - now_unix()).max(0) / 86_400),
                _ => String::new(),
            };
            let live: Vec<String> = n.advertised_routes.iter().filter(|r| n.approved_routes.contains(r)).map(ToString::to_string).collect();
            let waiting: Vec<String> = n.advertised_routes.iter().filter(|r| !n.approved_routes.contains(r)).map(ToString::to_string).collect();
            let routes = if live.is_empty() { String::new() } else { format!(" routes {}", live.join(",")) };
            println!("{:<5} {:<16} {:<30} {:<8} {status}{exit}{routes}{key}{tags}", n.id, n.ip.to_string(), name, n.os);
            if !waiting.is_empty() {
                println!("      offers {} (approve: retail server routes {})", waiting.join(", "), n.hostname);
            }
        }
    }
    let named: Vec<_> = st.invites.iter().filter(|i| i.name.is_some()).collect();
    if !named.is_empty() {
        println!();
        println!("{:<5} {:<20} {:<6} EXPIRES", "ID", "NAMED INVITE", "USES");
        for i in named {
            let expires = if i.expires_at == i64::MAX { "never".to_string() } else { format!("in {}h", (i.expires_at - now_unix()).max(0) / 3600) };
            println!("{:<5} {:<20} {:<6} {expires}", i.id, i.name.as_deref().unwrap_or(""), i.uses);
        }
    }
    let open: Vec<_> = st.invites.iter().filter(|i| i.name.is_none() && (!i.used || i.reusable)).collect();
    if !open.is_empty() {
        println!();
        println!("invites: {}", open.iter().map(|i| format!("#{}{}", i.id, if i.reusable { " (reusable)" } else { "" })).collect::<Vec<_>>().join(", "));
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[i]) }
}

/// The saved server `name` means: its exact URL, or the one URL containing it
async fn saved_server(client: &Client, name: &str) -> Result<String> {
    let st: StatusResponse = client.get("/status").await?;
    if st.servers.iter().any(|s| s.server == name) {
        return Ok(name.to_string());
    }
    let matches: Vec<&str> = st.servers.iter().map(|s| s.server.as_str()).filter(|s| s.contains(name)).collect();
    match matches[..] {
        [one] => Ok(one.to_string()),
        [] => anyhow::bail!("no saved server matches {name} (see `retail servers`)"),
        _ => anyhow::bail!("{name} matches several saved servers: {}", matches.join(", ")),
    }
}

fn print_status(st: &StatusResponse) {
    let state = match st.state {
        BackendState::NeedsLogin => "needs login (run `retail up --server URL --auth-key KEY`)",
        BackendState::Stopped => "stopped",
        BackendState::Running => "running",
    };
    println!("state:   {state}");
    if let Some(server) = &st.server {
        let conn = match (&st.control_via, st.control_connected) {
            (Some(via), true) => format!("connected, {via}"),
            (_, true) => "connected".to_string(),
            _ => "not connected".to_string(),
        };
        println!("server:  {server} ({conn})");
    }
    if let Some(n) = &st.self_node {
        let name = if n.dns_name.is_empty() { &n.hostname } else { &n.dns_name };
        println!("self:    {} {} key {}", n.ip, name, n.node_key.short());
        if !n.endpoints.is_empty() {
            let eps: Vec<String> = n.endpoints.iter().map(ToString::to_string).collect();
            println!("         endpoints {}", eps.join(", "));
        }
    }
    if let Some(key) = st.prefs.exit_node {
        match st.peers.iter().find(|p| p.node_key == key) {
            Some(p) if p.online && p.exit_node => println!("exit:    {} {} (all internet traffic goes through it)", p.ip, p.hostname),
            Some(p) => println!("exit:    {} {} is OFFLINE: internet traffic is blocked until it returns", p.ip, p.hostname),
            None => println!("exit:    {} is not in the network: internet traffic is blocked (`retail set --exit-node none`)", key.short()),
        }
    }
    if st.prefs.advertise_exit_node {
        println!("offer:   this device is an exit node for the others");
    }
    if !st.prefs.advertise_routes.is_empty() {
        let nets: Vec<String> = st.prefs.advertise_routes.iter().map(ToString::to_string).collect();
        println!("routes:  offers {} (the server's administrator approves them)", nets.join(", "));
    }
    if st.key_expired {
        println!("key:     EXPIRED: this device is cut off until the server's administrator renews it");
    } else if let Some(at) = st.key_expires_at {
        let days = (at - now_unix()).max(0) / 86_400;
        if days < 14 {
            println!("key:     expires in {days} days; the server's administrator can renew it");
        }
    }
    if let Some(proxy) = &st.prefs.proxy {
        // Without the password
        let shown = match proxy.split_once("://").zip(proxy.rsplit_once('@')) {
            Some(((scheme, _), (_, host))) => format!("{scheme}://{host}"),
            None => proxy.clone(),
        };
        println!("proxy:   {shown}");
    }
    match (&st.update.latest, st.update.available, st.update.installing) {
        (Some(latest), _, true) => println!("update:  installing {latest}"),
        (Some(latest), true, false) => println!("update:  {latest} is available (`retail update`)"),
        _ => {}
    }
    if st.prefs.auto_update {
        println!("updates: installed automatically");
    }
    let limit = st.prefs.memory_limit_mb.map_or_else(|| "automatic".to_string(), |mb| format!("{mb} MiB"));
    match st.memory_peak {
        Some(peak) => println!("memory:  peak {}, limit {limit}", human_bytes(peak)),
        None => println!("memory:  limit {limit}"),
    }
    if let Some(e) = &st.last_error {
        println!("error:   {e}");
    }
    if st.peers.is_empty() {
        return;
    }
    println!();
    println!("{:<16} {:<20} {:<8} {:<24} {:<12} TX / RX", "IP", "HOSTNAME", "CONTROL", "PATH", "HANDSHAKE");
    for p in &st.peers {
        let path = match (&p.path, p.endpoint) {
            (Some(path), _) => path.clone(),
            (None, Some(ep)) => format!("direct {ep}"),
            (None, None) if p.candidates.is_empty() => "no endpoints".into(),
            (None, None) => "connecting".into(),
        };
        let hs = p
            .last_handshake_secs
            .map_or_else(|| "-".into(), |s| format!("{s}s ago"));
        println!(
            "{:<16} {:<20} {:<8} {:<24} {:<12} {} / {}",
            p.ip.to_string(),
            {
                let name = if p.dns_name.is_empty() { p.hostname.clone() } else { p.dns_name.trim_end_matches(".retail.internal").to_string() };
                let name = if p.restricted { format!("{name} [limited]") } else { name };
                let name = if p.routes.is_empty() { name } else { format!("{name} [routes]") };
                if p.exit_node { format!("{name} [exit]") } else { name }
            },
            if p.online { "online" } else { "offline" },
            path,
            hs,
            human_bytes(p.tx_bytes),
            human_bytes(p.rx_bytes),
        );
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Opens `url` in the default browser
fn open_browser(url: &str) -> bool {
    let mut cmd = if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().is_ok()
}
