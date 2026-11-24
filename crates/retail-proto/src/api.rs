use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::Key;

/// `POST /api/v1/register`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub auth_key: String,
    /// WireGuard public key
    pub node_key: Key,
    pub hostname: String,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: i64,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    /// Bearer token for `GET /api/v1/poll`. The server stores only its hash.
    pub token: String,
}

/// Sent by the daemon on the poll WebSocket
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// LAN and STUN-discovered addresses of this node
    Endpoints { endpoints: Vec<SocketAddr> },
    /// Sent on every connect
    Hostinfo {
        /// Offers to route other nodes' internet traffic
        #[serde(default)]
        exit_node: bool,
    },
}

/// Sent by the control server on the poll WebSocket
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    NetMap(NetMap),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetMap {
    pub self_node: Node,
    pub peers: Vec<Node>,
    /// `host:port` entries. Empty means the control server's host on port 3478.
    pub stun_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: i64,
    pub hostname: String,
    pub os: String,
    pub node_key: Key,
    pub ip: Ipv4Addr,
    pub endpoints: Vec<SocketAddr>,
    /// Holds a poll connection to the control server
    pub online: bool,
    /// Offers to route other nodes' internet traffic
    #[serde(default)]
    pub exit_node: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// `POST /up`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpRequest {
    /// Base URL such as `https://retail.example.com`. Not needed with an invite.
    #[serde(default)]
    pub server: String,
    /// Required on first login, or to re-register with a different server
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    /// `retail1.…` code carrying server addresses, key pin and auth key
    #[serde(default)]
    pub invite: Option<String>,
}

/// `GET /server`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStatus {
    pub running: bool,
    pub port: Option<u16>,
    /// `ip:port` or domain other networks reach the server at, when known
    pub public: Option<String>,
    pub lan: Vec<String>,
    /// Outcome of router port forwarding, as text for the CLI
    pub port_mapping: Option<String>,
    /// Why devices elsewhere may not reach the server, as text for the CLI
    pub warning: Option<String>,
    /// The same two, for apps that word them themselves
    #[serde(default)]
    pub router: Option<RouterState>,
    #[serde(default)]
    pub notice: Option<ServerNotice>,
    pub domain: Option<String>,
    /// Camouflage website, `None` when REALITY is off
    #[serde(default)]
    pub reality: Option<String>,
    #[serde(default)]
    pub fronts: Vec<String>,
    /// Helper node address and whether the link is up
    #[serde(default)]
    pub helper: Option<String>,
    #[serde(default)]
    pub helper_linked: bool,
    pub nodes: Vec<ServerNode>,
    pub invites: Vec<ServerInvite>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterState {
    /// Ports opened by PCP, NAT-PMP or UPnP
    Opened { method: String, tcp: u16, udp: u16 },
    /// The router did not open them
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerNotice {
    /// The router's own address is private: other networks cannot reach it
    Cgnat { router_ip: std::net::IpAddr },
    /// Ports must be forwarded by hand
    ForwardPorts { tcp: u16, udp: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerNode {
    pub id: i64,
    pub hostname: String,
    pub os: String,
    pub ip: Ipv4Addr,
    pub online: bool,
    pub exit_node: bool,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInvite {
    pub id: i64,
    pub reusable: bool,
    pub used: bool,
    /// `i64::MAX` for a named invite that never expires
    pub expires_at: i64,
    pub created_at: i64,
    /// Named invites are reusable and keep their code for client downloads
    #[serde(default)]
    pub name: Option<String>,
    /// Devices that joined with it
    #[serde(default)]
    pub uses: u64,
}

/// `POST /server/start`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStartRequest {
    /// Also make this device a member of the new network
    #[serde(default = "yes")]
    pub join: bool,
    /// TCP port, 443 when unset
    #[serde(default)]
    pub port: Option<u16>,
    /// Host name pointing at this device (dynamic DNS, for example), used in
    /// invites instead of the router's current public address.
    #[serde(default)]
    pub domain: Option<String>,
    /// Plain HTTP, for tests only
    #[serde(default)]
    pub insecure_http: bool,
    /// REALITY camouflage website (`name` or `name:port`) or `off`. `None`
    /// keeps the current setting.
    #[serde(default)]
    pub reality: Option<String>,
    /// HTTPS URLs of a CDN in front of this server, put in invites. Empty
    /// clears them, `None` keeps the current ones.
    #[serde(default)]
    pub fronts: Option<Vec<String>>,
    /// Helper node code (`retailh1.…`) or `off`. `None` keeps the current one.
    #[serde(default)]
    pub helper: Option<String>,
}

fn yes() -> bool {
    true
}

/// `POST /server/invite`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InviteRequest {
    /// Usable by more than one device
    #[serde(default)]
    pub reusable: bool,
    #[serde(default)]
    pub ttl_hours: Option<u64>,
    /// Creates the named invite, or replaces its code (voiding the old one).
    /// Named invites are reusable and never expire unless `ttl_hours` is set.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteResponse {
    pub code: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    /// No registration yet
    NeedsLogin,
    /// Registered but not connected (`retail down`, or startup failed)
    Stopped,
    /// Data plane up
    Running,
}

/// `GET /status`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub state: BackendState,
    pub server: Option<String>,
    pub control_connected: bool,
    pub self_node: Option<SelfStatus>,
    pub peers: Vec<PeerStatus>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub prefs: Prefs,
    /// Bytes, where the OS reports it
    #[serde(default)]
    pub memory_peak: Option<u64>,
    /// How the control connection reaches the server, such as "HTTPS" or
    /// "REALITY via proxy"
    #[serde(default)]
    pub control_via: Option<String>,
    /// Servers this device has joined, the current one included
    #[serde(default)]
    pub servers: Vec<SavedServer>,
}

/// A server this device has joined and can switch back to without an invite
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SavedServer {
    /// Base URL, which also identifies it
    pub server: String,
    /// This device's address in that network
    pub ip: Option<Ipv4Addr>,
    /// The one in use
    pub current: bool,
}

/// `POST /servers/switch` and `POST /servers/forget`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSelect {
    pub server: String,
}

/// Persisted daemon settings
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Prefs {
    /// Node key of the exit node all internet traffic goes through
    #[serde(default)]
    pub exit_node: Option<Key>,
    #[serde(default)]
    pub advertise_exit_node: bool,
    /// `None` sizes buffers for throughput (about 10 MiB)
    #[serde(default)]
    pub memory_limit_mb: Option<u32>,
    /// Proxy for reaching the server, `http://`, `socks5://` (optionally with
    /// `user:password@`) or `off`. `None` follows the system settings.
    #[serde(default)]
    pub proxy: Option<String>,
}

/// `POST /prefs`. Fields left out stay as they are.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrefsRequest {
    /// Hostname, mesh IP or node key of the exit node. Empty stops using one.
    #[serde(default)]
    pub exit_node: Option<String>,
    #[serde(default)]
    pub advertise_exit_node: Option<bool>,
    /// 0 means automatic
    #[serde(default)]
    pub memory_limit_mb: Option<u32>,
    /// Empty follows the system settings
    #[serde(default)]
    pub proxy: Option<String>,
}

/// `POST /proxy/system`: the proxies the signed-in user's settings choose for
/// the server, sent by the tray app, which sees settings a service does not
/// (Windows per-user proxy and PAC scripts)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SystemProxy {
    /// `http://host:port` or `socks5://host:port`, in order; empty means direct
    pub proxies: Vec<String>,
}

/// `GET /helper`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperStatus {
    pub running: bool,
    pub port: Option<u16>,
    /// Given to the server's host (`retail server start --helper CODE`)
    pub code: Option<String>,
    /// A server is linked
    pub linked: bool,
    pub last_error: Option<String>,
}

/// `POST /helper/start`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperStartRequest {
    /// TCP port, 443 when unset
    #[serde(default)]
    pub port: Option<u16>,
    /// Public `host` or address put in the code, when the machine cannot tell
    #[serde(default)]
    pub public: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfStatus {
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub node_key: Key,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub hostname: String,
    pub ip: Ipv4Addr,
    pub node_key: Key,
    pub online: bool,
    /// Source of the last authenticated packet
    pub endpoint: Option<SocketAddr>,
    /// `"direct <addr>"`, `"relay"`, or `None` while no path is established
    #[serde(default)]
    pub path: Option<String>,
    pub candidates: Vec<SocketAddr>,
    pub last_handshake_secs: Option<u64>,
    /// Offers to route other nodes' internet traffic
    #[serde(default)]
    pub exit_node: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_messages() {
        let m = ClientMessage::Endpoints {
            endpoints: vec!["1.2.3.4:41641".parse().unwrap()],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(s, r#"{"type":"endpoints","endpoints":["1.2.3.4:41641"]}"#);
        assert_eq!(serde_json::from_str::<ClientMessage>(&s).unwrap(), m);

        let node = Node {
            id: 1,
            hostname: "a".into(),
            os: "linux".into(),
            node_key: Key([1; 32]),
            ip: Ipv4Addr::new(100, 64, 0, 1),
            endpoints: vec![],
            online: true,
            exit_node: false,
        };
        let nm = ServerMessage::NetMap(NetMap {
            self_node: node.clone(),
            peers: vec![node],
            stun_servers: vec![],
        });
        let s = serde_json::to_string(&nm).unwrap();
        assert!(s.starts_with(r#"{"type":"net_map""#));
        assert_eq!(serde_json::from_str::<ServerMessage>(&s).unwrap(), nm);
    }
}
