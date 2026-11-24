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
    /// The node's current token, when this key is registered already. A key
    /// alone is public (every member sees it), so it never takes a node over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
        /// Networks it offers to route for the others (subnet routes); they
        /// work once the server's administrator approves them
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        routes: Vec<crate::route::Ipv4Net>,
    },
    /// This node as a helper for the server (asked by `NetMap::helper`):
    /// its helper code once it listens, `None` if it cannot or stopped
    HelperCode { code: Option<String> },
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
    /// The server asks this node to be its helper node (the server cannot be
    /// reached from other networks, and an administrator chose this node)
    #[serde(default)]
    pub helper: bool,
    /// When this node's key expires (unix seconds), `None` for never
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// The key expired: the node is cut off from the others until the
    /// administrator renews it, so `peers` is empty
    #[serde(default)]
    pub expired: bool,
    /// The addresses the server is reachable at now (`host:port`), for
    /// nodes to find it after its public address changes
    #[serde(default)]
    pub server_addrs: Vec<String>,
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
    /// `<name>.retail.internal`, unique in the network
    #[serde(default)]
    pub dns_name: String,
    /// What the netmap's owner accepts from this node
    #[serde(default)]
    pub accept: crate::acl::Accept,
    /// Networks routed through this node (subnet routes), approved and offered
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<crate::route::Ipv4Net>,
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
    /// A member device acting as the helper node
    #[serde(default)]
    pub helper_device: Option<i64>,
    /// The member device's helper is up and linked
    #[serde(default)]
    pub helper_device_linked: bool,
    /// `None`: every device reaches every other
    #[serde(default)]
    pub acl: Option<crate::acl::AclPolicy>,
    /// Device keys expire this many days after joining or renewal
    #[serde(default)]
    pub key_expiry_days: Option<u32>,
    /// Devices not seen for this many days are removed
    #[serde(default)]
    pub remove_inactive_days: Option<u32>,
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
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Networks the device offers to route, while it is connected
    #[serde(default)]
    pub advertised_routes: Vec<crate::route::Ipv4Net>,
    /// Networks the administrator lets it route
    #[serde(default)]
    pub approved_routes: Vec<crate::route::Ipv4Net>,
    /// When its key expires, `None` for never
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub expired: bool,
    /// The invite it joined with, if that invite still exists
    #[serde(default)]
    pub invite_id: Option<i64>,
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
    #[serde(default)]
    pub update: UpdateStatus,
    /// When this device's key expires, `None` for never
    #[serde(default)]
    pub key_expires_at: Option<i64>,
    /// The key expired: the administrator must renew it
    #[serde(default)]
    pub key_expired: bool,
}

/// New official releases, as the daemon sees them
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UpdateStatus {
    /// The daemon's version
    pub current: String,
    /// The newest release found, once checked
    pub latest: Option<String>,
    /// `latest` is newer than `current`
    pub available: bool,
    /// Downloading or replacing the programs right now
    pub installing: bool,
    /// The last check or installation failed
    pub error: Option<String>,
    /// Official builds exist for this system, so it can update itself
    pub supported: bool,
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

/// `POST /server/acl`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclRequest {
    /// `None` lets every device reach every other
    pub acl: Option<crate::acl::AclPolicy>,
}

/// `POST /server/nodes/{id}/tags`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TagsRequest {
    pub tags: Vec<String>,
}

/// `POST /server/nodes/{id}/routes`: the networks it may route
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutesRequest {
    pub routes: Vec<crate::route::Ipv4Net>,
}

/// `POST /server/expiry`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpiryRequest {
    /// `None`: keys never expire
    pub key_expiry_days: Option<u32>,
    /// `None`: inactive devices stay
    pub remove_inactive_days: Option<u32>,
}

/// `POST /server/nodes/{id}/renew`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenewRequest {
    /// The key never expires (instead of the network's usual time)
    #[serde(default)]
    pub never: bool,
}

/// `POST /server/nodes/{id}/delete`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoveRequest {
    /// Also revoke the invite the device joined with, so nobody can join
    /// with it again
    #[serde(default)]
    pub revoke_invite: bool,
}

/// `POST /server/backup`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupRequest {
    /// Encrypts the backup; restoring needs it
    pub passphrase: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupResponse {
    /// The backup file's contents
    pub backup: String,
}

/// `POST /server/restore`, while the server is stopped
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub backup: String,
    pub passphrase: String,
}

/// `POST /server/helper-device`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperDeviceRequest {
    /// The member device to be the helper node, `None` for none
    pub id: Option<i64>,
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
    /// Install new official releases on their own
    #[serde(default)]
    pub auto_update: bool,
    /// Networks this device offers to route for the others
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<crate::route::Ipv4Net>,
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
    #[serde(default)]
    pub auto_update: Option<bool>,
    /// Networks such as `192.168.1.0/24`; empty stops routing any
    #[serde(default)]
    pub advertise_routes: Option<Vec<String>>,
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
    #[serde(default)]
    pub dns_name: String,
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
    #[serde(default)]
    pub dns_name: String,
    /// This device takes only some traffic from it (an access rule)
    #[serde(default)]
    pub restricted: bool,
    /// Networks reached through it
    #[serde(default)]
    pub routes: Vec<crate::route::Ipv4Net>,
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
            dns_name: "a.retail.internal".into(),
            accept: crate::acl::Accept::Ports { ports: vec![crate::acl::PortRule::parse("tcp:22").unwrap()] },
            routes: vec!["192.168.1.0/24".parse().unwrap()],
        };
        let nm = ServerMessage::NetMap(NetMap {
            self_node: node.clone(),
            peers: vec![node],
            stun_servers: vec![],
            helper: false,
            expires_at: Some(1),
            expired: false,
            server_addrs: vec!["203.0.113.1:443".into()],
        });
        let s = serde_json::to_string(&nm).unwrap();
        assert!(s.starts_with(r#"{"type":"net_map""#));
        assert_eq!(serde_json::from_str::<ServerMessage>(&s).unwrap(), nm);

        // A netmap from an older server: everything accepted, no names
        let old = r#"{"type":"net_map","self_node":{"id":1,"hostname":"a","os":"linux","node_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","ip":"100.64.0.1","endpoints":[],"online":true},"peers":[],"stun_servers":[]}"#;
        let ServerMessage::NetMap(nm) = serde_json::from_str::<ServerMessage>(old).unwrap();
        assert_eq!(nm.self_node.accept, crate::acl::Accept::All);
        assert!(!nm.helper);
        assert!(!nm.expired && nm.expires_at.is_none() && nm.server_addrs.is_empty() && nm.self_node.routes.is_empty());
        // And an older client's hostinfo
        let ClientMessage::Hostinfo { routes, .. } = serde_json::from_str(r#"{"type":"hostinfo","exit_node":true}"#).unwrap() else { panic!() };
        assert!(routes.is_empty());
    }
}
