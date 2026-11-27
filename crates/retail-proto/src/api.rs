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
    /// HTTPS URLs that forward to the server (a CDN, or the server's own
    /// internet tunnel, whose address changes). `None` from servers before
    /// 1.0.1, which keeps the ones the invite gave.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_fronts: Option<Vec<String>>,
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
    /// Why the server could not be reached, when that is what failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<FailReason>,
}

/// Why a connection to the server failed, as far as this device can tell
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    /// No answer at all: something drops the traffic, or the server's computer is off
    Timeout,
    /// Nothing listens there (or a firewall says so)
    Refused,
    /// Cut once made, which networks that block VPNs do
    Reset,
    /// The server's name could not be looked up
    Dns,
    /// This device has no route there
    Unreachable,
    /// Something else answered in the server's place (TLS failed)
    Intercepted,
    /// The server turned this device away (HTTP 401/403)
    Rejected,
    /// A proxy wants a sign-in retail cannot give
    ProxyAuth,
    /// The server answered with an error
    ServerError,
    /// Anything else, a newer daemon's reasons included
    #[serde(other)]
    Other,
}

impl FailReason {
    /// In a line, for the command line
    pub fn summary(self) -> &'static str {
        match self {
            FailReason::Timeout => "no answer: the network may block it, or the server is off",
            FailReason::Refused => "refused: is retail running on the server's computer?",
            FailReason::Reset => "cut on the way: the network may block VPN connections",
            FailReason::Dns => "the server's name could not be looked up",
            FailReason::Unreachable => "no route to the server: is this device online?",
            FailReason::Intercepted => "something answered in the server's place (a filtering proxy or a sign-in page)",
            FailReason::Rejected => "the server turned this device away: ask for a new invite",
            FailReason::ProxyAuth => "the network's proxy wants a sign-in (retail set --proxy)",
            FailReason::ServerError => "the server answered with an error",
            FailReason::Other => "could not reach the server",
        }
    }
}

/// The control connection is down, and why
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionProblem {
    pub reason: FailReason,
    /// The error itself, in English
    pub detail: String,
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
    /// The internet tunnel, `None` when off
    #[serde(default)]
    pub tunnel: Option<TunnelStatus>,
    pub nodes: Vec<ServerNode>,
    pub invites: Vec<ServerInvite>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterState {
    /// Ports opened by PCP, NAT-PMP or UPnP; `alt` is the second server port
    Opened {
        method: String,
        tcp: u16,
        udp: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alt: Option<u16>,
        /// WireGuard's, for direct connections to this device
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wg: Option<u16>,
    },
    /// The router did not open them
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerNotice {
    /// The router's own address is private: other networks cannot reach it
    Cgnat { router_ip: std::net::IpAddr },
    /// Ports must be forwarded by hand; `alt` is the second server port
    ForwardPorts {
        tcp: u16,
        udp: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alt: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wg: Option<u16>,
    },
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
    /// The internet tunnel (see [`TunnelStatus`]). `None` keeps the current setting.
    #[serde(default)]
    pub tunnel: Option<bool>,
}

/// The internet tunnel: the server reachable through a Cloudflare quick
/// tunnel, which needs no open port (CGNAT, routers that do not forward)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// `https://….trycloudflare.com` once up; `None` while it starts
    pub url: Option<String>,
    /// Why it is not up
    pub error: Option<String>,
}

/// `POST /server/tunnel`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub on: bool,
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
    /// Why the server cannot be reached, while it cannot
    #[serde(default)]
    pub problem: Option<ConnectionProblem>,
    /// This device's port on the router, while `open_router_port` asks for it
    #[serde(default)]
    pub router_port: Option<PortState>,
    /// Traffic since this device started counting, across restarts
    #[serde(default)]
    pub usage_total: Option<UsageTotal>,
    /// How long this connection has been up
    #[serde(default)]
    pub connected_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageTotal {
    /// Unix seconds when counting began
    pub since: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Time connected, all connections together
    #[serde(default)]
    pub connected_secs: u64,
}

/// This device's WireGuard port on the router
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PortState {
    /// By PCP, NAT-PMP or UPnP, as `port` outside
    Opened { method: String, port: u16 },
    /// The router did not open UDP `port`
    Unavailable { port: u16 },
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
    /// What the installation is doing now
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<UpdateStage>,
    /// While downloading: bytes so far, and in all when the server says
    #[serde(default)]
    pub done_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

/// The steps of installing an update, in order
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStage {
    Downloading,
    /// Comparing with the release's checksums and taking the programs out
    Checking,
    /// Putting the programs in place
    Replacing,
    /// Shutting down to start again as the new version
    Restarting,
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
    /// The proxy was set by an administrator, so on Windows it may be given
    /// the signed-in user's Windows sign-in
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_sign_in: bool,
    /// Install new official releases on their own
    #[serde(default)]
    pub auto_update: bool,
    /// Networks this device offers to route for the others
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<crate::route::Ipv4Net>,
    /// Ask the router to open this device's WireGuard port, for direct
    /// connections from other networks
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open_router_port: bool,
    /// Keeps what this device sends under this many Mbit/s, so a download
    /// through it does not slow everything else (bufferbloat)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_limit_mbit: Option<u32>,
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
    #[serde(default)]
    pub open_router_port: Option<bool>,
    /// 0 turns the upload limit off
    #[serde(default)]
    pub upload_limit_mbit: Option<u32>,
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
    /// Why `path` is what it is
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_reason: Option<PathReason>,
    pub candidates: Vec<SocketAddr>,
    pub last_handshake_secs: Option<u64>,
    /// Offers to route other nodes' internet traffic
    #[serde(default)]
    pub exit_node: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Across restarts, as `usage_total` counts it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tx_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_rx_bytes: Option<u64>,
    #[serde(default)]
    pub dns_name: String,
    /// This device takes only some traffic from it (an access rule)
    #[serde(default)]
    pub restricted: bool,
    /// Networks reached through it
    #[serde(default)]
    pub routes: Vec<crate::route::Ipv4Net>,
    /// Round trip through the tunnel, measured while traffic flows
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// Round trips 2 s apart, oldest first, up to 5 minutes; `u16::MAX` is a
    /// ping with no answer
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rtt_history: Vec<u16>,
}

/// Why a peer is reached directly, through the relay, or not at all
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathReason {
    /// Direct, on the same local network
    Lan,
    /// Direct, across the internet
    Internet,
    /// The peer is not connected to the server
    PeerOffline,
    /// Still trying the first paths
    Connecting,
    /// The direct path went quiet; the relay carries it until UDP answers again
    DirectLost,
    /// Our UDP reaches the peer but its replies do not reach us
    OneWay,
    /// This device learned no public address (UDP to the internet blocked)
    UdpBlockedHere,
    /// The peer offers no public address
    PeerNoAddress,
    /// Both have public addresses, but hole punching got no answer
    PunchFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_stage_is_optional() {
        // What a 1.0.1 daemon sends
        let old: UpdateStatus = serde_json::from_str(
            r#"{"current":"1.0.1","latest":"1.0.2","available":true,"installing":true,"error":null,"supported":true}"#,
        )
        .unwrap();
        assert_eq!((old.stage, old.done_bytes, old.total_bytes), (None, 0, None));
        let new = UpdateStatus { stage: Some(UpdateStage::Downloading), done_bytes: 5, total_bytes: Some(9), ..old };
        let s = serde_json::to_string(&new).unwrap();
        assert!(s.contains(r#""stage":"downloading""#), "{s}");
        assert_eq!(serde_json::from_str::<UpdateStatus>(&s).unwrap(), new);
    }

    #[test]
    fn fail_reasons_are_optional_and_open() {
        let old: ApiError = serde_json::from_str(r#"{"error":"x"}"#).unwrap();
        assert_eq!(old.reason, None);
        // A reason this version does not know
        let new: ApiError = serde_json::from_str(r#"{"error":"x","reason":"solar_flare"}"#).unwrap();
        assert_eq!(new.reason, Some(FailReason::Other));
        let s = serde_json::to_string(&ApiError { error: "x".into(), reason: Some(FailReason::ProxyAuth) }).unwrap();
        assert!(s.contains(r#""reason":"proxy_auth""#), "{s}");
    }

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
            server_fronts: Some(vec!["https://a.trycloudflare.com".into()]),
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
        // None: keep the invite's fronts
        assert!(nm.server_fronts.is_none());
        // And an older client's hostinfo
        let ClientMessage::Hostinfo { routes, .. } = serde_json::from_str(r#"{"type":"hostinfo","exit_node":true}"#).unwrap() else { panic!() };
        assert!(routes.is_empty());
    }
}
