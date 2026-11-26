//! Router port forwarding for a network hosted here: PCP (RFC 6887) first,
//! then NAT-PMP (RFC 6886), then UPnP IGD. Everything the router sends is untrusted LAN input, so sizes
//! and waits are bounded and parsing is plain string search.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const NATPMP_PORT: u16 = 5351;
const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const MAX_HTTP: usize = 64 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Mappings are renewed at half the lease
pub const LEASE: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn upnp(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    pub proto: Proto,
    pub internal: u16,
    pub external: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Method {
    /// The nonce identifies the mappings for renewal and removal
    Pcp { gateway: Ipv4Addr, nonce: [u8; 12] },
    NatPmp { gateway: Ipv4Addr },
    Upnp { control: String, service: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outcome {
    pub method: Method,
    pub external_ip: Option<IpAddr>,
    pub mappings: Vec<Mapping>,
}

impl Outcome {
    pub fn external(&self, proto: Proto, internal: u16) -> Option<u16> {
        self.mappings.iter().find(|m| m.proto == proto && m.internal == internal).map(|m| m.external)
    }

    pub fn method_name(&self) -> &'static str {
        match self.method {
            Method::Pcp { .. } => "PCP",
            Method::NatPmp { .. } => "NAT-PMP",
            Method::Upnp { .. } => "UPnP",
        }
    }
}

/// Mappings open on the router, kept in a file so that ones a stopped or
/// killed daemon left behind (a router may take only permanent UPnP
/// mappings) are removed when it starts again
static RECORD: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// The ports an outcome is about, which identify it in the record
fn ports_of(o: &Outcome) -> Vec<(Proto, u16)> {
    let mut p: Vec<(Proto, u16)> = o.mappings.iter().map(|m| (m.proto, m.internal)).collect();
    p.sort_by_key(|(proto, port)| (*proto as u8, *port));
    p
}

fn read_record(path: &std::path::Path) -> Vec<Outcome> {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Adds `o` to the record, or with `remove` takes it out
fn note(o: &Outcome, remove: bool) {
    let guard = RECORD.lock().unwrap();
    let Some(path) = guard.as_ref() else { return };
    let mut all = read_record(path);
    all.retain(|x| ports_of(x) != ports_of(o));
    if !remove && !o.mappings.is_empty() {
        all.push(o.clone());
    }
    let result = if all.is_empty() {
        std::fs::remove_file(path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
    } else {
        std::fs::write(path, serde_json::to_vec(&all).unwrap_or_default())
    };
    if let Err(e) = result {
        tracing::debug!("recording port mappings: {e}");
    }
}

/// Keeps the record in `state_dir` and removes what an earlier run left open
pub async fn init(state_dir: &std::path::Path) {
    let path = state_dir.join("portmaps.json");
    let stale = read_record(&path);
    *RECORD.lock().unwrap() = Some(path);
    if stale.is_empty() {
        return;
    }
    tracing::info!("removing {} router port mapping(s) left from the last run", stale.len());
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        for o in &stale {
            close(o).await;
        }
    })
    .await;
}

/// Asks for the same external port as each internal one. Ports after the
/// first `required` are mapped if the router allows, skipped otherwise.
pub async fn open(ports: &[(Proto, u16)], required: usize) -> Result<Outcome> {
    let o = open_new(ports, required).await?;
    note(&o, false);
    Ok(o)
}

async fn open_new(ports: &[(Proto, u16)], required: usize) -> Result<Outcome> {
    let gateway = default_gateway().context("no default gateway")?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    match pcp_open(gateway, nonce, ports, required).await {
        Ok(o) => return Ok(o),
        Err(e) => tracing::debug!("PCP: {e:#}"),
    }
    match natpmp_open(gateway, ports, required).await {
        Ok(o) => return Ok(o),
        Err(e) => tracing::debug!("NAT-PMP: {e:#}"),
    }
    upnp_open(ports, required).await.context("the router answered none of PCP, NAT-PMP and UPnP")
}

/// The router's internet address, asked without opening anything: for a
/// router that maps no ports (UPnP off), whose user forwards them by hand
pub async fn router_ip() -> Option<IpAddr> {
    let gateway = default_gateway()?;
    if let Ok(resp) = natpmp_request(gateway, &[0, 0], 12).await {
        return Some(IpAddr::V4(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11])));
    }
    let (control, service, _) = discover().await.ok()?;
    let body = soap(&control, &service, "GetExternalIPAddress", "").await.ok()?;
    tag(&body, "NewExternalIPAddress").and_then(|s| s.trim().parse().ok())
}

pub async fn renew(outcome: &Outcome, required: usize) -> Result<Outcome> {
    let ports: Vec<(Proto, u16)> = outcome.mappings.iter().map(|m| (m.proto, m.internal)).collect();
    let o = match &outcome.method {
        Method::Pcp { gateway, nonce } => pcp_open(*gateway, *nonce, &ports, required).await,
        Method::NatPmp { gateway } => natpmp_open(*gateway, &ports, required).await,
        Method::Upnp { .. } => upnp_open(&ports, required).await,
    }?;
    note(&o, false);
    Ok(o)
}

pub async fn close(outcome: &Outcome) {
    close_on_router(outcome).await;
    note(outcome, true);
}

async fn close_on_router(outcome: &Outcome) {
    match &outcome.method {
        Method::Pcp { gateway, nonce } => {
            for m in &outcome.mappings {
                let _ = pcp_map(*gateway, *nonce, m.proto, m.internal, m.external, Duration::ZERO).await;
            }
        }
        Method::NatPmp { gateway } => {
            for m in &outcome.mappings {
                let _ = natpmp_map(*gateway, m.proto, m.internal, 0, Duration::ZERO).await;
            }
        }
        Method::Upnp { control, service, .. } => {
            for m in &outcome.mappings {
                let args = format!(
                    "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>{}</NewProtocol>",
                    m.external,
                    m.proto.upnp()
                );
                let _ = soap(control, service, "DeletePortMapping", &args).await;
            }
        }
    }
}

/// Unreachable from the internet. As a router's external address this means
/// it sits behind another NAT (CGNAT, or a second router).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || retail_proto::in_mesh(v4)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// PCP shares NAT-PMP's port; a NAT-PMP-only router answers version 0
async fn pcp_map(
    gateway: Ipv4Addr,
    nonce: [u8; 12],
    proto: Proto,
    internal: u16,
    external: u16,
    lease: Duration,
) -> Result<(u16, IpAddr)> {
    let local = local_ipv4_towards(IpAddr::V4(gateway)).context("no local address towards the router")?;
    let mut req = vec![2, 1, 0, 0];
    req.extend_from_slice(&(lease.as_secs() as u32).to_be_bytes());
    req.extend_from_slice(&local.to_ipv6_mapped().octets());
    req.extend_from_slice(&nonce);
    req.push(match proto {
        Proto::Tcp => 6,
        Proto::Udp => 17,
    });
    req.extend_from_slice(&[0, 0, 0]);
    req.extend_from_slice(&internal.to_be_bytes());
    req.extend_from_slice(&external.to_be_bytes());
    req.extend_from_slice(&Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets());
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((gateway, NATPMP_PORT)).await?;
    let mut buf = [0u8; 1100];
    for wait in [250u64, 500] {
        sock.send(&req).await?;
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(wait), sock.recv(&mut buf)).await else {
            continue;
        };
        if n >= 2 && buf[0] != 2 {
            bail!("the router speaks NAT-PMP, not PCP");
        }
        if n < 60 || buf[1] != 0x81 || buf[24..36] != nonce {
            continue;
        }
        if buf[3] != 0 {
            bail!("PCP error {}", buf[3]);
        }
        let port = u16::from_be_bytes([buf[42], buf[43]]);
        let ip: [u8; 16] = buf[44..60].try_into().unwrap();
        let ip = std::net::Ipv6Addr::from(ip);
        let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
        return Ok((port, ip));
    }
    bail!("no PCP answer from {gateway}")
}

async fn pcp_open(gateway: Ipv4Addr, nonce: [u8; 12], ports: &[(Proto, u16)], required: usize) -> Result<Outcome> {
    let mut mappings = Vec::new();
    let mut external_ip = None;
    for (i, &(proto, internal)) in ports.iter().enumerate() {
        match pcp_map(gateway, nonce, proto, internal, internal, LEASE).await {
            Ok((external, ip)) => {
                external_ip = Some(ip);
                mappings.push(Mapping { proto, internal, external });
            }
            Err(e) if i < required => {
                undo(Outcome { method: Method::Pcp { gateway, nonce }, external_ip, mappings }).await;
                return Err(e);
            }
            Err(e) => tracing::debug!(internal, "optional port not mapped: {e:#}"),
        }
    }
    Ok(Outcome { method: Method::Pcp { gateway, nonce }, external_ip, mappings })
}

async fn natpmp_request(gateway: Ipv4Addr, req: &[u8], expect: usize) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((gateway, NATPMP_PORT)).await?;
    let mut buf = [0u8; 64];
    // RFC 6886 retransmits from 250 ms, doubling, and two tries keep a silent router cheap
    for wait in [250u64, 500] {
        sock.send(req).await?;
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(wait), sock.recv(&mut buf)).await
            && n >= expect
            && buf[0] == 0
            && buf[1] == req[1] | 0x80
        {
            let result = u16::from_be_bytes([buf[2], buf[3]]);
            if result != 0 {
                bail!("NAT-PMP error {result}");
            }
            return Ok(buf[..n].to_vec());
        }
    }
    bail!("no NAT-PMP answer from {gateway}")
}

async fn natpmp_map(gateway: Ipv4Addr, proto: Proto, internal: u16, external: u16, lease: Duration) -> Result<u16> {
    let op = match proto {
        Proto::Udp => 1,
        Proto::Tcp => 2,
    };
    let mut req = vec![0, op, 0, 0];
    req.extend_from_slice(&internal.to_be_bytes());
    req.extend_from_slice(&external.to_be_bytes());
    req.extend_from_slice(&(lease.as_secs() as u32).to_be_bytes());
    let resp = natpmp_request(gateway, &req, 16).await?;
    Ok(u16::from_be_bytes([resp[10], resp[11]]))
}

async fn natpmp_open(gateway: Ipv4Addr, ports: &[(Proto, u16)], required: usize) -> Result<Outcome> {
    let resp = natpmp_request(gateway, &[0, 0], 12).await?;
    let external_ip = IpAddr::V4(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]));
    let mut mappings = Vec::new();
    for (i, &(proto, internal)) in ports.iter().enumerate() {
        match natpmp_map(gateway, proto, internal, internal, LEASE).await {
            Ok(external) => mappings.push(Mapping { proto, internal, external }),
            Err(e) if i < required => {
                undo(Outcome { method: Method::NatPmp { gateway }, external_ip: Some(external_ip), mappings }).await;
                return Err(e);
            }
            Err(e) => tracing::debug!(internal, "optional port not mapped: {e:#}"),
        }
    }
    Ok(Outcome { method: Method::NatPmp { gateway }, external_ip: Some(external_ip), mappings })
}

const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

async fn upnp_open(ports: &[(Proto, u16)], required: usize) -> Result<Outcome> {
    let (control, service, local) = discover().await?;
    let external_ip = soap(&control, &service, "GetExternalIPAddress", "")
        .await
        .ok()
        .and_then(|body| tag(&body, "NewExternalIPAddress").and_then(|s| s.trim().parse().ok()));
    let mut mappings = Vec::new();
    for (i, &(proto, internal)) in ports.iter().enumerate() {
        match upnp_map(&control, &service, local, proto, internal).await {
            Ok(external) => mappings.push(Mapping { proto, internal, external }),
            Err(e) if i < required => {
                undo(Outcome { method: Method::Upnp { control, service }, external_ip, mappings }).await;
                return Err(e);
            }
            Err(e) => tracing::debug!(internal, "optional port not mapped: {e:#}"),
        }
    }
    Ok(Outcome { method: Method::Upnp { control, service }, external_ip, mappings })
}

/// What a failed open got before a required port failed: nothing would
/// close it later (a router may keep UPnP mappings for good)
async fn undo(partial: Outcome) {
    if !partial.mappings.is_empty() {
        close_on_router(&partial).await;
    }
}

async fn upnp_map(control: &str, service: &str, local: Ipv4Addr, proto: Proto, internal: u16) -> Result<u16> {
    let mut lease = LEASE.as_secs();
    let mut last = None;
    for attempt in 0..6u16 {
        // The same port first, then others above the privileged range
        let external = if attempt == 0 { internal } else { 1024 + internal.wrapping_add(attempt * 1000) % 64000 };
        let args = format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external}</NewExternalPort><NewProtocol>{}</NewProtocol>\
             <NewInternalPort>{internal}</NewInternalPort><NewInternalClient>{local}</NewInternalClient>\
             <NewEnabled>1</NewEnabled><NewPortMappingDescription>retail</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>",
            proto.upnp()
        );
        match soap(control, service, "AddPortMapping", &args).await {
            Ok(_) => return Ok(external),
            Err(e) => {
                let msg = format!("{e:#}");
                // 725 means the router only takes permanent mappings
                if msg.contains("725") && lease != 0 {
                    lease = 0;
                    continue;
                }
                last = Some(e);
                // 718 means the external port is in use, and any other error is final
                if !msg.contains("718") {
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("AddPortMapping failed")))
}

/// Returns the WAN connection service's control URL and type, and our LAN address
async fn discover() -> Result<(String, String, Ipv4Addr)> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n\
                  ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    sock.send_to(search.as_bytes(), SSDP).await?;
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let gateway = default_gateway();
    while let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
        // Any device on the LAN can answer; only the router counts
        if gateway.is_some_and(|gw| from.ip() != IpAddr::V4(gw)) {
            continue;
        }
        let text = String::from_utf8_lossy(&buf[..n]);
        let Some(location) = header(&text, "location") else { continue };
        // Only follow descriptions served by the device that answered
        let Some((host, port, path)) = split_http_url(&location) else { continue };
        if host.parse::<IpAddr>().ok() != Some(from.ip()) {
            continue;
        }
        match description(host, port, &path).await {
            Ok((control, service)) => {
                let control = if control.starts_with("http://") { control } else { format!("http://{host}:{port}{}", absolute(&control)) };
                // The control URL may not send us to another host
                if split_http_url(&control).is_none_or(|(h, _, _)| h != host) {
                    continue;
                }
                let local = local_ipv4_towards(from.ip()).context("finding our LAN address")?;
                return Ok((control, service, local));
            }
            Err(e) => tracing::debug!("UPnP description at {location}: {e:#}"),
        }
    }
    bail!("no UPnP router answered")
}

async fn description(host: &str, port: u16, path: &str) -> Result<(String, String)> {
    let body = http(host, port, &format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")).await?;
    for service in SERVICES {
        if let Some(at) = body.find(service) {
            let rest = &body[at..];
            if let Some(control) = tag(rest, "controlURL") {
                return Ok((control.trim().to_string(), service.to_string()));
            }
        }
    }
    bail!("no WAN connection service")
}

async fn soap(control: &str, service: &str, action: &str, args: &str) -> Result<String> {
    let (host, port, path) = split_http_url(control).context("bad control URL")?;
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: \"{service}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http(host, port, &req).await?;
    if let Some(code) = tag(&resp, "errorCode") {
        bail!("UPnP {action} error {}", code.trim());
    }
    Ok(resp)
}

async fn http(host: &str, port: u16, request: &str) -> Result<String> {
    let exchange = async {
        let mut s = TcpStream::connect((host, port)).await?;
        s.write_all(request.as_bytes()).await?;
        let mut raw = Vec::new();
        (&mut s).take(MAX_HTTP as u64).read_to_end(&mut raw).await?;
        anyhow::Ok(raw)
    };
    let raw = tokio::time::timeout(HTTP_TIMEOUT, exchange).await.context("router did not answer")??;
    let resp = crate::http::parse_response(&raw)?;
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    if resp.status >= 400 && !body.contains("errorCode") {
        bail!("HTTP {}", resp.status);
    }
    Ok(body)
}

fn header(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// Content of the first `<name>` element, namespace prefixes allowed
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = xml.find(&format!("{name}>"))?;
    let start = open + name.len() + 1;
    let end = xml[start..].find("</")? + start;
    Some(&xml[start..end])
}

fn absolute(path: &str) -> String {
    if path.starts_with('/') { path.to_string() } else { format!("/{path}") }
}

fn split_http_url(url: &str) -> Option<(&str, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 80),
    };
    Some((host, port, path.to_string()))
}

pub fn local_ipv4_towards(to: IpAddr) -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(to, 9)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub fn default_gateway() -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 2 && f[1] == "00000000" {
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            Some(Ipv4Addr::from(gw.to_le_bytes()))
        } else {
            None
        }
    })
}

#[cfg(target_os = "windows")]
pub fn default_gateway() -> Option<Ipv4Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
    // SAFETY: the row is filled in by the call
    unsafe {
        let mut row: MIB_IPFORWARDROW = std::mem::zeroed();
        let dest = u32::from_ne_bytes([1, 1, 1, 1]);
        if GetBestRoute(dest, 0, &mut row) != 0 {
            return None;
        }
        let gw = Ipv4Addr::from(row.dwForwardNextHop.to_ne_bytes());
        (!gw.is_unspecified()).then_some(gw)
    }
}

#[cfg(target_os = "macos")]
pub fn default_gateway() -> Option<Ipv4Addr> {
    let out = std::process::Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .and_then(|g| g.trim().parse().ok())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn default_gateway() -> Option<Ipv4Addr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mappings a killed daemon left on a (fake) UPnP router are deleted at
    /// the next start, and a clean close leaves nothing recorded
    #[tokio::test]
    async fn stale_mappings_are_removed_at_start() {
        let router = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = format!("http://127.0.0.1:{}/ctl", router.local_addr().unwrap().port());
        let deleted = tokio::spawn(async move {
            let mut got = Vec::new();
            while let Ok(Ok((mut s, _))) = tokio::time::timeout(Duration::from_secs(2), router.accept()).await {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                if req.contains("DeletePortMapping") {
                    got.push(tag(&req, "NewExternalPort").unwrap_or_default().to_string());
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
            got
        });
        let dir = std::env::temp_dir().join(format!("retail-portmap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let left = Outcome {
            method: Method::Upnp { control, service: "urn:schemas-upnp-org:service:WANIPConnection:1".into() },
            external_ip: None,
            mappings: vec![Mapping { proto: Proto::Tcp, internal: 443, external: 443 }, Mapping { proto: Proto::Udp, internal: 3478, external: 3478 }],
        };
        std::fs::write(dir.join("portmaps.json"), serde_json::to_vec(&vec![left.clone()]).unwrap()).unwrap();
        init(&dir).await;
        assert!(!dir.join("portmaps.json").exists(), "the record is cleared once removed");
        assert_eq!(deleted.await.unwrap(), ["443", "3478"]);
        // Recorded while open, gone after a clean close
        note(&left, false);
        assert_eq!(read_record(&dir.join("portmaps.json")).len(), 1);
        note(&left, true);
        assert!(!dir.join("portmaps.json").exists());
        *RECORD.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parsing_router_answers() {
        let ssdp = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n";
        assert_eq!(header(ssdp, "location").as_deref(), Some("http://192.168.1.1:5000/rootDesc.xml"));
        assert_eq!(split_http_url("http://192.168.1.1:5000/ctl/IPConn"), Some(("192.168.1.1", 5000, "/ctl/IPConn".into())));
        assert_eq!(split_http_url("http://10.0.0.1"), Some(("10.0.0.1", 80, "/".into())));
        let xml = "<s:Body><u:R><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:R></s:Body>";
        assert_eq!(tag(xml, "NewExternalIPAddress"), Some("203.0.113.9"));
        assert!(is_private("100.64.1.2".parse().unwrap()), "CGNAT");
        assert!(is_private("192.168.0.1".parse().unwrap()));
        assert!(!is_private("203.0.113.9".parse().unwrap()));
    }
}
