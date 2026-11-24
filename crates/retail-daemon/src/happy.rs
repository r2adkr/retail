//! Happy Eyeballs (RFC 8305) TCP connect over every resolved address. Without
//! it a broken IPv6 route (common on home networks) or a dead address stalls
//! the control connection for the OS connect timeout, often 20 s or more,
//! before the next address is tried.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;

const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Last addresses that resolved for each `host:port`, used when a lookup fails.
/// With an exit node DNS goes through the tunnel, and if that path is down the
/// control connection (which carries the relay) must still reach the server.
type Resolved = HashMap<(String, u16), Vec<SocketAddr>>;

static RESOLVED: Mutex<Option<Resolved>> = Mutex::new(None);

async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let key = (host.to_string(), port);
    let looked_up = tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port))).await;
    match looked_up {
        Ok(Ok(addrs)) => {
            let addrs: Vec<SocketAddr> = addrs.collect();
            if !addrs.is_empty() {
                RESOLVED.lock().unwrap().get_or_insert_with(HashMap::new).insert(key, addrs.clone());
            }
            Ok(addrs)
        }
        failed => {
            let cached = RESOLVED.lock().unwrap().as_ref().and_then(|m| m.get(&key).cloned());
            match (cached, failed) {
                (Some(addrs), _) => {
                    tracing::debug!(host, "name lookup failed; using the last known addresses");
                    Ok(addrs)
                }
                (None, Ok(Err(e))) => Err(e),
                (None, _) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("looking up {host} timed out"))),
            }
        }
    }
}

async fn connect_one(addr: SocketAddr) -> io::Result<TcpStream> {
    let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    if let Err(e) = crate::exit::bypass(socket2::SockRef::from(&sock)) {
        tracing::debug!("marking control socket: {e}");
    }
    sock.connect(addr).await
}

pub fn interleave(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Races `host:port` together with `alts`, which are `host:port` strings
pub async fn connect_many(host: &str, port: u16, alts: &[String]) -> io::Result<TcpStream> {
    let mut addrs = Vec::new();
    let mut last_err = None;
    let targets = std::iter::once((host.to_string(), port)).chain(alts.iter().filter_map(|a| split_host_port(a)));
    for (h, p) in targets {
        match resolve(&h, p).await {
            Ok(found) => {
                for a in found {
                    if !addrs.contains(&a) {
                        addrs.push(a);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    if addrs.is_empty() {
        return Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses to connect to")));
    }
    if let Some(prefix) = nat64_prefix().await {
        let synthesized: Vec<SocketAddr> = addrs.iter().filter_map(|a| synthesize(prefix, *a)).collect();
        for a in synthesized {
            if !addrs.contains(&a) {
                addrs.push(a);
            }
        }
    }
    connect_addrs(&interleave(addrs)).await
}

/// NAT64 prefix (RFC 7050) and when it was last looked up
static NAT64: Mutex<Option<(std::time::Instant, Option<[u8; 12]>)>> = Mutex::new(None);
const NAT64_RECHECK: Duration = Duration::from_secs(300);

/// The network's NAT64 /96 prefix, found by resolving `ipv4only.arpa`, which
/// only has IPv4 addresses: a DNS64 resolver answers with synthesized IPv6 ones
pub async fn nat64_prefix() -> Option<[u8; 12]> {
    if let Some((at, p)) = *NAT64.lock().unwrap()
        && at.elapsed() < NAT64_RECHECK
    {
        return p;
    }
    // Only an IPv6-only device needs it, and the lookup loads the system
    // resolver's modules, which cost memory for good
    if has_ipv4() {
        *NAT64.lock().unwrap() = Some((std::time::Instant::now(), None));
        return None;
    }
    let found = match tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host(("ipv4only.arpa", 0))).await {
        Ok(Ok(addrs)) => addrs.into_iter().find_map(|a| match a.ip() {
            std::net::IpAddr::V6(v6) => {
                let o = v6.octets();
                (o[12..] == [192, 0, 0, 170] || o[12..] == [192, 0, 0, 171]).then(|| o[..12].try_into().unwrap())
            }
            _ => None,
        }),
        _ => None,
    };
    if found.is_some() && NAT64.lock().unwrap().is_none_or(|(_, p)| p.is_none()) {
        tracing::info!("IPv6-only network with NAT64; IPv4 addresses are reached through it");
    }
    *NAT64.lock().unwrap() = Some((std::time::Instant::now(), found));
    found
}

/// A usable IPv4 address other than the mesh's
fn has_ipv4() -> bool {
    if_addrs::get_if_addrs().is_ok_and(|ifs| {
        ifs.iter().any(|i| match i.ip() {
            std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !retail_proto::in_mesh(v4),
            _ => false,
        })
    })
}

/// Last known prefix, without looking it up
pub fn nat64_cached() -> Option<[u8; 12]> {
    NAT64.lock().unwrap().and_then(|(_, p)| p)
}

/// The NAT64 address for an IPv4 one
pub fn synthesize(prefix: [u8; 12], addr: SocketAddr) -> Option<SocketAddr> {
    let SocketAddr::V4(v4) = addr else { return None };
    let mut o = [0u8; 16];
    o[..12].copy_from_slice(&prefix);
    o[12..].copy_from_slice(&v4.ip().octets());
    Some(SocketAddr::new(std::net::Ipv6Addr::from(o).into(), v4.port()))
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some((addr.ip().to_string(), addr.port()));
    }
    let (h, p) = s.rsplit_once(':')?;
    Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
}

pub async fn connect_addrs(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses to connect to"));
    }
    let mut attempts: JoinSet<io::Result<TcpStream>> = JoinSet::new();
    let mut pending = addrs.iter().copied();
    let mut last_err = None;
    let start = |attempts: &mut JoinSet<_>, addr: SocketAddr| {
        attempts.spawn(async move {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, connect_one(addr)).await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {addr} timed out"))),
            }
        });
    };
    if let Some(first) = pending.next() {
        start(&mut attempts, first);
    }
    loop {
        tokio::select! {
            done = attempts.join_next() => match done {
                Some(Ok(Ok(stream))) => return Ok(stream), // Dropping the set aborts the rest
                Some(Ok(Err(e))) => {
                    last_err = Some(e);
                    if let Some(addr) = pending.next() {
                        start(&mut attempts, addr);
                    }
                }
                Some(Err(e)) => last_err = Some(io::Error::other(e)),
                None => match pending.next() {
                    Some(addr) => start(&mut attempts, addr),
                    None => return Err(last_err.unwrap_or_else(|| io::Error::other("connection failed"))),
                },
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if pending.len() > 0 => {
                if let Some(addr) = pending.next() {
                    start(&mut attempts, addr);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn interleaves_families_ipv6_first() {
        let a: Vec<SocketAddr> = ["1.1.1.1:1", "2.2.2.2:1", "[::1]:1", "3.3.3.3:1", "[::2]:1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let got: Vec<String> = interleave(a).iter().map(ToString::to_string).collect();
        assert_eq!(got, ["[::1]:1", "1.1.1.1:1", "[::2]:1", "2.2.2.2:1", "3.3.3.3:1"]);
    }

    #[tokio::test]
    async fn a_blackholed_first_address_does_not_stall() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        // 192.0.2.1 (TEST-NET-1) is never routed, so the connect just hangs
        let dead: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let t0 = Instant::now();
        let stream = connect_addrs(&[dead, good]).await.expect("falls through to the working address");
        assert_eq!(stream.peer_addr().unwrap(), good);
        assert!(t0.elapsed() < Duration::from_secs(2), "took {:?}", t0.elapsed());
    }

    #[tokio::test]
    async fn reports_failure_when_nothing_answers() {
        // Port 9 on localhost is refused immediately
        let refused: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(connect_addrs(&[refused]).await.is_err());
    }
}
