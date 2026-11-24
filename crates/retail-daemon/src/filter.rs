//! What comes in from the mesh, on the receiving side.
//!
//! First by destination: this device takes packets for itself, for the
//! networks it routes (subnet routes), and for the internet while it is an
//! exit node, and nothing else, so a peer cannot use it to reach other
//! networks it happens to be connected to.
//!
//! Then access rules. The netmap says what this device takes from each peer
//! (`Accept`). For a restricted peer, packets that start something are let
//! in only to the allowed ports; replies to what this device sent first always
//! come in, tracked here per flow. Routed networks are reached only by peers
//! with full access to the router, since port rules name devices, not the
//! hosts behind them.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use retail_proto::acl::{Accept, PortRule};
use retail_proto::route::Ipv4Net;

/// This device, as the destination check sees it
pub struct Here<'a> {
    pub ip: Ipv4Addr,
    /// Offers itself as an exit node
    pub exit: bool,
    /// Networks it routes for the others
    pub routes: &'a [Ipv4Net],
}

#[derive(PartialEq, Debug)]
enum Dest {
    Own,
    Subnet,
    Internet,
}

impl Here<'_> {
    fn classify(&self, dst: Ipv4Addr) -> Option<Dest> {
        if dst == self.ip {
            return Some(Dest::Own);
        }
        if self.routes.iter().any(|r| r.contains(dst)) {
            return Some(Dest::Subnet);
        }
        if dst.is_multicast() || dst.is_broadcast() {
            return Some(Dest::Own);
        }
        // Its LAN or public address is this device too
        let own = crate::host::is_own(dst);
        if self.exit && is_internet(dst) && !own {
            return Some(Dest::Internet);
        }
        own.then_some(Dest::Own)
    }
}

/// A flow is forgotten after this long without packets either way
const FLOW_IDLE: Duration = Duration::from_secs(600);
/// Bounds the table per peer; the oldest flows go first when full
const MAX_FLOWS: usize = 16 * 1024;

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

/// (protocol, peer's address, peer's port, our port); ICMP echo uses its id for both ports
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct FlowKey(u8, Ipv4Addr, u16, u16);

#[derive(Default)]
pub struct Filter {
    restricted: AtomicBool,
    ports: RwLock<Vec<PortRule>>,
    flows: Mutex<HashMap<FlowKey, Instant>>,
}

/// The parts of an IPv4 packet the filter looks at
struct Header {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    /// ICMP type, for telling echo requests from replies and errors
    icmp_type: u8,
    /// A fragment after the first: no ports to look at
    later_fragment: bool,
}

fn parse(p: &[u8]) -> Option<Header> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let frag_offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    let mut h = Header { proto, src, dst, sport: 0, dport: 0, icmp_type: 0, later_fragment: frag_offset != 0 };
    if h.later_fragment {
        return Some(h);
    }
    let l4 = p.get(ihl..)?;
    match proto {
        TCP | UDP if l4.len() >= 4 => {
            h.sport = u16::from_be_bytes([l4[0], l4[1]]);
            h.dport = u16::from_be_bytes([l4[2], l4[3]]);
        }
        ICMP if l4.len() >= 8 => {
            h.icmp_type = l4[0];
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            (h.sport, h.dport) = (id, id);
        }
        TCP | UDP | ICMP => return None,
        _ => {}
    }
    Some(h)
}

impl Filter {
    pub fn set(&self, accept: &Accept) {
        match accept {
            Accept::All => {
                self.restricted.store(false, Ordering::Relaxed);
                self.flows.lock().unwrap().clear();
            }
            Accept::Ports { ports } => {
                *self.ports.write().unwrap() = ports.clone();
                self.restricted.store(true, Ordering::Relaxed);
            }
        }
    }

    pub fn restricted(&self) -> bool {
        self.restricted.load(Ordering::Relaxed)
    }

    /// Notes a packet we send to the peer, so its replies come in
    pub fn outbound(&self, p: &[u8]) {
        let Some(h) = parse(p) else { return };
        if h.later_fragment || !matches!(h.proto, TCP | UDP | ICMP) || (h.proto == ICMP && h.icmp_type != 8) {
            return;
        }
        let key = FlowKey(h.proto, h.dst, h.dport, h.sport);
        let mut flows = self.flows.lock().unwrap();
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&key) {
            prune(&mut flows);
        }
        flows.insert(key, Instant::now());
    }

    /// Whether a packet from the peer may come in
    pub fn inbound(&self, p: &[u8], here: &Here) -> bool {
        if p.len() < 20 {
            return false;
        }
        let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
        let restricted = self.restricted();
        // The usual case, quickly
        if dst == here.ip && !restricted {
            return true;
        }
        match here.classify(dst) {
            None => false,
            // Internet traffic through an exit node is not the rules' business
            Some(Dest::Internet) => true,
            Some(Dest::Subnet) => !restricted,
            Some(Dest::Own) => !restricted || self.allowed(p),
        }
    }

    /// Access rules for a restricted peer's packet to this device
    fn allowed(&self, p: &[u8]) -> bool {
        let Some(h) = parse(p) else { return false };
        if h.later_fragment {
            return false;
        }
        let port = if h.proto == ICMP { 0 } else { h.dport };
        // Echo requests are new traffic; echo replies and ICMP errors answer ours
        let new = h.proto != ICMP || h.icmp_type == 8;
        if new && self.ports.read().unwrap().iter().any(|r| r.matches(h.proto, port)) {
            return true;
        }
        match h.proto {
            TCP | UDP => self.reply(FlowKey(h.proto, h.src, h.sport, h.dport)),
            ICMP if h.icmp_type == 0 => self.reply(FlowKey(ICMP, h.src, h.sport, h.dport)),
            // Destination unreachable, time exceeded: about our traffic
            ICMP => matches!(h.icmp_type, 3 | 11) && self.flows.lock().unwrap().keys().any(|k| k.1 == h.src),
            _ => false,
        }
    }

    fn reply(&self, key: FlowKey) -> bool {
        let mut flows = self.flows.lock().unwrap();
        match flows.get_mut(&key) {
            Some(t) if t.elapsed() < FLOW_IDLE => {
                *t = Instant::now();
                true
            }
            _ => false,
        }
    }

    /// Drops idle flows
    pub fn expire(&self) {
        let mut flows = self.flows.lock().unwrap();
        if !flows.is_empty() {
            flows.retain(|_, t| t.elapsed() < FLOW_IDLE);
        }
    }
}

/// A public unicast address: what exit-node traffic is for. Documentation
/// ranges count, since they never reach the real internet anyway and test
/// networks use them.
pub fn is_internet(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
        || retail_proto::in_mesh(ip))
}

/// Makes room: idle flows, then the oldest half
fn prune(flows: &mut HashMap<FlowKey, Instant>) {
    flows.retain(|_, t| t.elapsed() < FLOW_IDLE);
    if flows.len() >= MAX_FLOWS {
        let mut ages: Vec<Instant> = flows.values().copied().collect();
        ages.sort_unstable();
        let cutoff = ages[ages.len() / 2];
        flows.retain(|_, t| *t > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    fn packet(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    fn icmp(ty: u8, src: Ipv4Addr, dst: Ipv4Addr, id: u16) -> Vec<u8> {
        let mut p = packet(ICMP, src, dst, 0, 0);
        p[20] = ty;
        p[24..26].copy_from_slice(&id.to_be_bytes());
        p
    }

    const PLAIN: Here<'static> = Here { ip: ME, exit: false, routes: &[] };
    const EXIT: Here<'static> = Here { ip: ME, exit: true, routes: &[] };

    #[test]
    fn unrestricted_peers_reach_this_device_only() {
        let f = Filter::default();
        assert!(f.inbound(&packet(TCP, PEER, ME, 1000, 22), &PLAIN));
        assert!(f.inbound(&packet(UDP, PEER, Ipv4Addr::new(224, 0, 0, 251), 5353, 5353), &PLAIN));
        // Not a way into other networks, nor to the internet unless an exit node
        let lan = packet(TCP, PEER, Ipv4Addr::new(10, 99, 0, 7), 1000, 22);
        assert!(!f.inbound(&lan, &PLAIN));
        let internet = packet(TCP, PEER, Ipv4Addr::new(8, 8, 8, 8), 40000, 80);
        assert!(!f.inbound(&internet, &PLAIN));
        assert!(f.inbound(&internet, &EXIT));
        assert!(!f.inbound(&lan, &EXIT), "an exit node keeps its private networks to itself");
        // A routed network is reachable
        let routes: [Ipv4Net; 1] = ["10.99.0.0/24".parse().unwrap()];
        let router = Here { ip: ME, exit: false, routes: &routes };
        assert!(f.inbound(&lan, &router));
        assert!(!f.inbound(&packet(TCP, PEER, Ipv4Addr::new(10, 98, 0, 7), 1000, 22), &router));
    }

    #[test]
    fn allowed_ports_and_replies_only() {
        let f = Filter::default();
        f.set(&Accept::Ports { ports: vec![PortRule::parse("tcp:443").unwrap()] });
        assert!(f.inbound(&packet(TCP, PEER, ME, 40000, 443), &PLAIN));
        assert!(!f.inbound(&packet(TCP, PEER, ME, 40000, 22), &PLAIN));
        assert!(!f.inbound(&packet(UDP, PEER, ME, 40000, 443), &PLAIN));
        // We connect to the peer's port 22: its answers come back, others do not
        f.outbound(&packet(TCP, ME, PEER, 50000, 22));
        assert!(f.inbound(&packet(TCP, PEER, ME, 22, 50000), &PLAIN));
        assert!(!f.inbound(&packet(TCP, PEER, ME, 22, 50001), &PLAIN));
        assert!(!f.inbound(&packet(TCP, Ipv4Addr::new(100, 64, 0, 3), ME, 22, 50000), &PLAIN));
        // Pings: ours get answered, theirs are not let in
        f.outbound(&icmp(8, ME, PEER, 7));
        assert!(f.inbound(&icmp(0, PEER, ME, 7), &PLAIN));
        assert!(!f.inbound(&icmp(0, PEER, ME, 8), &PLAIN));
        assert!(!f.inbound(&icmp(8, PEER, ME, 9), &PLAIN));
        // Internet traffic through us as an exit node is not ours to filter
        let internet = packet(TCP, PEER, Ipv4Addr::new(8, 8, 8, 8), 40000, 80);
        assert!(f.inbound(&internet, &EXIT));
        assert!(!f.inbound(&internet, &PLAIN), "not an exit node: no internet traffic either");
        // Broadcast and other mesh addresses are not let in on the side
        for dst in [Ipv4Addr::new(192, 168, 1, 10), Ipv4Addr::new(255, 255, 255, 255), Ipv4Addr::new(224, 0, 0, 251), Ipv4Addr::new(100, 64, 0, 9)] {
            assert!(!f.inbound(&packet(UDP, PEER, dst, 40000, 5353), &EXIT), "{dst}");
        }
        // Routed networks only for peers with full access
        let routes: [Ipv4Net; 1] = ["10.99.0.0/24".parse().unwrap()];
        let router = Here { ip: ME, exit: false, routes: &routes };
        assert!(!f.inbound(&packet(TCP, PEER, Ipv4Addr::new(10, 99, 0, 7), 40000, 443), &router));
        // Garbage and later fragments are dropped
        assert!(!f.inbound(&[0x45, 0, 0], &PLAIN));
        let mut frag = packet(TCP, PEER, ME, 40000, 443);
        frag[7] = 1;
        assert!(!f.inbound(&frag, &PLAIN));
    }

    #[test]
    fn replies_only_and_back_to_all() {
        let f = Filter::default();
        f.set(&Accept::Ports { ports: vec![] });
        assert!(!f.inbound(&icmp(8, PEER, ME, 1), &PLAIN));
        f.set(&Accept::All);
        assert!(f.inbound(&icmp(8, PEER, ME, 1), &PLAIN));
    }
}
