//! Throughput comes from batching: Linux TUN offload (TSO reads, GRO writes)
//! and quinn-udp's batched receive and GSO send, so a burst to one peer costs
//! one syscall. Hot-path sends wait for socket space instead of dropping,
//! which pushes back on the TUN queue and lets TCP pace itself.
//!
//! Lock order: `peers` → `Peer::tunn` → `Peer::info`. No std lock is held
//! across an `.await`.

use std::collections::HashMap;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use retail_proto::route::Ipv4Net;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use rand::RngCore;
use retail_proto::api::{NetMap, Node, PeerStatus};
use retail_proto::{Key, TUN_MTU, in_mesh, stun};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tun_rs::AsyncDevice;

const KEEPALIVE_SECS: u16 = 25;
/// After this long without an authenticated packet we stop trusting the
/// learned endpoint and spray all candidates again.
const ENDPOINT_STALE: Duration = Duration::from_secs(20);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(20);
/// Discovery interval until STUN answers, so a public endpoint (what lets
/// peers go direct) is learned soon after UDP is unblocked.
const DISCOVERY_RETRY: Duration = Duration::from_secs(3);
/// While no session exists, the last handshake initiation is re-sent this often
/// (instead of WireGuard's 5 s retry) so NAT holes open within a fraction of a second.
const PUNCH_INTERVAL: Duration = Duration::from_millis(250);
/// boringtun starts a fresh initiation after REKEY_TIMEOUT, so the old one is not re-sent past it
const PUNCH_WINDOW: Duration = Duration::from_secs(5);
/// How long a new path gets to work over UDP alone before the relay joins the
/// race. Short enough to connect within a couple of seconds when UDP is
/// blocked, long enough that a working direct path normally wins outright.
const RELAY_DELAY: Duration = Duration::from_millis(1000);
/// While relayed, how often a keepalive is sent to the direct candidates. One
/// that gets through moves both sides back to the direct path.
const PROBE_INTERVAL: Duration = Duration::from_secs(3);
/// A peer stays on the relay through idle periods (keepalives every 25 s
/// through the relay keep it fresh) instead of flapping back to searching.
const RELAY_STALE: Duration = Duration::from_secs(60);
/// Once the relay has carried a peer, a new search includes it at once
/// instead of giving the direct path its head start again.
const RELAY_REMEMBER: Duration = Duration::from_secs(300);
/// While data is being sent, a direct path that has carried nothing back
/// for this long is treated as lost and traffic fails over. Safe because the
/// receiving side answers data with a keepalive at least every
/// `ACTIVE_KEEPALIVE` (WireGuard's own passive keepalive is 10 s).
const DIRECT_SUSPECT: Duration = Duration::from_secs(3);
/// While receiving data and sending nothing back, send a keepalive this often
const ACTIVE_KEEPALIVE: Duration = Duration::from_secs(1);
/// A peer that keeps sending data through the relay this long after our
/// direct path came up cannot hear us directly (one-way UDP failure).
const RELAY_DATA_GRACE: Duration = Duration::from_secs(2);
/// Relay frames waiting for the control connection, at most about 1 MB
const RELAY_OUT_QUEUE: usize = 16;
/// A relay frame and when it was queued
pub type Queued = (Instant, Vec<u8>);
/// Large frames mean fewer messages, flushes and wakeups per byte: measured
/// against 16 KB, relayed throughput rose about 60% and CPU per byte fell a
/// third. Kept under the protocol's 64 KiB frame limit.
const RELAY_FRAME_BYTES: usize = 60 * 1024;
/// Most time udp-send waits for relay queue room per job. Short waits pace
/// bulk relay traffic without loss. Past this budget relay frames are dropped,
/// so a stalled relay delays direct traffic to other peers by at most this
/// much per job.
const RELAY_JOB_WAIT: Duration = Duration::from_millis(2);
const MAX_PACKET: usize = 65536;
/// Handshake initiations per second that get a Diffie-Hellman without proof
/// of their source address; past it senders must first echo a cookie
const HANDSHAKE_RATE_LIMIT: u64 = 100;
/// boringtun derives session indices as `peer_index << 8 | n`, so peer indices are 24-bit
const INDEX_MASK: u32 = 0x00FF_FFFF;
const SOCKET_BUFFER: usize = 8 << 20;
/// Slots per TUN read: tun-rs needs more than 65535/MTU to split a full TSO
/// super-packet
const TUN_READ: usize = 64;
/// Packets per transmit job, up to two super-packets
const TUN_BATCH: usize = 2 * TUN_READ;
/// Packets per receive batch: about two GRO trains of 64 KB
const RX_BATCH: usize = 128;
/// A batch grows past `RX_BATCH` for a train of small datagrams (TCP
/// acknowledgements can fill 64 KB with hundreds), up to this many
const RX_BATCH_MAX: usize = 1024;
/// Jobs in flight per crypto worker and direction. With 2 the stages starve
/// each other and throughput drops ~30-45% (docs/DESIGN.md §12), so only the
/// smallest memory limits go below 4.
const PIPELINE_DEPTH: usize = 4;
/// recvmmsg slots per call when each slot holds a GRO train of up to 64 KB
const RX_SLOTS_GRO: usize = 8;
/// Memory the daemon needs besides data-plane buffers, on top of what it
/// uses when the data plane starts: control connection, TLS, relay frames.
const MEMORY_OVERHEAD: u64 = 1536 * 1024;
/// How often a process above its memory limit returns freed memory to the OS
const MEMORY_CHECK: Duration = Duration::from_secs(10);
const RX_SLOTS: usize = 32;
const MAX_CRYPTO_WORKERS: usize = 4;
/// Measured +13-16% throughput (docs/DESIGN.md §12) on Linux with TUN offload,
/// UDP GRO (jobs of ~40 packets) and at least 4 cores. Elsewhere jobs can be
/// single packets and a per-packet handoff costs more than it saves, so the
/// default there is 1.
const DEFAULT_CRYPTO_WORKERS: usize = 2;
const ENCRYPT_STAGES: [&str; MAX_CRYPTO_WORKERS] = ["encrypt", "encrypt1", "encrypt2", "encrypt3"];
const DECRYPT_STAGES: [&str; MAX_CRYPTO_WORKERS] = ["decrypt", "decrypt1", "decrypt2", "decrypt3"];
/// Per-packet buffer: MTU plus room for the virtio header and WireGuard overhead
const PKT_BUF: usize = 1536;
const MAX_GSO_BYTES: usize = 64000;
/// Bytes in front of each IP packet handed to tun-rs (the virtio-net header on Linux)
#[cfg(target_os = "linux")]
const TUN_OFFSET: usize = tun_rs::VIRTIO_NET_HDR_LEN;
#[cfg(target_os = "linux")]
const _: () = assert!(TUN_OFFSET == crate::gro::VNET_HDR_LEN);
#[cfg(not(target_os = "linux"))]
const TUN_OFFSET: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Src {
    Udp(SocketAddr),
    /// Through the control server's relay
    Relay,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Route {
    /// A UDP endpoint authenticated recently
    Direct(SocketAddr),
    /// Only the relay has carried authenticated packets recently
    Relay,
    /// Nothing works yet: try every candidate, and the relay too once the
    /// direct attempt has had `RELAY_DELAY` to succeed.
    Search { relay: bool },
}

fn is_handshake_init(p: &[u8]) -> bool {
    p.len() == 148 && p[..4] == [1, 0, 0, 0]
}

/// Receiver session index of a transport-data message
fn data_receiver_index(p: &[u8]) -> Option<u32> {
    if p.len() >= 32 && p[..4] == [4, 0, 0, 0] {
        Some(u32::from_le_bytes([p[4], p[5], p[6], p[7]]))
    } else {
        None
    }
}

struct PeerInfo {
    hostname: String,
    dns_name: String,
    ip: Ipv4Addr,
    online: bool,
    /// The peer offers to route internet traffic
    exit_node: bool,
    candidates: Vec<SocketAddr>,
    endpoint: Option<SocketAddr>,
    /// Last authenticated packet over UDP (from `endpoint`)
    last_rx: Option<Instant>,
    /// Last authenticated packet through the relay
    relay_rx: Option<Instant>,
    /// Since when no path has worked (starts the relay race)
    searching_since: Option<Instant>,
    last_probe: Option<Instant>,
    /// Last handshake initiation we produced, kept for fast re-sends while punching
    last_init: Option<(Vec<u8>, Instant)>,
    /// Data byte counters as last seen by the timer loop, and when they moved
    tx_seen: u64,
    rx_seen: u64,
    tx_at: Option<Instant>,
    rx_at: Option<Instant>,
    keepalive_at: Option<Instant>,
    direct_since: Option<Instant>,
    /// Last data (not keepalives) from the peer over UDP and over the relay
    udp_data_at: Option<Instant>,
    relay_data_at: Option<Instant>,
    /// Set when the direct path was lost while sending. Receiving over UDP
    /// then only proves the peer reaches us, so direct is trusted again only
    /// after a handshake answered over UDP.
    needs_proof: bool,
}

#[derive(PartialEq)]
enum Liveness {
    Fine,
    /// Data arrives and nothing goes back: send a keepalive so the sender
    /// can tell the path works.
    Keepalive,
    /// The direct path went quiet while we were sending: fail over
    Lost,
}

impl PeerInfo {
    fn fresh(&self) -> bool {
        self.last_rx.is_some_and(|t| t.elapsed() < ENDPOINT_STALE)
    }

    fn relay_fresh(&self) -> bool {
        self.relay_rx.is_some_and(|t| t.elapsed() < RELAY_STALE)
    }

    /// The direct endpoint, if it works in both directions as far as we can tell
    fn direct_ok(&self) -> Option<SocketAddr> {
        if self.needs_proof || !self.fresh() {
            return None;
        }
        // Peer data still arriving over the relay, well after our direct path came
        // up and more recently than over UDP, means it cannot hear us directly
        if let (Some(relay), Some(since)) = (self.relay_data_at, self.direct_since)
            && relay > since + RELAY_DATA_GRACE
            && self.udp_data_at.is_none_or(|udp| relay > udp)
        {
            return None;
        }
        self.endpoint
    }

    fn uses_relay(&self) -> bool {
        self.direct_ok().is_none() && (self.relay_fresh() || self.needs_proof)
    }
}

pub struct Peer {
    key: Key,
    index: u32,
    tunn: Mutex<Tunn>,
    info: Mutex<PeerInfo>,
    /// This peer is our selected exit node: packets from it may carry any
    /// internet (non-mesh) source address.
    is_exit: AtomicBool,
    /// What we take from it (access rules)
    filter: crate::filter::Filter,
    /// Networks we reach through it (subnet routes we accepted)
    routes: RwLock<Arc<[Ipv4Net]>>,
}

impl Peer {
    fn route(&self) -> Route {
        let mut info = self.info.lock().unwrap();
        if let Some(ep) = info.direct_ok() {
            return Route::Direct(ep);
        }
        if info.uses_relay() {
            return Route::Relay;
        }
        let since = *info.searching_since.get_or_insert_with(Instant::now);
        let relay_known = info.relay_rx.is_some_and(|t| t.elapsed() < RELAY_REMEMBER);
        Route::Search { relay: relay_known || since.elapsed() >= RELAY_DELAY }
    }

    /// `tx` and `rx` are the session's data byte counters
    fn check_liveness(&self, tx: u64, rx: u64) -> Liveness {
        let mut info = self.info.lock().unwrap();
        let now = Instant::now();
        if tx != info.tx_seen {
            info.tx_seen = tx;
            info.tx_at = Some(now);
        }
        if rx != info.rx_seen {
            info.rx_seen = rx;
            info.rx_at = Some(now);
        }
        let recent = |t: Option<Instant>| t.is_some_and(|t| now.duration_since(t) < ACTIVE_KEEPALIVE);
        let quiet_since = |t: Option<Instant>| t.is_some_and(|t| now.duration_since(t) >= DIRECT_SUSPECT);
        if info.direct_ok().is_some() && recent(info.tx_at) && quiet_since(info.last_rx) {
            tracing::info!(peer = %info.hostname, "direct path lost; failing over to the relay");
            info.last_rx = None;
            // Go straight to the relay since the peer was reachable a moment ago,
            // and trust direct again only after a handshake answered over UDP
            info.needs_proof = true;
            return Liveness::Lost;
        }
        if recent(info.rx_at) && !recent(info.tx_at) && !recent(info.keepalive_at) {
            info.keepalive_at = Some(now);
            return Liveness::Keepalive;
        }
        Liveness::Fine
    }

    fn candidates(&self) -> Vec<SocketAddr> {
        let info = self.info.lock().unwrap();
        let mut v = info.candidates.clone();
        if let Some(ep) = info.endpoint
            && !v.contains(&ep)
        {
            v.push(ep);
        }
        // On an IPv6-only network IPv4 peers are reached through NAT64
        if let Some(prefix) = crate::happy::nat64_cached() {
            let synthesized: Vec<SocketAddr> = v.iter().filter_map(|a| crate::happy::synthesize(prefix, *a)).collect();
            for a in synthesized {
                if !v.contains(&a) {
                    v.push(a);
                }
            }
        }
        v
    }

    fn is_fresh(&self) -> bool {
        self.info.lock().unwrap().direct_ok().is_some()
    }

    /// Records an authenticated packet, `data` meaning it carried an IP packet.
    /// A UDP source becomes the direct endpoint and takes over from the relay
    /// at once. Returns true when this brings a direct path up.
    #[must_use]
    fn mark_rx(&self, src: Src, data: bool) -> bool {
        let mut info = self.info.lock().unwrap();
        let now = Instant::now();
        let mut up = false;
        match src {
            Src::Udp(addr) => {
                if data {
                    info.udp_data_at = Some(now);
                }
                if info.needs_proof {
                    return false; // See `confirm_direct`
                }
                let stale = info.last_rx.is_none_or(|t| now.duration_since(t) >= ENDPOINT_STALE);
                if info.endpoint != Some(addr) || stale {
                    tracing::info!(peer = %info.hostname, src = %addr, "direct path up");
                    info.endpoint = Some(addr);
                    info.direct_since = Some(now);
                    up = true;
                }
                info.last_rx = Some(now);
            }
            Src::Relay => {
                if data {
                    info.relay_data_at = Some(now);
                }
                if !info.relay_fresh() && !info.fresh() {
                    tracing::info!(peer = %info.hostname, "relay path up");
                }
                info.relay_rx = Some(now);
            }
        }
        info.searching_since = None;
        up
    }

    /// Called when a handshake we started over UDP was answered over UDP from
    /// `addr`, which proves the direct path both ways.
    fn confirm_direct(&self, addr: SocketAddr) {
        let mut info = self.info.lock().unwrap();
        let now = Instant::now();
        if info.needs_proof {
            tracing::info!(peer = %info.hostname, src = %addr, "direct path confirmed both ways");
        }
        info.needs_proof = false;
        info.endpoint = Some(addr);
        info.last_rx = Some(now);
        info.direct_since = Some(now);
        info.searching_since = None;
    }

    /// While the peer is reached through the relay, says whether a direct
    /// probe is due (and notes that one is being sent), and whether it must
    /// be a handshake (to prove both directions) rather than a keepalive.
    fn probe_due(&self) -> Option<bool> {
        let mut info = self.info.lock().unwrap();
        if !info.uses_relay() || info.last_probe.is_some_and(|t| t.elapsed() < PROBE_INTERVAL) {
            return None;
        }
        info.last_probe = Some(Instant::now());
        Some(info.needs_proof)
    }

    fn ip(&self) -> Ipv4Addr {
        self.info.lock().unwrap().ip
    }

    fn routes(&self) -> Arc<[Ipv4Net]> {
        self.routes.read().unwrap().clone()
    }

    fn allowed_src<'a>(&self, routes: &'a [Ipv4Net]) -> crate::crypto::AllowedSrc<'a> {
        crate::crypto::AllowedSrc { ip: self.ip(), internet: self.is_exit.load(Ordering::Relaxed), routes }
    }
}

#[derive(Default)]
struct PeerTable {
    by_key: HashMap<Key, Arc<Peer>>,
    by_ip: HashMap<Ipv4Addr, Arc<Peer>>,
    by_index: HashMap<u32, Arc<Peer>>,
    /// Selected exit node if it is in the netmap. Gets every packet for an
    /// address outside the mesh.
    exit: Option<Arc<Peer>>,
    /// Routed networks and their routers, longest prefix first
    routes: Vec<(Ipv4Net, Arc<Peer>)>,
}

impl PeerTable {
    fn routed(&self, dst: Ipv4Addr) -> Option<&Arc<Peer>> {
        self.routes.iter().find(|(r, _)| r.contains(dst)).map(|(_, p)| p)
    }

    fn select_exit(&mut self, key: Option<Key>) {
        for p in self.by_key.values() {
            p.is_exit.store(Some(p.key) == key, Ordering::Relaxed);
        }
        self.exit = key.and_then(|k| self.by_key.get(&k).cloned());
    }
}

pub struct EngineConfig {
    pub private_key: StaticSecret,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub listen_port: u16,
    pub tun_name: Option<String>,
    /// Memory budget in MiB. `None` sizes buffers for throughput.
    pub memory_limit_mb: Option<u32>,
}

/// Data-plane buffer sizing: crypto workers per direction, jobs in flight
/// per worker, receive slots per recvmmsg call.
#[derive(Clone, Copy, Debug, PartialEq)]
struct BufferPlan {
    workers: usize,
    depth: usize,
    rx_slots: usize,
}

impl BufferPlan {
    /// Bytes of buffers this plan allocates (`slot_len`: bytes per receive slot)
    fn bytes(self, slot_len: usize) -> u64 {
        let tx_job = TUN_BATCH * PKT_BUF + TUN_BATCH * (TUN_MTU as usize + crate::crypto::OVERHEAD);
        let rx_batch = RX_BATCH * PKT_BUF;
        let jobs = self.workers * self.depth;
        let spare = self.workers * (self.depth + 1);
        (jobs * (tx_job + rx_batch) + (spare + self.rx_slots) * slot_len) as u64
    }
}

/// Plans from fastest to leanest
const PLANS: [BufferPlan; 5] = [
    BufferPlan { workers: 4, depth: PIPELINE_DEPTH, rx_slots: RX_SLOTS_GRO },
    BufferPlan { workers: 2, depth: PIPELINE_DEPTH, rx_slots: RX_SLOTS_GRO },
    BufferPlan { workers: 1, depth: PIPELINE_DEPTH, rx_slots: RX_SLOTS_GRO },
    BufferPlan { workers: 1, depth: PIPELINE_DEPTH, rx_slots: 4 },
    BufferPlan { workers: 1, depth: 2, rx_slots: 2 },
];

/// Without a limit returns the measured default, otherwise
/// the fastest plan whose buffers fit the budget left after `base` bytes.
fn buffer_plan(limit_mb: Option<u32>, batched: bool, slot_len: usize, base: u64) -> BufferPlan {
    let workers = crypto_workers(batched);
    let slots = if slot_len > PKT_BUF { RX_SLOTS_GRO } else { RX_SLOTS };
    let Some(limit) = limit_mb else {
        return BufferPlan { workers, depth: PIPELINE_DEPTH, rx_slots: slots };
    };
    let budget = (u64::from(limit) << 20).saturating_sub(base + MEMORY_OVERHEAD);
    // More workers than the machine and the environment allow never help
    let max_workers = if std::env::var_os("RETAIL_CRYPTO_THREADS").is_some() || (batched && cores() >= 4) {
        workers.max(if batched { MAX_CRYPTO_WORKERS.min(cores() / 2).max(1) } else { 1 })
    } else {
        1
    };
    let fits = PLANS
        .iter()
        .map(|p| BufferPlan { rx_slots: if slots == RX_SLOTS { RX_SLOTS } else { p.rx_slots }, ..*p })
        .filter(|p| p.workers <= max_workers)
        .find(|p| p.bytes(slot_len) <= budget);
    match fits {
        Some(p) => p,
        None => {
            let p = PLANS[PLANS.len() - 1];
            tracing::warn!(limit_mb = limit, "memory limit is below what the data plane needs; using the smallest buffers");
            BufferPlan { rx_slots: if slots == RX_SLOTS { RX_SLOTS } else { p.rx_slots }, ..p }
        }
    }
}

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

#[derive(Default)]
struct Stats {
    tun_reads: AtomicU64,
    tun_read_pkts: AtomicU64,
    udp_sends: AtomicU64,
    udp_send_segs: AtomicU64,
    udp_recvs: AtomicU64,
    udp_recv_dgrams: AtomicU64,
    tun_writes: AtomicU64,
    tun_write_pkts: AtomicU64,
    /// Nanoseconds each stage spent working (busy) or blocked on the next stage (wait)
    busy_tun_read: AtomicU64,
    wait_tun_read: AtomicU64,
    busy_udp_send: AtomicU64,
    busy_udp_recv: AtomicU64,
    wait_udp_recv: AtomicU64,
    busy_tun_write: AtomicU64,
    crypto_tx: AtomicU64,
    crypto_rx: AtomicU64,
}

impl Stats {
    fn add(counter: &AtomicU64, n: usize) {
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn time(counter: &AtomicU64, since: Instant) {
        counter.fetch_add(since.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn take_stages(&self, window: Duration) -> String {
        let pct = |c: &AtomicU64| c.swap(0, Ordering::Relaxed) as f64 / window.as_nanos() as f64 * 100.0;
        format!(
            "tun-read busy {:.0}% wait-next {:.0}% | udp-send busy {:.0}% | udp-recv busy {:.0}% wait-next {:.0}% | tun-write busy {:.0}% | crypto tx {:.0}% rx {:.0}%",
            pct(&self.busy_tun_read),
            pct(&self.wait_tun_read),
            pct(&self.busy_udp_send),
            pct(&self.busy_udp_recv),
            pct(&self.wait_udp_recv),
            pct(&self.busy_tun_write),
            pct(&self.crypto_tx),
            pct(&self.crypto_rx),
        )
    }

    fn take_line(&self) -> Option<String> {
        let t = |c: &AtomicU64| c.swap(0, Ordering::Relaxed);
        let (tr, trp, us, uss, ur, urd, tw, twp) = (
            t(&self.tun_reads),
            t(&self.tun_read_pkts),
            t(&self.udp_sends),
            t(&self.udp_send_segs),
            t(&self.udp_recvs),
            t(&self.udp_recv_dgrams),
            t(&self.tun_writes),
            t(&self.tun_write_pkts),
        );
        if trp + urd == 0 {
            return None;
        }
        let avg = |n: u64, d: u64| if d == 0 { 0.0 } else { n as f64 / d as f64 };
        Some(format!(
            "tun read {trp} pkts/{tr} calls ({:.1}), udp send {uss} segs/{us} calls ({:.1}), \
             udp recv {urd} dgrams/{ur} calls ({:.1}), tun write {twp} pkts/{tw} writes ({:.1})",
            avg(trp, tr),
            avg(uss, us),
            avg(urd, ur),
            avg(twp, tw)
        ))
    }
}

pub struct Engine {
    stats: Stats,
    /// Whether every TUN read/write carries a virtio-net header (Linux offload)
    vnet_hdr: bool,
    private: StaticSecret,
    public: PublicKey,
    self_ip: Ipv4Addr,
    listen_port: u16,
    udp: UdpSocket,
    udp_state: UdpSocketState,
    tun: AsyncDevice,
    peers: RwLock<PeerTable>,
    next_index: AtomicU32,
    pub control_connected: AtomicBool,
    stun_servers: Mutex<Vec<String>>,
    stun_pending: Mutex<HashMap<stun::TransactionId, Instant>>,
    /// Public endpoints learned via STUN: [IPv4, IPv6]
    stun_public: Mutex<[Option<SocketAddr>; 2]>,
    /// The UDP socket is IPv6 with IPv4 mapped in (both families usable)
    dual_stack: bool,
    endpoints: watch::Sender<Vec<SocketAddr>>,
    relay_out: mpsc::Sender<Queued>,
    relay_out_rx: Mutex<Option<mpsc::Receiver<Queued>>>,
    /// User's choice, kept even while the peer is absent from the netmap
    exit_pref: Mutex<Option<Key>>,
    advertise_exit: watch::Sender<bool>,
    /// Networks this device offers to route
    advertise_routes: watch::Sender<Vec<Ipv4Net>>,
    /// Networks the server approved for this device, as last told
    granted_routes: RwLock<Vec<Ipv4Net>>,
    /// Networks this device routes: approved and still offered here
    own_routes: RwLock<Arc<[Ipv4Net]>>,
    /// What the system's routes and forwarding should follow
    route_state: watch::Sender<RouteState>,
    /// This device's key: when it expires, and whether it has
    key_state: Mutex<(Option<i64>, bool)>,
    /// Where the server says it is reachable now
    server_addrs: watch::Sender<Vec<String>>,
    /// The HTTPS URLs that forward to it, once a server (1.0.1 on) says
    server_fronts: watch::Sender<Option<Vec<String>>>,
    /// Tells the control loop to reconnect so its socket picks up new routes
    pub control_reset: tokio::sync::Notify,
    memory_limit_mb: Option<u32>,
    extra_endpoints: Mutex<Vec<SocketAddr>>,
    /// Starts a discovery round now (new STUN servers, new control address)
    stun_now: tokio::sync::Notify,
    /// The control server address that answered. STUN goes there unless the
    /// netmap names STUN servers, since of an invite's several addresses only
    /// this one is known to be reachable.
    control_addr: Mutex<Option<SocketAddr>>,
    /// How the control connection reaches the server, while connected
    control_via: Mutex<Option<String>>,
    /// Why the last try to reach the server failed, until one works, and
    /// since when tries have failed
    control_problem: Mutex<Option<(retail_proto::api::ConnectionProblem, Instant)>>,
    /// Checks handshake initiations' mac1 before the expensive part and,
    /// under load, makes senders prove their address with a cookie
    mac1: boringtun::noise::rate_limiter::RateLimiter,
    /// MagicDNS names of this device and its peers
    names: RwLock<crate::magicdns::Names>,
    self_dns_name: Mutex<String>,
    /// Queries to the MagicDNS address, for `dns_loop`
    dns_queries: mpsc::Sender<Vec<u8>>,
    dns_queries_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// The server asks this device to be its helper node
    helper_role: watch::Sender<bool>,
    /// Our helper code while we are one, for the control connection to send
    helper_code: watch::Sender<Option<String>>,
    /// Forwarding for the mesh through our own network stack, where the
    /// system has no NAT (`forward`)
    forward: RwLock<Option<Arc<crate::forward::Forward>>>,
}

impl Engine {
    pub async fn new(cfg: EngineConfig) -> Result<Self> {
        let mut builder = tun_rs::DeviceBuilder::new()
            .ipv4(cfg.ip, cfg.prefix_len, None)
            .mtu(TUN_MTU);
        if let Some(name) = &cfg.tun_name {
            builder = builder.name(name.clone());
        }
        #[cfg(target_os = "linux")]
        {
            builder = builder.offload(true);
        }
        let tun = builder.build_async().context(
            "creating TUN device (needs Administrator/root; on Windows wintun.dll must sit next to retaild.exe)",
        )?;
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = tun.set_tx_queue_len(1000) {
                tracing::debug!("setting TUN txqueuelen: {e}");
            }
            tracing::info!(tso = tun.tcp_gso(), uso = tun.udp_gso(), "TUN offload");
        }

        let (std_udp, dual_stack) = match bind_udp(cfg.listen_port) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("udp/{} unavailable ({e}); using a random port", cfg.listen_port);
                bind_udp(0)?
            }
        };
        let udp = UdpSocket::from_std(std_udp)?;
        let udp_state = UdpSocketState::new((&udp).into()).context("configuring UDP socket")?;
        set_socket_buffers(&udp);
        let listen_port = udp.local_addr()?.port();
        tracing::info!(
            ip = %cfg.ip,
            port = listen_port,
            dual_stack,
            gso_segments = udp_state.max_gso_segments(),
            gro_segments = udp_state.gro_segments(),
            "data plane up"
        );

        let public = PublicKey::from(&cfg.private_key);
        let (relay_out, relay_out_rx) = mpsc::channel(RELAY_OUT_QUEUE);
        let (dns_queries, dns_queries_rx) = mpsc::channel(64);
        #[cfg(target_os = "linux")]
        let vnet_hdr = tun.tcp_gso();
        #[cfg(not(target_os = "linux"))]
        let vnet_hdr = false;
        Ok(Engine {
            stats: Stats::default(),
            vnet_hdr,
            private: cfg.private_key,
            public,
            self_ip: cfg.ip,
            listen_port,
            udp,
            udp_state,
            tun,
            peers: RwLock::default(),
            next_index: AtomicU32::new(1),
            control_connected: AtomicBool::new(false),
            stun_servers: Mutex::default(),
            stun_pending: Mutex::default(),
            stun_public: Mutex::default(),
            dual_stack,
            endpoints: watch::channel(Vec::new()).0,
            relay_out,
            relay_out_rx: Mutex::new(Some(relay_out_rx)),
            exit_pref: Mutex::new(None),
            advertise_exit: watch::channel(false).0,
            advertise_routes: watch::channel(Vec::new()).0,
            own_routes: RwLock::new(Arc::from(Vec::new())),
            granted_routes: RwLock::new(Vec::new()),
            route_state: watch::channel(RouteState::default()).0,
            key_state: Mutex::default(),
            server_addrs: watch::channel(Vec::new()).0,
            server_fronts: watch::channel(None).0,
            control_reset: tokio::sync::Notify::new(),
            memory_limit_mb: cfg.memory_limit_mb,
            extra_endpoints: Mutex::default(),
            stun_now: tokio::sync::Notify::new(),
            control_addr: Mutex::default(),
            control_via: Mutex::default(),
            control_problem: Mutex::default(),
            names: RwLock::default(),
            mac1: boringtun::noise::rate_limiter::RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT),
            self_dns_name: Mutex::default(),
            dns_queries,
            dns_queries_rx: Mutex::new(Some(dns_queries_rx)),
            helper_role: watch::channel(false).0,
            helper_code: watch::channel(None).0,
            forward: RwLock::default(),
        })
    }

    /// Forwards for the mesh through our own network stack, or stops
    pub fn set_userspace_forwarding(self: &Arc<Self>, on: bool) -> Result<()> {
        let mut forward = self.forward.write().unwrap();
        if on == forward.is_some() {
            return Ok(());
        }
        *forward = if on {
            Some(Arc::new(crate::forward::Forward::start(self, self.self_ip).context("forwarding through this device's network stack")?))
        } else {
            None
        };
        Ok(())
    }

    /// Sends one IP packet to the peer it is addressed to
    pub fn send_ip(&self, packet: &[u8]) {
        let Some(dst) = packet.get(16..20).and_then(|d| <[u8; 4]>::try_from(d).ok()).map(Ipv4Addr::from) else { return };
        let Some(peer) = self.peers.read().unwrap().by_ip.get(&dst).cloned() else { return };
        let mut out = vec![0u8; (packet.len() + 32).max(148)];
        let n = {
            let mut tunn = peer.tunn.lock().unwrap();
            let n = tunn.encapsulate(packet, &mut out).len_if_network();
            if n.is_some() {
                tunn.note_sent(packet.len(), true);
            }
            n
        };
        if let Some(n) = n {
            self.send_to_peer(&peer, &out[..n]);
        }
    }

    /// Hands one IP packet to the system, as if it came from the mesh
    pub async fn write_ip(&self, packet: &[u8]) {
        if self.vnet_hdr {
            let mut buf = vec![0u8; TUN_OFFSET];
            buf.extend_from_slice(packet);
            self.tun_send(&buf).await;
        } else {
            self.tun_send(packet).await;
        }
    }

    /// Name and interface index of the TUN device (index 0 where unknown)
    pub fn tun_device(&self) -> (String, u32) {
        let name = self.tun.name().unwrap_or_default();
        #[cfg(target_os = "windows")]
        let index = self.tun.if_index().unwrap_or(0);
        #[cfg(not(target_os = "windows"))]
        let index = 0;
        (name, index)
    }

    pub fn set_exit_node(&self, key: Option<Key>) {
        *self.exit_pref.lock().unwrap() = key;
        self.peers.write().unwrap().select_exit(key);
    }

    /// Finds a peer by mesh IP, node key (base64) or hostname. Hostnames are
    /// chosen by each device and need not be unique, so a name several
    /// devices share is refused rather than picking one of them.
    pub fn find_peer(&self, name: &str) -> anyhow::Result<(Key, String, bool)> {
        let peers = self.peers.read().unwrap();
        let mut by_name = Vec::new();
        for p in peers.by_key.values() {
            let info = p.info.lock().unwrap();
            let found = (p.key, info.hostname.clone(), info.exit_node);
            if info.ip.to_string() == name || p.key.to_base64() == name {
                return Ok(found);
            }
            if info.hostname.eq_ignore_ascii_case(name) {
                by_name.push(found);
            }
        }
        match by_name.len() {
            0 => anyhow::bail!("no device named {name}"),
            1 => Ok(by_name.remove(0)),
            n => anyhow::bail!("{n} devices are named {name}; give its mesh IP or key instead"),
        }
    }

    pub fn set_advertise_exit(&self, on: bool) {
        self.advertise_exit.send_replace(on);
    }

    pub fn subscribe_advertise_exit(&self) -> watch::Receiver<bool> {
        self.advertise_exit.subscribe()
    }

    pub fn set_advertise_routes(&self, routes: Vec<Ipv4Net>) {
        self.advertise_routes.send_if_modified(|r| std::mem::replace(r, routes.clone()) != routes);
        // A network withdrawn here stops being routed at once, server or not
        let own = self.own_routes_now();
        *self.own_routes.write().unwrap() = own.clone();
        self.route_state.send_if_modified(|s| {
            let changed = s.own[..] != own[..];
            s.own = own.to_vec();
            changed
        });
    }

    /// The networks this device routes for the mesh: those the server
    /// approved that this device's owner also offers. The server is not
    /// trusted to add networks the owner did not offer.
    fn own_routes_now(&self) -> Arc<[Ipv4Net]> {
        let offered = self.advertise_routes.borrow();
        let granted = self.granted_routes.read().unwrap();
        granted.iter().filter(|r| r.check_route().is_ok() && offered.contains(r)).copied().collect()
    }

    pub fn subscribe_advertise_routes(&self) -> watch::Receiver<Vec<Ipv4Net>> {
        self.advertise_routes.subscribe()
    }

    pub fn subscribe_routes(&self) -> watch::Receiver<RouteState> {
        self.route_state.subscribe()
    }

    pub fn subscribe_server_addrs(&self) -> watch::Receiver<Vec<String>> {
        self.server_addrs.subscribe()
    }

    pub fn subscribe_server_fronts(&self) -> watch::Receiver<Option<Vec<String>>> {
        self.server_fronts.subscribe()
    }

    /// When this device's key expires, and whether it has
    pub fn key_state(&self) -> (Option<i64>, bool) {
        *self.key_state.lock().unwrap()
    }

    /// What this device takes from the mesh
    fn here<'a>(&self, routes: &'a [Ipv4Net]) -> crate::filter::Here<'a> {
        crate::filter::Here { ip: self.self_ip, exit: *self.advertise_exit.borrow(), routes }
    }

    /// Re-applies the exit-node socket bypass, needed on Windows/macOS where it
    /// pins the socket to the current interface.
    pub fn refresh_bypass(&self) {
        if let Err(e) = crate::exit::bypass(socket2::SockRef::from(&self.udp)) {
            tracing::debug!("re-pinning the UDP socket: {e}");
        }
    }

    pub fn subscribe_endpoints(&self) -> watch::Receiver<Vec<SocketAddr>> {
        self.endpoints.subscribe()
    }

    pub fn current_endpoints(&self) -> Vec<SocketAddr> {
        self.endpoints.borrow().clone()
    }

    pub fn apply_netmap(&self, nm: NetMap) {
        let own_key = Key(self.public.to_bytes());
        if nm.self_node.ip != self.self_ip {
            tracing::warn!(
                "control server reports IP {} but the tunnel uses {}; run `retail up` again",
                nm.self_node.ip,
                self.self_ip
            );
        }
        let stun_changed = {
            let mut cur = self.stun_servers.lock().unwrap();
            let changed = *cur != nm.stun_servers;
            *cur = nm.stun_servers.clone();
            changed
        };
        if stun_changed {
            self.stun_now.notify_one();
        }

        let names = crate::magicdns::Names::new(
            std::iter::once((nm.self_node.dns_name.as_str(), self.self_ip)).chain(nm.peers.iter().map(|n| (n.dns_name.as_str(), n.ip))),
        );
        *self.names.write().unwrap() = names;
        *self.self_dns_name.lock().unwrap() = nm.self_node.dns_name.clone();
        self.helper_role.send_if_modified(|h| std::mem::replace(h, nm.helper) != nm.helper);
        {
            let mut k = self.key_state.lock().unwrap();
            if nm.expired && !k.1 {
                tracing::warn!("this device's key expired; the server's administrator can renew it");
            }
            *k = (nm.expires_at, nm.expired);
        }
        let addrs: Vec<String> = nm.server_addrs.iter().take(16).filter(|a| a.len() < 300).cloned().collect();
        if !addrs.is_empty() {
            self.server_addrs.send_if_modified(|cur| std::mem::replace(cur, addrs.clone()) != addrs);
        }
        if let Some(fronts) = &nm.server_fronts {
            let fronts: Vec<String> =
                fronts.iter().filter(|f| f.starts_with("https://") && f.len() < 300).take(8).cloned().collect();
            self.server_fronts.send_if_modified(|cur| cur.replace(fronts.clone()).as_ref() != Some(&fronts));
        }
        *self.granted_routes.write().unwrap() = nm.self_node.routes.clone();
        let own_routes = self.own_routes_now();
        *self.own_routes.write().unwrap() = own_routes.clone();
        // Networks this device is on itself stay off the tunnel, or it would
        // lose its own LAN
        let local = crate::host::local_networks();
        let accepted: Vec<(Ipv4Net, Key)> = nm
            .peers
            .iter()
            .filter(|n| n.node_key != own_key)
            .flat_map(|n| n.routes.iter().map(move |r| (*r, n.node_key)))
            .filter(|(r, _)| r.check_route().is_ok() && !local.iter().any(|l| l.overlaps(r)) && !own_routes.iter().any(|o| o.overlaps(r)))
            .collect();

        let mut kick = Vec::new();
        let table = {
            let old = self.peers.read().unwrap();
            let mut table = PeerTable::default();
            for node in &nm.peers {
                if node.node_key == own_key || node.ip == self.self_ip || !in_mesh(node.ip) {
                    continue;
                }
                // An endpoint inside a routed network would send the tunnel through itself
                let routed = |e: &SocketAddr| match e.ip() {
                    IpAddr::V4(v4) => accepted.iter().any(|(r, _)| r.contains(v4)),
                    IpAddr::V6(_) => false,
                };
                let candidates: Vec<SocketAddr> = node
                    .endpoints
                    .iter()
                    .copied()
                    .filter(|e| e.is_ipv4() || (self.dual_stack && usable_ip(e.ip())))
                    .filter(|e| !routed(e))
                    .collect();
                let routes: Arc<[Ipv4Net]> = accepted.iter().filter(|(_, k)| *k == node.node_key).map(|(r, _)| *r).collect();
                let peer = match old.by_key.get(&node.node_key) {
                    Some(p) => {
                        let mut info = p.info.lock().unwrap();
                        let changed = info.candidates != candidates || (node.online && !info.online);
                        info.hostname = display_safe(&node.hostname);
                        info.dns_name = display_safe(&node.dns_name);
                        info.ip = node.ip;
                        info.online = node.online;
                        info.exit_node = node.exit_node;
                        info.candidates = candidates;
                        drop(info);
                        p.filter.set(&node.accept);
                        *p.routes.write().unwrap() = routes.clone();
                        if changed {
                            kick.push(p.clone());
                        }
                        p.clone()
                    }
                    None => {
                        let p = Arc::new(self.new_peer(node, candidates));
                        *p.routes.write().unwrap() = routes.clone();
                        tracing::info!(peer = %node.hostname, ip = %node.ip, "peer added");
                        kick.push(p.clone());
                        p
                    }
                };
                table.by_ip.insert(node.ip, peer.clone());
                table.by_index.insert(peer.index, peer.clone());
                table.by_key.insert(node.node_key, peer);
            }
            for (key, p) in &old.by_key {
                if !table.by_key.contains_key(key) {
                    tracing::info!(peer = %p.info.lock().unwrap().hostname, "peer removed");
                }
            }
            table.select_exit(*self.exit_pref.lock().unwrap());
            table.routes = accepted.iter().filter_map(|(r, k)| Some((*r, table.by_key.get(k)?.clone()))).collect();
            table.routes.sort_by_key(|(r, _)| std::cmp::Reverse(r.prefix_len()));
            table
        };
        *self.peers.write().unwrap() = table;
        let state = RouteState { own: own_routes.to_vec(), accepted: accepted.iter().map(|(r, _)| *r).collect() };
        self.route_state.send_if_modified(|s| std::mem::replace(s, state.clone()) != state);

        // Both sides handshake at once on seeing a new or moved peer, which punches the NAT holes
        let mut out = [0u8; 256];
        for p in kick {
            if p.is_fresh() {
                continue;
            }
            let result = p.tunn.lock().unwrap().encapsulate(&[], &mut out).len_if_network();
            match result {
                Some(n) => self.send_to_peer(&p, &out[..n]),
                // A handshake is already in flight, so re-send it to the new candidates
                None => self.resend_init(&p),
            }
        }
    }

    fn new_peer(&self, node: &Node, candidates: Vec<SocketAddr>) -> Peer {
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) & INDEX_MASK;
        let tunn = Tunn::new(
            self.private.clone(),
            PublicKey::from(node.node_key.0),
            None,
            Some(KEEPALIVE_SECS),
            index,
            None,
        );
        let filter = crate::filter::Filter::default();
        filter.set(&node.accept);
        Peer {
            key: node.node_key,
            index,
            tunn: Mutex::new(tunn),
            is_exit: AtomicBool::new(false),
            filter,
            routes: RwLock::new(Arc::from(Vec::new())),
            info: Mutex::new(PeerInfo {
                hostname: display_safe(&node.hostname),
                dns_name: display_safe(&node.dns_name),
                ip: node.ip,
                online: node.online,
                exit_node: node.exit_node,
                candidates,
                endpoint: None,
                last_rx: None,
                relay_rx: None,
                searching_since: None,
                last_probe: None,
                last_init: None,
                tx_seen: 0,
                rx_seen: 0,
                tx_at: None,
                rx_at: None,
                keepalive_at: None,
                direct_since: None,
                udp_data_at: None,
                relay_data_at: None,
                needs_proof: false,
            }),
        }
    }

    /// Non-batched send of a handshake, keepalive or (while no path works)
    /// data packet. Goes to the direct endpoint once it works, otherwise to
    /// every candidate plus the relay when it carries the peer or the direct
    /// attempt has had its head start.
    fn send_to_peer(&self, peer: &Peer, data: &[u8]) {
        if is_handshake_init(data) {
            peer.info.lock().unwrap().last_init = Some((data.to_vec(), Instant::now()));
        }
        self.send_routed(peer, data);
    }

    fn send_routed(&self, peer: &Peer, data: &[u8]) {
        let relay = match peer.route() {
            Route::Direct(ep) => {
                self.send_now(data, ep);
                return;
            }
            // Control packets keep probing the direct candidates while relayed
            Route::Relay => true,
            Route::Search { relay } => relay,
        };
        for dst in peer.candidates() {
            self.send_now(data, dst);
        }
        if relay {
            self.relay_send(&peer.key, std::iter::once(data));
        }
    }

    /// Drops the datagrams if the control connection is down or backed up.
    /// Never waits, because it is used outside udp-send.
    fn relay_send<'a>(&self, key: &Key, datagrams: impl Iterator<Item = &'a [u8]>) {
        if !self.control_connected.load(Ordering::Relaxed) {
            return;
        }
        let Ok(permit) = self.relay_out.try_reserve() else {
            return;
        };
        Self::relay_frame(permit, key, datagrams);
    }

    /// Like [`Self::relay_send`], but waits for room until `deadline` (udp-send only)
    async fn relay_send_paced<'a>(&self, key: &Key, datagrams: impl Iterator<Item = &'a [u8]>, deadline: Instant) {
        if !self.control_connected.load(Ordering::Relaxed) {
            return;
        }
        let permit = match self.relay_out.try_reserve() {
            Ok(p) => p,
            Err(mpsc::error::TrySendError::Full(())) => {
                match tokio::time::timeout_at(deadline.into(), self.relay_out.reserve()).await {
                    Ok(Ok(p)) => p,
                    _ => return, // Over this job's budget
                }
            }
            Err(_) => return,
        };
        Self::relay_frame(permit, key, datagrams);
    }

    fn relay_frame<'a>(permit: mpsc::Permit<'_, Queued>, key: &Key, mut datagrams: impl Iterator<Item = &'a [u8]>) {
        let Some(first) = datagrams.next() else { return };
        // All but the last datagram of a group have the first one's length
        let n = 1 + datagrams.size_hint().0;
        let mut frame = Vec::with_capacity(32 + (2 + first.len()) * n);
        retail_proto::relay::begin(key, &mut frame);
        for d in std::iter::once(first).chain(datagrams) {
            if !retail_proto::relay::push(&mut frame, d) {
                break; // Unreachable since callers send at most MAX_GSO_BYTES
            }
        }
        permit.send((Instant::now(), frame));
    }

    /// Taken once by the control loop
    pub fn take_relay_out(&self) -> Option<mpsc::Receiver<Queued>> {
        self.relay_out_rx.lock().unwrap().take()
    }

    /// Writes decrypted packets straight to the TUN device, outside the UDP
    /// pipeline and its ordering.
    pub async fn receive_relay(&self, frame: &[u8], rx: &mut RelayRx) {
        let Some((from, datagrams)) = retail_proto::relay::parse(frame) else {
            return;
        };
        if !self.peers.read().unwrap().by_key.contains_key(&from) {
            return;
        }
        // Decrypted in batches and merged for the TUN device, as on the UDP path
        let datagrams: Vec<&[u8]> = datagrams.collect();
        for chunk in datagrams.chunks(RX_BATCH) {
            rx.batch.len = 0;
            self.receive_run(chunk.iter().copied(), Src::Relay, &mut rx.batch);
            let len = rx.batch.len;
            if len > 0 {
                Stats::add(&self.stats.tun_write_pkts, len);
                self.write_tun(&mut rx.batch.bufs[..len], &mut rx.gro).await;
            }
        }
    }

    fn note_rx(&self, peer: &Peer, src: Src, data: bool) {
        if peer.mark_rx(src, data)
            && let Src::Udp(addr) = src
        {
            self.answer_direct(peer, addr);
        }
    }

    /// Called when a direct path just came up, typically from a probe while
    /// relayed. An immediate keepalive back lets the other side switch now
    /// instead of at its next keepalive.
    fn answer_direct(&self, peer: &Peer, addr: SocketAddr) {
        let mut out = [0u8; 64];
        let n = {
            let mut tunn = peer.tunn.lock().unwrap();
            if tunn.current_send_session().is_none() {
                return;
            }
            tunn.encapsulate(&[], &mut out).len_if_network()
        };
        if let Some(n) = n {
            self.send_now(&out[..n], addr);
        }
    }

    fn reply(&self, peer: &Peer, data: &[u8], src: Src) {
        match src {
            Src::Udp(addr) => self.send_now(data, addr),
            Src::Relay => self.relay_send(&peer.key, std::iter::once(data)),
        }
    }

    /// IPv4 destinations become IPv4-mapped IPv6 addresses on a dual-stack socket
    fn wire(&self, addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V4(v4) if self.dual_stack => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
            _ => addr,
        }
    }

    fn send_now(&self, data: &[u8], dst: SocketAddr) {
        if let Err(e) = self.udp.try_send_to(data, self.wire(dst)) {
            tracing::trace!(%dst, "udp send failed: {e}");
        }
    }

    /// Re-sends the pending handshake initiation, if it is still current
    fn resend_init(&self, peer: &Peer) {
        let init = {
            let info = peer.info.lock().unwrap();
            match &info.last_init {
                Some((pkt, at)) if at.elapsed() < PUNCH_WINDOW && info.online => pkt.clone(),
                _ => return,
            }
        };
        self.send_routed(peer, &init);
    }

    /// The load gate for handshake initiations, before any Diffie-Hellman. A
    /// replayed or forged initiation passes mac1, so past the limit a sender
    /// gets a cookie reply and must come back with it (WireGuard's mac2);
    /// over the relay, which has no address to bind a cookie to, it is dropped.
    fn handshake_allowed(&self, dgram: &[u8], src: Src) -> bool {
        if dgram.len() != 148 || dgram[..4] != [1, 0, 0, 0] {
            return true;
        }
        self.mac1.reset_count();
        let addr = match src {
            Src::Udp(addr) => Some(addr),
            Src::Relay => None,
        };
        let mut cookie = [0u8; 64];
        match self.mac1.verify_packet(addr.map(|a| a.ip()), dgram, &mut cookie) {
            Ok(_) => true,
            Err(TunnResult::WriteToNetwork(reply)) => {
                if let Some(addr) = addr {
                    self.send_now(reply, addr);
                }
                false
            }
            Err(_) => false,
        }
    }

    fn lookup_incoming(&self, pkt: &[u8]) -> Option<Arc<Peer>> {
        let peers = self.peers.read().unwrap();
        match Tunn::parse_incoming_packet(pkt).ok()? {
            Packet::HandshakeInit(h) => {
                // Only senders who know our public key get a Diffie-Hellman out of us
                if !self.mac1.verify_mac1(pkt) {
                    return None;
                }
                let half = parse_handshake_anon(&self.private, &self.public, &h).ok()?;
                peers.by_key.get(&Key(half.peer_static_public)).cloned()
            }
            Packet::HandshakeResponse(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketCookieReply(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketData(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
        }
    }

    /// The data-plane stages, each run on its own thread:
    ///
    /// ```text
    ///   tun-read --+-- encrypt[0..K] --+-- udp-send
    ///   udp-recv --+-- decrypt[0..K] --+-- tun-write
    /// ```
    ///
    /// Work is dealt to the K crypto workers round-robin and collected in the
    /// same cyclic order. As every channel is FIFO, packets leave in arrival
    /// order without a reorder buffer. Buffers circulate through free lists, so
    /// the hot path does not allocate and a stage waits only when every buffer
    /// is in flight.
    pub fn data_plane_tasks(self: &Arc<Self>) -> Vec<(&'static str, DataPlaneTask)> {
        let gro = self.udp_state.gro_segments().max(1);
        let slot_len = (gro * 1500).clamp(PKT_BUF, MAX_PACKET);
        let base = crate::memory::current().unwrap_or(6 << 20);
        let plan = buffer_plan(self.memory_limit_mb, self.vnet_hdr && gro > 1, slot_len, base);
        tracing::info!(
            limit_mb = ?self.memory_limit_mb,
            workers = plan.workers,
            depth = plan.depth,
            rx_slots = plan.rx_slots,
            buffers_kib = plan.bytes(slot_len) / 1024,
            base_kib = base / 1024,
            "data-plane buffers"
        );
        let (k, depth) = (plan.workers, plan.depth);
        let mut tasks: Vec<(&'static str, DataPlaneTask)> = Vec::new();

        let (job_free_tx, job_free_rx) = mpsc::channel::<TxJob>(k * depth);
        for _ in 0..k * depth {
            job_free_tx.try_send(TxJob::new()).expect("room for every job");
        }
        let (mut to_encrypt, mut from_encrypt) = (Vec::new(), Vec::new());
        for stage in ENCRYPT_STAGES.iter().take(k) {
            let (in_tx, in_rx) = mpsc::channel::<TxJob>(depth);
            let (out_tx, out_rx) = mpsc::channel::<TxJob>(depth);
            to_encrypt.push(in_tx);
            from_encrypt.push(out_rx);
            tasks.push((*stage, Box::pin(self.clone().encrypt_loop(in_rx, out_tx))));
        }
        tasks.push(("tun-read", Box::pin(self.clone().tun_loop(job_free_rx, to_encrypt))));
        tasks.push(("udp-send", Box::pin(self.clone().udp_send_loop(from_encrypt, job_free_tx))));

        let slots = plan.rx_slots;
        // Enough spare receive buffers to keep every decrypt worker busy
        let spare_n = k * (depth + 1);
        let (spare_tx, spare_rx) = mpsc::channel::<Vec<u8>>(spare_n);
        for _ in 0..spare_n {
            spare_tx.try_send(vec![0u8; slot_len]).expect("room for every spare slot");
        }
        let (mut to_decrypt, mut from_decrypt) = (Vec::new(), Vec::new());
        for stage in DECRYPT_STAGES.iter().take(k) {
            let (train_tx, train_rx) = mpsc::channel::<Vec<Train>>(depth);
            let (full, free) = pipeline(depth, RxBatch::new);
            to_decrypt.push(train_tx);
            from_decrypt.push((full.1, free.0));
            tasks.push((*stage, Box::pin(self.clone().decrypt_loop(train_rx, spare_tx.clone(), full.0, free.1))));
        }
        tasks.push(("udp-recv", Box::pin(self.clone().udp_loop(to_decrypt, spare_rx, spare_n, slots, slot_len))));
        tasks.push(("tun-write", Box::pin(self.clone().tun_write_loop(from_decrypt))));
        tasks
    }

    async fn tun_loop(self: Arc<Self>, mut free: mpsc::Receiver<TxJob>, workers: Vec<mpsc::Sender<TxJob>>) -> Result<()> {
        #[cfg(target_os = "linux")]
        let mut original = vec![0u8; TUN_OFFSET + MAX_PACKET];
        let mut turn = 0usize;
        loop {
            let mut job = free.recv().await.context("udp-send stage stopped")?;
            #[cfg(target_os = "linux")]
            let n = {
                let mut n = self
                    .tun
                    .recv_multiple(&mut original, &mut job.bufs[..TUN_READ], &mut job.sizes[..TUN_READ], 0)
                    .await
                    .context("reading TUN device")?;
                // Under load more super-packets are already waiting: take them
                // into the same job, which halves the hand-offs between stages
                while n + TUN_READ <= TUN_BATCH {
                    let (bufs, sizes) = (&mut job.bufs[n..n + TUN_READ], &mut job.sizes[n..n + TUN_READ]);
                    match self.tun.try_recv_multiple(&mut original, bufs, sizes, 0) {
                        Ok(m) => {
                            Stats::add(&self.stats.tun_reads, 1);
                            n += m;
                        }
                        Err(_) => break,
                    }
                }
                n
            };
            #[cfg(not(target_os = "linux"))]
            let n = {
                job.sizes[0] = self.tun.recv(&mut job.bufs[0]).await.context("reading TUN device")?;
                1
            };
            job.n = n;
            if let Some(f) = self.forward.read().unwrap().as_ref() {
                for j in 0..n {
                    f.outbound(&mut job.bufs[j][..job.sizes[j]]);
                }
            }
            Stats::add(&self.stats.tun_reads, 1);
            Stats::add(&self.stats.tun_read_pkts, n);
            let t0 = Instant::now();
            self.plan_runs(&mut job);
            Stats::time(&self.stats.busy_tun_read, t0);
            let worker = &workers[turn % workers.len()];
            turn = turn.wrapping_add(1);
            worker.send(job).await.map_err(|_| anyhow::anyhow!("encrypt stage stopped"))?;
        }
    }

    /// Splits a TUN read into runs of consecutive packets for the same peer
    /// (a TSO super-packet is always one run) and, where a session exists,
    /// reserves the run's send counters and records it as sent.
    fn plan_runs(&self, job: &mut TxJob) {
        job.runs.clear();
        let (bufs, sizes, n) = (&job.bufs, &job.sizes, job.n);
        let ipv4 = |j: usize| sizes[j] >= 20 && bufs[j][0] >> 4 == 4;
        let mut i = 0;
        while i < n {
            if !ipv4(i) {
                i += 1; // IPv4 only
                continue;
            }
            let dst_ip: [u8; 4] = bufs[i][16..20].try_into().unwrap();
            let mut end = i + 1;
            while end < n && ipv4(end) && bufs[end][16..20] == dst_ip {
                end += 1;
            }
            let range = i..end;
            i = end;
            let dst = Ipv4Addr::from(dst_ip);
            let peer = {
                let peers = self.peers.read().unwrap();
                match peers.by_ip.get(&dst) {
                    Some(p) => Some(p.clone()),
                    // Unknown mesh addresses never go to the exit node
                    None if !in_mesh(dst) => peers.routed(dst).or(peers.exit.as_ref()).cloned(),
                    None => None,
                }
            };
            let Some(peer) = peer else {
                if dst == retail_proto::MAGIC_DNS_IP {
                    for j in range {
                        let _ = self.dns_queries.try_send(bufs[j][..sizes[j]].to_vec());
                    }
                }
                continue;
            };
            if peer.filter.restricted() {
                for j in range.clone() {
                    peer.filter.outbound(&bufs[j][..sizes[j]]);
                }
            }
            let session = {
                let mut tunn = peer.tunn.lock().unwrap();
                tunn.current_send_session().map(|s| {
                    let first = s.reserve_counters(range.len() as u64);
                    tunn.note_sent(range.clone().map(|j| sizes[j]).sum(), true);
                    (s, first)
                })
            };
            job.runs.push(TxRun { range, peer, session });
        }
    }

    async fn encrypt_loop(self: Arc<Self>, mut jobs: mpsc::Receiver<TxJob>, done: mpsc::Sender<TxJob>) -> Result<()> {
        let mut lens: Vec<usize> = Vec::with_capacity(TUN_BATCH);
        while let Some(mut job) = jobs.recv().await {
            let c0 = Instant::now();
            job.out.clear();
            job.sends.clear();
            let mut runs = std::mem::take(&mut job.runs);
            for run in &runs {
                let start = job.out.len();
                lens.clear();
                match &run.session {
                    Some((session, first)) => {
                        let packets: Vec<&[u8]> = run.range.clone().map(|j| &job.bufs[j][..job.sizes[j]]).collect();
                        crate::crypto::encrypt_batch(session, *first, &packets, &mut job.out);
                        lens.extend(packets.iter().map(|p| p.len() + crate::crypto::OVERHEAD));
                    }
                    None => {
                        // Without a session Tunn queues the packets and starts a handshake
                        let mut tunn = run.peer.tunn.lock().unwrap();
                        for j in run.range.clone() {
                            let at = job.out.len();
                            job.out.resize(at + (job.sizes[j] + 32).max(148), 0);
                            match tunn.encapsulate(&job.bufs[j][..job.sizes[j]], &mut job.out[at..]) {
                                TunnResult::WriteToNetwork(b) => {
                                    let len = b.len();
                                    job.out.truncate(at + len);
                                    lens.push(len);
                                }
                                TunnResult::Err(e) => {
                                    tracing::trace!("encapsulate: {e:?}");
                                    job.out.truncate(at);
                                }
                                _ => job.out.truncate(at),
                            }
                        }
                    }
                }
                let mut at = start;
                let route = if run.session.is_some() { run.peer.route() } else { Route::Search { relay: false } };
                let dst = match route {
                    Route::Direct(dst) => Some(Dest::Udp(dst)),
                    Route::Relay => Some(Dest::Relay),
                    Route::Search { .. } => None,
                };
                match dst {
                    // One relay frame per GSO group when relayed
                    Some(dst) => {
                        let max = self.udp_state.max_gso_segments();
                        for (first, count) in gso_groups(&lens, max, MAX_GSO_BYTES) {
                            let total: usize = lens[first..first + count].iter().sum();
                            let send = TxSend { peer: run.peer.clone(), dst, start: at, seg: lens[first], count, total };
                            job.sends.push(send);
                            at += total;
                        }
                    }
                    // Handshakes or an undiscovered path, so each datagram tries every route
                    None => {
                        for &len in &lens {
                            let send = TxSend { peer: run.peer.clone(), dst: Dest::Search, start: at, seg: len, count: 1, total: len };
                            job.sends.push(send);
                            at += len;
                        }
                    }
                }
            }
            runs.clear();
            job.runs = runs;
            Stats::time(&self.stats.crypto_tx, c0);
            if done.send(job).await.is_err() {
                break;
            }
        }
        anyhow::bail!("udp-send stage stopped")
    }

    /// Collects jobs from the encrypt workers in the order they were dealt
    async fn udp_send_loop(self: Arc<Self>, mut workers: Vec<mpsc::Receiver<TxJob>>, free: mpsc::Sender<TxJob>) -> Result<()> {
        let k = workers.len();
        let mut turn = 0usize;
        loop {
            let Some(mut job) = workers[turn % k].recv().await else { break };
            turn = turn.wrapping_add(1);
            let t0 = Instant::now();
            let relay_deadline = t0 + RELAY_JOB_WAIT;
            for send in &job.sends {
                let contents = &job.out[send.start..send.start + send.total];
                match send.dst {
                    Dest::Udp(dst) => {
                        let transmit = Transmit {
                            destination: self.wire(dst),
                            ecn: None,
                            contents,
                            segment_size: (send.count > 1).then_some(send.seg),
                            src_ip: None,
                        };
                        let r = self
                            .udp
                            .async_io(Interest::WRITABLE, || self.udp_state.try_send((&self.udp).into(), &transmit))
                            .await;
                        if let Err(e) = r {
                            tracing::trace!(%dst, segments = send.count, "udp send failed: {e}");
                        }
                        Stats::add(&self.stats.udp_sends, 1);
                        Stats::add(&self.stats.udp_send_segs, send.count);
                    }
                    Dest::Relay => {
                        let per_frame = (RELAY_FRAME_BYTES / send.seg.max(1)).max(1) * send.seg;
                        for part in contents.chunks(per_frame) {
                            self.relay_send_paced(&send.peer.key, part.chunks(send.seg), relay_deadline).await;
                        }
                    }
                    Dest::Search => self.send_to_peer(&send.peer, contents),
                }
            }
            job.sends.clear();
            Stats::time(&self.stats.busy_udp_send, t0);
            if free.send(job).await.is_err() {
                break;
            }
        }
        anyhow::bail!("encrypt stage stopped")
    }

    /// Deals each GRO train, buffer and all, to the decrypt workers. Filled
    /// slots are swapped for spare ones, so receiving waits only when every
    /// spare slot is in flight.
    async fn udp_loop(
        self: Arc<Self>,
        workers: Vec<mpsc::Sender<Vec<Train>>>,
        mut spare: mpsc::Receiver<Vec<u8>>,
        spare_n: usize,
        slots: usize,
        slot_len: usize,
    ) -> Result<()> {
        let mut rx: Vec<Vec<u8>> = (0..slots).map(|_| vec![0u8; slot_len]).collect();
        let mut meta = vec![RecvMeta::default(); slots];
        let mut turn = 0usize;
        loop {
            let r = self
                .udp
                .async_io(Interest::READABLE, || {
                    let mut iov: Vec<IoSliceMut<'_>> = rx.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                    self.udp_state.recv((&self.udp).into(), &mut iov, &mut meta)
                })
                .await;
            let n = match r {
                Ok(n) => n,
                // Windows surfaces ICMP port-unreachable as WSAECONNRESET on the next recv
                Err(e) => {
                    tracing::trace!("udp recv: {e}");
                    continue;
                }
            };
            Stats::add(&self.stats.udp_recvs, 1);
            let t0 = Instant::now();
            // Trains from one receive go to a worker together, up to a batch of
            // datagrams, so a burst costs one hand-off instead of one per train.
            // A job holds fewer buffers than there are spares, or waiting for
            // the next spare could wait on itself.
            let max_trains = spare_n.saturating_sub(1).max(1);
            let mut job: Vec<Train> = Vec::with_capacity(n);
            let mut dgrams = 0;
            for (m, slot) in meta.iter().zip(rx.iter_mut()).take(n) {
                let stride = if m.stride == 0 { m.len.max(1) } else { m.stride };
                let count = m.len.div_ceil(stride);
                Stats::add(&self.stats.udp_recv_dgrams, count);
                if !job.is_empty() && (dgrams + count > RX_BATCH || job.len() >= max_trains) {
                    let worker = &workers[turn % workers.len()];
                    turn = turn.wrapping_add(1);
                    worker.send(std::mem::take(&mut job)).await.map_err(|_| anyhow::anyhow!("decrypt stage stopped"))?;
                    dgrams = 0;
                }
                let w = Instant::now();
                let fresh = spare.recv().await.context("decrypt stage stopped")?;
                Stats::time(&self.stats.wait_udp_recv, w);
                let buf = std::mem::replace(slot, fresh);
                job.push(Train { buf, len: m.len, stride, src: canonical(m.addr) });
                dgrams += count;
            }
            if !job.is_empty() {
                let worker = &workers[turn % workers.len()];
                turn = turn.wrapping_add(1);
                worker.send(job).await.map_err(|_| anyhow::anyhow!("decrypt stage stopped"))?;
            }
            Stats::time(&self.stats.busy_udp_recv, t0);
        }
    }

    /// Emits exactly one batch per job of trains, possibly empty, so
    /// tun-write can collect them in the order they were dealt.
    async fn decrypt_loop(
        self: Arc<Self>,
        mut trains: mpsc::Receiver<Vec<Train>>,
        spare: mpsc::Sender<Vec<u8>>,
        full: mpsc::Sender<RxBatch>,
        mut free: mpsc::Receiver<RxBatch>,
    ) -> Result<()> {
        while let Some(job) = trains.recv().await {
            let mut batch = free.recv().await.context("tun-write stage stopped")?;
            let c0 = Instant::now();
            for train in &job {
                self.receive_run(train.buf[..train.len].chunks(train.stride), Src::Udp(train.src), &mut batch);
            }
            Stats::time(&self.stats.crypto_rx, c0);
            for train in job {
                if spare.send(train.buf).await.is_err() {
                    anyhow::bail!("udp-recv stage stopped");
                }
            }
            if full.send(batch).await.is_err() {
                break;
            }
        }
        anyhow::bail!("udp-recv stage stopped")
    }

    /// Collects batches from the decrypt workers in dealing order
    async fn tun_write_loop(self: Arc<Self>, mut workers: Vec<(mpsc::Receiver<RxBatch>, mpsc::Sender<RxBatch>)>) -> Result<()> {
        let mut gro = crate::gro::Coalescer::new();
        let k = workers.len();
        let mut turn = 0usize;
        loop {
            let (full, free) = &mut workers[turn % k];
            turn = turn.wrapping_add(1);
            let Some(mut batch) = full.recv().await else { break };
            let len = batch.len;
            if len > 0 {
                Stats::add(&self.stats.tun_write_pkts, len);
                let t0 = Instant::now();
                self.write_tun(&mut batch.bufs[..len], &mut gro).await;
                Stats::time(&self.stats.busy_tun_write, t0);
            }
            batch.len = 0;
            if free.send(batch).await.is_err() {
                break;
            }
        }
        anyhow::bail!("decrypt stage stopped")
    }

    /// Decrypts runs of transport-data packets for the same session as a
    /// batch, with one peer lookup and two short `Tunn` locks. Anything else
    /// goes through [`Self::receive`].
    fn receive_run<'a>(&self, dgrams: impl Iterator<Item = &'a [u8]>, src: Src, b: &mut RxBatch) {
        let own_routes = self.own_routes.read().unwrap().clone();
        let here = self.here(&own_routes);
        let mut dgrams = dgrams.peekable();
        let mut run: Vec<&[u8]> = Vec::with_capacity(RX_BATCH);
        let mut results = Vec::with_capacity(RX_BATCH);
        while let Some(d) = dgrams.next() {
            if b.len == b.bufs.len() {
                if b.len >= RX_BATCH_MAX {
                    return;
                }
                b.bufs.push(vec![0u8; PKT_BUF]);
            }
            let Some(r_idx) = data_receiver_index(d) else {
                if self.receive(d, src, &mut b.bufs[b.len]) {
                    b.len += 1;
                }
                continue;
            };
            let Some(peer) = self.peers.read().unwrap().by_index.get(&(r_idx >> 8)).cloned() else {
                continue;
            };
            let session = peer.tunn.lock().unwrap().session_for(r_idx);
            let Some(session) = session else {
                // Let Tunn reject an unknown or expired session
                if self.receive(d, src, &mut b.bufs[b.len]) {
                    b.len += 1;
                }
                continue;
            };
            run.clear();
            run.push(d);
            let room = (RX_BATCH_MAX - b.len).min(RX_BATCH);
            while run.len() < room {
                match dgrams.next_if(|n| data_receiver_index(n) == Some(r_idx)) {
                    Some(n) => run.push(n),
                    None => break,
                }
            }
            while b.bufs.len() < b.len + run.len() {
                b.bufs.push(vec![0u8; PKT_BUF]);
            }

            let peer_routes = peer.routes();
            crate::crypto::decrypt_batch(&session, &run, &mut b.bufs[b.len..], TUN_OFFSET, peer.allowed_src(&peer_routes), &mut results);

            // Keep delivered packets contiguous and in order
            let first = b.len;
            let (mut bytes, mut authenticated) = (0, false);
            for (i, r) in results.iter().enumerate() {
                match *r {
                    crate::crypto::Decrypted::Packet(len) => {
                        authenticated = true;
                        if !peer.filter.inbound(&b.bufs[first + i][TUN_OFFSET..TUN_OFFSET + len], &here) {
                            continue;
                        }
                        b.bufs.swap(first + i, b.len);
                        b.len += 1;
                        bytes += len;
                        authenticated = true;
                    }
                    crate::crypto::Decrypted::Authenticated => authenticated = true,
                    crate::crypto::Decrypted::Rejected => tracing::trace!(?src, "transport packet rejected"),
                }
            }
            if authenticated {
                peer.tunn.lock().unwrap().note_received(r_idx, bytes, bytes > 0);
                if peer.mark_rx(src, bytes > 0)
                    && let Src::Udp(addr) = src
                {
                    self.answer_direct(&peer, addr);
                }
            }
        }
    }

    /// Handles one datagram. Returns true if `out` now holds an IP packet for
    /// the TUN device (at `TUN_OFFSET`, with `out.len()` marking its end).
    fn receive(&self, dgram: &[u8], src: Src, out: &mut Vec<u8>) -> bool {
        if matches!(src, Src::Udp(_)) && stun::is_stun(dgram) {
            self.handle_stun(dgram);
            return false;
        }
        if !self.handshake_allowed(dgram, src) {
            return false;
        }
        let Some(peer) = self.lookup_incoming(dgram) else {
            return false;
        };
        let response = dgram.len() == 92 && dgram[..4] == [2, 0, 0, 0];
        if out.len() < PKT_BUF {
            out.resize(PKT_BUF, 0);
        }
        let mut tunn = peer.tunn.lock().unwrap();
        let base = out.as_ptr() as usize;
        let src_ip = match src {
            Src::Udp(addr) => Some(addr.ip()),
            Src::Relay => None,
        };
        match tunn.decapsulate(src_ip, dgram, &mut out[TUN_OFFSET..]) {
            TunnResult::WriteToNetwork(b) => {
                // Replies and packets queued during the handshake go back the way it came
                self.reply(&peer, b, src);
                while let TunnResult::WriteToNetwork(b) = tunn.decapsulate(None, &[], &mut out[TUN_OFFSET..]) {
                    self.reply(&peer, b, src);
                }
                drop(tunn);
                match src {
                    // Responses return the way the initiation came, so a UDP
                    // response proves both directions
                    Src::Udp(addr) if response => peer.confirm_direct(addr),
                    _ => self.note_rx(&peer, src, false),
                }
                false
            }
            TunnResult::WriteToTunnelV4(b, inner_src) => {
                let (start, len) = (b.as_ptr() as usize - base, b.len());
                drop(tunn);
                if !peer.allowed_src(&peer.routes()).permits(inner_src) {
                    tracing::debug!(%inner_src, "dropping packet with spoofed source");
                    return false;
                }
                self.note_rx(&peer, src, true);
                let own_routes = self.own_routes.read().unwrap().clone();
                if !peer.filter.inbound(&out[start..start + len], &self.here(&own_routes)) {
                    return false;
                }
                if start != TUN_OFFSET {
                    out.copy_within(start..start + len, TUN_OFFSET);
                }
                out.truncate(TUN_OFFSET + len);
                true
            }
            TunnResult::WriteToTunnelV6(..) => false,
            TunnResult::Done => {
                drop(tunn);
                match src {
                    Src::Udp(addr) if response => peer.confirm_direct(addr),
                    _ => self.note_rx(&peer, src, false),
                }
                false
            }
            TunnResult::Err(e) => {
                tracing::trace!(?src, "decapsulate: {e:?}");
                false
            }
        }
    }

    /// With a virtio-net header (Linux offload) runs of TCP segments are merged
    /// first, so a burst costs one write.
    async fn write_tun(&self, bufs: &mut [Vec<u8>], gro: &mut crate::gro::Coalescer) {
        let forward = self.forward.read().unwrap().clone();
        let own_routes = forward.as_ref().map(|_| self.own_routes.read().unwrap().clone()).unwrap_or_else(|| Arc::from(Vec::new()));
        let here = self.here(&own_routes);
        // Forwarding without the system's NAT: our stack takes what is not for this device
        let keep = |b: &mut [u8]| match &forward {
            Some(f) if b.len() >= 20 && b[16..20] != self.self_ip.octets() => {
                let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
                f.inbound(b, here.forwarded(dst))
            }
            Some(f) => f.inbound(b, false),
            None => true,
        };
        if !self.vnet_hdr {
            for b in bufs.iter_mut() {
                if keep(&mut b[TUN_OFFSET..]) {
                    self.tun_send(&b[TUN_OFFSET..]).await;
                }
            }
            return;
        }
        for b in bufs.iter_mut() {
            if !keep(&mut b[TUN_OFFSET..]) {
                continue;
            }
            if gro.try_append(&b[TUN_OFFSET..]) {
                continue;
            }
            if let Some(merged) = gro.finish() {
                self.tun_send(merged).await;
            }
            if !gro.start(&b[TUN_OFFSET..]) {
                // With vnet_hdr, TUN_OFFSET is exactly the virtio header length
                b[..TUN_OFFSET].fill(0);
                self.tun_send(b).await;
            }
        }
        if let Some(merged) = gro.finish() {
            self.tun_send(merged).await;
        }
    }

    /// Answers MagicDNS queries (see `magicdns`)
    pub async fn dns_loop(self: Arc<Self>) -> Result<()> {
        let Some(mut queries) = self.dns_queries_rx.lock().unwrap().take() else { return Ok(()) };
        while let Some(q) = queries.recv().await {
            let Some(reply) = crate::magicdns::answer(&q, &self.names.read().unwrap()) else { continue };
            if self.vnet_hdr {
                let mut buf = vec![0u8; TUN_OFFSET];
                buf.extend_from_slice(&reply);
                self.tun_send(&buf).await;
            } else {
                self.tun_send(&reply).await;
            }
        }
        Ok(())
    }

    pub fn subscribe_helper_role(&self) -> watch::Receiver<bool> {
        self.helper_role.subscribe()
    }

    pub fn set_helper_code(&self, code: Option<String>) {
        self.helper_code.send_if_modified(|c| std::mem::replace(c, code.clone()) != code);
    }

    pub fn subscribe_helper_code(&self) -> watch::Receiver<Option<String>> {
        self.helper_code.subscribe()
    }

    pub fn self_dns_name(&self) -> String {
        self.self_dns_name.lock().unwrap().clone()
    }

    async fn tun_send(&self, buf: &[u8]) {
        Stats::add(&self.stats.tun_writes, 1);
        if let Err(e) = self.tun.send(buf).await {
            tracing::debug!("TUN write: {e}");
        }
    }

    /// Drives WireGuard timers (retries, keepalives, rekeying) and fast
    /// handshake re-sends while a path is being punched.
    pub async fn timer_loop(self: Arc<Self>) -> Result<()> {
        let mut tick = tokio::time::interval(PUNCH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut out = vec![0u8; MAX_PACKET];
        let mut last_stats = Instant::now();
        let mut last_memory_check = Instant::now();
        loop {
            tick.tick().await;
            if let Some(limit) = self.memory_limit_mb
                && last_memory_check.elapsed() >= MEMORY_CHECK
            {
                last_memory_check = Instant::now();
                if crate::memory::current().is_some_and(|now| now > u64::from(limit) << 20) {
                    crate::memory::trim();
                }
            }
            if last_stats.elapsed() >= Duration::from_secs(10) {
                last_stats = Instant::now();
                for p in self.peers.read().unwrap().by_key.values() {
                    p.filter.expire();
                }
                if let Some(line) = self.stats.take_line() {
                    tracing::debug!("batching: {line}");
                    tracing::debug!("stages: {}", self.stats.take_stages(Duration::from_secs(10)));
                } else {
                    self.stats.take_stages(Duration::from_secs(10));
                }
            }
            let peers: Vec<Arc<Peer>> = self.peers.read().unwrap().by_key.values().cloned().collect();
            for p in peers {
                let (result, established, tx, rx) = {
                    let mut tunn = p.tunn.lock().unwrap();
                    let r = match tunn.update_timers(&mut out) {
                        TunnResult::WriteToNetwork(b) => Some(b.len()),
                        TunnResult::Err(WireGuardError::ConnectionExpired) => None,
                        TunnResult::Err(e) => {
                            tracing::trace!("timers: {e:?}");
                            None
                        }
                        _ => None,
                    };
                    let (_, tx, rx, _, _) = tunn.stats();
                    (r, tunn.time_since_last_handshake().is_some(), tx as u64, rx as u64)
                };
                if established && p.check_liveness(tx, rx) != Liveness::Fine {
                    // Proof of life for a sender, or the first relayed packet after
                    // a direct path was lost
                    let n = p.tunn.lock().unwrap().encapsulate(&[], &mut out).len_if_network();
                    if let Some(n) = n {
                        self.send_to_peer(&p, &out[..n]);
                    }
                }
                if let Some(n) = result {
                    self.send_to_peer(&p, &out[..n]);
                } else if !established {
                    self.resend_init(&p);
                } else if let Some(handshake) = p.probe_due() {
                    // After a lost path only a handshake works as a probe,
                    // since its UDP answer proves both directions
                    let n = {
                        let mut tunn = p.tunn.lock().unwrap();
                        if handshake {
                            tunn.format_handshake_initiation(&mut out, true).len_if_network()
                        } else {
                            tunn.encapsulate(&[], &mut out).len_if_network()
                        }
                    };
                    if let Some(n) = n {
                        for dst in p.candidates() {
                            self.send_now(&out[..n], dst);
                        }
                    }
                }
            }
        }
    }

    pub fn set_control_problem(&self, problem: Option<retail_proto::api::ConnectionProblem>) {
        let mut p = self.control_problem.lock().unwrap();
        let since = p.as_ref().map_or_else(Instant::now, |(_, at)| *at);
        *p = problem.map(|x| (x, since));
    }

    /// Once tries have failed for a few seconds: a way that fails while
    /// another is about to work says nothing to the user
    pub fn control_problem(&self) -> Option<retail_proto::api::ConnectionProblem> {
        let p = self.control_problem.lock().unwrap();
        p.as_ref().filter(|(_, at)| at.elapsed() >= Duration::from_secs(3)).map(|(x, _)| x.clone())
    }

    pub fn set_control_via(&self, via: Option<String>) {
        *self.control_via.lock().unwrap() = via;
    }

    pub fn control_via(&self) -> Option<String> {
        self.control_via.lock().unwrap().clone()
    }

    pub fn set_control_addr(&self, addr: SocketAddr) {
        let addr = canonical(addr);
        let changed = self.control_addr.lock().unwrap().replace(addr) != Some(addr);
        if changed {
            self.stun_now.notify_one();
        }
    }

    /// Asks STUN servers for our public address from the tunnel's own socket
    pub async fn discovery_loop(self: Arc<Self>, default_stun: String) -> Result<()> {
        let mut tick = tokio::time::interval(DISCOVERY_RETRY);
        let mut last_round: Option<Instant> = None;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                () = self.stun_now.notified() => last_round = None,
            }
            let answered = self.stun_public.lock().unwrap().iter().any(Option::is_some);
            if answered && last_round.is_some_and(|t| t.elapsed() < DISCOVERY_INTERVAL) {
                continue;
            }
            last_round = Some(Instant::now());
            self.stun_pending
                .lock()
                .unwrap()
                .retain(|_, t| t.elapsed() < Duration::from_secs(10));

            let mut servers = self.stun_servers.lock().unwrap().clone();
            if servers.is_empty() {
                let control = *self.control_addr.lock().unwrap();
                servers.push(match control {
                    Some(addr) => SocketAddr::new(addr.ip(), retail_proto::DEFAULT_STUN_PORT).to_string(),
                    None => default_stun.clone(),
                });
            }
            for server in servers {
                match tokio::net::lookup_host(server.as_str()).await {
                    Ok(addrs) => {
                        // The public IPv4 and IPv6 endpoints are separate candidates
                        let addrs: Vec<SocketAddr> = addrs.map(canonical).collect();
                        let v4 = addrs.iter().find(|a| a.is_ipv4());
                        let v6 = addrs.iter().find(|a| a.is_ipv6()).filter(|_| self.dual_stack);
                        let nat64 = crate::happy::nat64_cached()
                            .filter(|_| self.dual_stack && v6.is_none())
                            .and_then(|p| crate::happy::synthesize(p, *v4?));
                        for addr in v4.into_iter().chain(v6).chain(nat64.as_ref()) {
                            let mut tx = [0u8; 12];
                            rand::rngs::OsRng.fill_bytes(&mut tx);
                            self.stun_pending.lock().unwrap().insert(tx, Instant::now());
                            self.send_now(&stun::binding_request(&tx), *addr);
                        }
                    }
                    Err(e) => tracing::debug!(%server, "resolving STUN server: {e}"),
                }
            }
            self.publish_endpoints();
        }
    }

    fn handle_stun(&self, pkt: &[u8]) {
        let Some((tx, addr)) = stun::parse_binding_response(pkt) else {
            return;
        };
        if self.stun_pending.lock().unwrap().remove(&tx).is_none() {
            return;
        }
        let addr = canonical(addr);
        // A STUN server on this very device (hosting) answers with loopback
        if !usable_ip(addr.ip()) {
            return;
        }
        let family = usize::from(addr.is_ipv6());
        let mut public = self.stun_public.lock().unwrap();
        if public[family] != Some(addr) {
            tracing::info!(%addr, "public endpoint discovered via STUN");
            public[family] = Some(addr);
        }
        drop(public);
        self.publish_endpoints();
    }

    /// Public endpoints known without STUN (the router's port mapping while
    /// hosting a network).
    pub fn set_extra_endpoints(&self, eps: Vec<SocketAddr>) {
        *self.extra_endpoints.lock().unwrap() = eps;
        self.publish_endpoints();
    }

    fn publish_endpoints(&self) {
        let mut eps = local_endpoints(self.listen_port, self.dual_stack);
        let extra = self.extra_endpoints.lock().unwrap().clone();
        for public in self.stun_public.lock().unwrap().iter().flatten().chain(extra.iter()).rev() {
            if !eps.contains(public) {
                eps.insert(0, *public);
            }
        }
        self.endpoints.send_if_modified(|cur| {
            if *cur != eps {
                *cur = eps;
                true
            } else {
                false
            }
        });
    }

    pub fn peer_status(&self) -> Vec<PeerStatus> {
        let peers: Vec<Arc<Peer>> = self.peers.read().unwrap().by_key.values().cloned().collect();
        let mut out: Vec<PeerStatus> = peers
            .iter()
            .map(|p| {
                let (handshake, tx, rx, _, _) = p.tunn.lock().unwrap().stats();
                let info = p.info.lock().unwrap();
                let path = match (info.direct_ok(), info.uses_relay()) {
                    (Some(ep), _) => Some(format!("direct {ep}")),
                    (None, true) => Some("relay".to_string()),
                    (None, false) => None,
                };
                PeerStatus {
                    dns_name: info.dns_name.clone(),
                    restricted: p.filter.restricted(),
                    hostname: info.hostname.clone(),
                    ip: info.ip,
                    node_key: p.key,
                    online: info.online,
                    endpoint: info.direct_ok(),
                    path,
                    candidates: info.candidates.clone(),
                    last_handshake_secs: handshake.map(|d| d.as_secs()),
                    exit_node: info.exit_node,
                    tx_bytes: tx as u64,
                    rx_bytes: rx as u64,
                    routes: p.routes().to_vec(),
                }
            })
            .collect();
        out.sort_by_key(|p| p.ip);
        out
    }
}

/// Names from the server end up in terminals (`retail status`) and the tray.
/// The server cleans the names it hands out, but this device does not depend
/// on that: control characters (terminal escape sequences) are dropped and
/// the length is bounded.
fn display_safe(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).take(253).collect()
}

/// Subnet routes as the system should see them
#[derive(Clone, Default, PartialEq, Debug)]
pub struct RouteState {
    /// Networks this device routes for the others (forwarding)
    pub own: Vec<Ipv4Net>,
    /// Networks reached through peers (routes into the tunnel)
    pub accepted: Vec<Ipv4Net>,
}

pub type DataPlaneTask = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

type Stage<T> = (mpsc::Sender<T>, mpsc::Receiver<T>);

/// A bounded "full" channel plus a "free" channel pre-filled with `depth` buffers
fn pipeline<T>(depth: usize, make: impl Fn() -> T) -> (Stage<T>, Stage<T>) {
    let full = mpsc::channel(depth);
    let free = mpsc::channel(depth);
    for _ in 0..depth {
        free.0.try_send(make()).expect("free list has room for every buffer");
    }
    (full, free)
}

/// One TUN read on its way through encrypt to udp-send
struct TxJob {
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    n: usize,
    /// Set by tun-read: packets grouped per peer, with reserved counters
    runs: Vec<TxRun>,
    /// Set by encrypt: the datagrams, back to back, and how to send them
    out: Vec<u8>,
    sends: Vec<TxSend>,
}

impl TxJob {
    fn new() -> Self {
        TxJob {
            bufs: (0..TUN_BATCH).map(|_| vec![0u8; PKT_BUF]).collect(),
            sizes: vec![0; TUN_BATCH],
            n: 0,
            runs: Vec::with_capacity(4),
            out: Vec::with_capacity(TUN_BATCH * (TUN_MTU as usize + crate::crypto::OVERHEAD)),
            sends: Vec::with_capacity(8),
        }
    }
}

/// Consecutive packets of a TUN read for one peer
struct TxRun {
    range: std::ops::Range<usize>,
    peer: Arc<Peer>,
    /// The session and the first of `range.len()` reserved send counters,
    /// `None` until a handshake has completed.
    session: Option<(Arc<boringtun::noise::Session>, u64)>,
}

#[derive(Clone, Copy)]
enum Dest {
    /// One GSO send
    Udp(SocketAddr),
    /// One relay frame
    Relay,
    /// A single datagram along every route worth trying (`Engine::send_to_peer`)
    Search,
}

/// `count` datagrams of `seg` bytes (the last may be shorter) at
/// `out[start..start + total]`.
struct TxSend {
    peer: Arc<Peer>,
    dst: Dest,
    start: usize,
    seg: usize,
    count: usize,
    total: usize,
}

/// One received GRO train (datagrams of `stride` bytes from `src`), with the
/// buffer it was received into.
struct Train {
    buf: Vec<u8>,
    len: usize,
    stride: usize,
    src: SocketAddr,
}

struct RxBatch {
    bufs: Vec<Vec<u8>>,
    len: usize,
}

/// Buffers for relayed packets, kept by the control connection
pub struct RelayRx {
    batch: RxBatch,
    gro: crate::gro::Coalescer,
}

impl RelayRx {
    pub fn new() -> Self {
        RelayRx { batch: RxBatch::new(), gro: crate::gro::Coalescer::new() }
    }
}

impl RxBatch {
    fn new() -> Self {
        RxBatch {
            bufs: (0..RX_BATCH).map(|_| vec![0u8; PKT_BUF]).collect(),
            len: 0,
        }
    }
}

/// Splits datagram lengths into GSO groups: runs of equal-sized datagrams
/// where only the last may be shorter, at most `max_segments` and `max_bytes`
/// per group. Returns (first index, count) pairs.
fn gso_groups(lens: &[usize], max_segments: usize, max_bytes: usize) -> Vec<(usize, usize)> {
    let mut groups = Vec::new();
    let mut i = 0;
    while i < lens.len() {
        let seg = lens[i];
        let (mut count, mut bytes) = (1, seg);
        while i + count < lens.len() && count < max_segments.max(1) {
            let next = lens[i + count];
            if next > seg || bytes + next > max_bytes {
                break;
            }
            count += 1;
            bytes += next;
            if next < seg {
                break; // A short datagram ends the group
            }
        }
        groups.push((i, count));
        i += count;
    }
    groups
}

/// Crypto workers per direction, from `RETAIL_CRYPTO_THREADS` or the default
/// for this platform (`batched`: TUN offload and UDP GRO are both active).
fn crypto_workers(batched: bool) -> usize {
    std::env::var("RETAIL_CRYPTO_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            if batched && cores >= 4 { DEFAULT_CRYPTO_WORKERS } else { 1 }
        })
        .clamp(1, MAX_CRYPTO_WORKERS)
}

trait TunnResultExt {
    fn len_if_network(self) -> Option<usize>;
}

impl TunnResultExt for TunnResult<'_> {
    fn len_if_network(self) -> Option<usize> {
        match self {
            TunnResult::WriteToNetwork(b) => Some(b.len()),
            _ => None,
        }
    }
}

/// Raises the socket buffers so bursts are queued rather than dropped. As root
/// on Linux the `*FORCE` variants bypass `net.core.{r,w}mem_max`.
fn set_socket_buffers(udp: &UdpSocket) {
    let sock = socket2::SockRef::from(udp);
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = udp.as_raw_fd();
        let size = SOCKET_BUFFER as libc::c_int;
        for opt in [libc::SO_RCVBUFFORCE, libc::SO_SNDBUFFORCE] {
            // SAFETY: valid fd and a correctly sized c_int option value
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
    if sock.recv_buffer_size().unwrap_or(0) < SOCKET_BUFFER {
        let _ = sock.set_recv_buffer_size(SOCKET_BUFFER);
    }
    if sock.send_buffer_size().unwrap_or(0) < SOCKET_BUFFER {
        let _ = sock.set_send_buffer_size(SOCKET_BUFFER);
    }
    tracing::debug!(
        rcvbuf = sock.recv_buffer_size().unwrap_or(0),
        sndbuf = sock.send_buffer_size().unwrap_or(0),
        "UDP socket buffers"
    );
}

/// An address worth offering to peers: not loopback, link-local, multicast
/// or unspecified, and not inside the mesh itself.
fn usable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !in_mesh(ip),
        // fe80::/10 needs a scope id and only works on one link
        IpAddr::V6(ip) => {
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && (ip.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// IPv4 peers of a dual-stack socket show up as ::ffff:a.b.c.d
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// IPv6 with IPv4 mapped in where the system allows it, so both families race
/// as candidates, plain IPv4 otherwise.
fn bind_udp(port: u16) -> std::io::Result<(std::net::UdpSocket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).and_then(|s| {
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok(s)
    });
    let (sock, is_dual) = match dual {
        Ok(s) => (s, true),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Err(e),
        Err(e) => {
            tracing::info!("IPv6 unavailable ({e}); using IPv4 only");
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            (s, false)
        }
    };
    if let Err(e) = crate::exit::bypass(socket2::SockRef::from(&sock)) {
        tracing::debug!("marking the UDP socket: {e}");
    }
    sock.set_nonblocking(true)?;
    Ok((sock.into(), is_dual))
}

fn local_endpoints(port: u16, ipv6: bool) -> Vec<SocketAddr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut eps: Vec<SocketAddr> = ifaces
        .into_iter()
        .map(|i| i.ip())
        .filter(|ip| usable_ip(*ip) && (ip.is_ipv4() || ipv6))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    eps.sort();
    eps.dedup();
    eps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_helpers() {
        let mapped: SocketAddr = "[::ffff:198.51.100.2]:41641".parse().unwrap();
        assert_eq!(canonical(mapped), "198.51.100.2:41641".parse().unwrap());
        assert!(usable_ip("2001:db8::10".parse().unwrap()));
        assert!(usable_ip("fd00::1".parse().unwrap()));
        assert!(!usable_ip("fe80::1".parse().unwrap()));
        assert!(!usable_ip("::1".parse().unwrap()));
        assert!(!usable_ip("100.64.0.3".parse().unwrap()), "mesh addresses are not candidates");
        assert!(usable_ip("192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn gso_grouping() {
        // A short tail closes the group
        assert_eq!(gso_groups(&[100, 100, 100, 60, 100], 64, 64000), vec![(0, 4), (4, 1)]);
        assert_eq!(gso_groups(&[10; 5], 2, 64000), vec![(0, 2), (2, 2), (4, 1)]);
        assert_eq!(gso_groups(&[100; 4], 64, 250), vec![(0, 2), (2, 2)]);
        // A larger datagram starts a new group
        assert_eq!(gso_groups(&[60, 100], 64, 64000), vec![(0, 1), (1, 1)]);
        assert!(gso_groups(&[], 64, 64000).is_empty());
    }

    #[test]
    fn memory_limit_picks_the_fastest_plan_that_fits() {
        let gro_slot = 64 * 1024;
        let base = 6 << 20;
        let sizes: Vec<u64> = PLANS.iter().map(|p| p.bytes(gro_slot)).collect();
        assert!(sizes.windows(2).all(|w| w[0] > w[1]), "{sizes:?}");
        let roomy = buffer_plan(Some(64), true, gro_slot, base);
        let tight = buffer_plan(Some(9), true, gro_slot, base);
        assert!(tight.bytes(gro_slot) < roomy.bytes(gro_slot));
        assert!(base + MEMORY_OVERHEAD + tight.bytes(gro_slot) <= 9 << 20);
        // An impossible limit still yields the smallest working plan
        assert_eq!(buffer_plan(Some(1), true, gro_slot, base), PLANS[PLANS.len() - 1]);
    }

    #[test]
    fn handshake_init_detection() {
        let mut p = vec![0u8; 148];
        p[0] = 1;
        assert!(is_handshake_init(&p));
        p[0] = 4;
        assert!(!is_handshake_init(&p));
        assert!(!is_handshake_init(&[1, 0, 0, 0]));
    }
}
