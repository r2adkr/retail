//! Forwarding for the mesh through this device's own TCP/IP stack, where the
//! system has no NAT to do it (Windows Home has no WinNAT). Packets from
//! peers to the internet or a routed network never leave as they are:
//! - TCP: the destination is dialled first. Then the peer's packets get a
//!   listener on this device's mesh address as their destination (and a port
//!   of ours as their source port), so the system's TCP stack takes the
//!   connection, which is spliced to the dialled one. Its replies get the
//!   original addresses back on their way to the peer.
//! - UDP: a socket per peer port sends for it and takes the answers.
//! - Echo requests: the system's ping.
//!
//! The peer's address stays, so the system's replies still route into the
//! TUN device. A destination that cannot be reached is answered with a reset,
//! as it would be without us in between.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{AbortHandle, JoinSet};

use crate::engine::Engine;

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

const MAX_TCP: usize = 4096;
const MAX_TCP_PER_PEER: usize = 1024;
const MAX_UDP: usize = 1024;
const MAX_PINGS: usize = 32;
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// A dialled connection the system never took
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// A port stays taken this long after its connection ends: the system's
/// TIME_WAIT (up to 4 minutes on Windows)
const LINGER: Duration = Duration::from_secs(240);
const UDP_IDLE: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
/// Per direction and connection; the system's socket buffers do the rest
const SPLICE_BUF: usize = 16 * 1024;
const MTU: usize = retail_proto::TUN_MTU as usize;
const FIRST_PORT: u16 = 1024;

/// A peer's connection as it sent it
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Conn {
    peer: SocketAddrV4,
    dst: SocketAddrV4,
}

enum Stage {
    /// The peer's SYN waits for the destination
    Dialing(Vec<u8>),
    /// The SYN went to the system, which has yet to accept it
    Dialled(Option<TcpStream>, Instant),
    Open,
    Closed(Instant),
}

struct Entry {
    port: u16,
    stage: Stage,
}

#[derive(Default)]
struct Table {
    conns: HashMap<Conn, Entry>,
    /// (peer's address, our port) → its connection
    ports: HashMap<(Ipv4Addr, u16), Conn>,
    per_peer: HashMap<Ipv4Addr, usize>,
    next: u16,
}

impl Table {
    fn add(&mut self, conn: Conn, syn: Vec<u8>) -> Option<u16> {
        let ip = *conn.peer.ip();
        if self.conns.len() >= MAX_TCP || self.per_peer.get(&ip).copied().unwrap_or(0) >= MAX_TCP_PER_PEER {
            return None;
        }
        let mut port = None;
        for _ in FIRST_PORT..=u16::MAX {
            self.next = if self.next < FIRST_PORT || self.next == u16::MAX { FIRST_PORT } else { self.next + 1 };
            if !self.ports.contains_key(&(ip, self.next)) {
                port = Some(self.next);
                break;
            }
        }
        let port = port?;
        self.conns.insert(conn, Entry { port, stage: Stage::Dialing(syn) });
        self.ports.insert((ip, port), conn);
        *self.per_peer.entry(ip).or_default() += 1;
        Some(port)
    }

    fn remove(&mut self, conn: &Conn) -> Option<Entry> {
        let e = self.conns.remove(conn)?;
        let ip = *conn.peer.ip();
        self.ports.remove(&(ip, e.port));
        if let Some(n) = self.per_peer.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                self.per_peer.remove(&ip);
            }
        }
        Some(e)
    }
}

struct Udp {
    sock: Arc<std::net::UdpSocket>,
    /// Seconds since `Shared::epoch`
    last: Arc<AtomicU64>,
    task: AbortHandle,
}

struct Shared {
    /// The listener the system takes connections on
    me: SocketAddrV4,
    engine: Weak<Engine>,
    rt: tokio::runtime::Handle,
    table: Mutex<Table>,
    udp: Mutex<HashMap<SocketAddrV4, Udp>>,
    tasks: Mutex<JoinSet<()>>,
    pings: AtomicUsize,
    ip_id: AtomicU16,
    epoch: Instant,
}

pub struct Forward {
    shared: Arc<Shared>,
}

impl Forward {
    /// Listens on `ip`, this device's mesh address
    pub fn start(engine: &Arc<Engine>, ip: Ipv4Addr) -> io::Result<Self> {
        let rt = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let listener = std::net::TcpListener::bind((ip, 0))?;
        listener.set_nonblocking(true)?;
        let SocketAddr::V4(me) = listener.local_addr()? else { return Err(io::Error::other("not an IPv4 listener")) };
        let shared = Arc::new(Shared {
            me,
            engine: Arc::downgrade(engine),
            rt,
            table: Mutex::default(),
            udp: Mutex::default(),
            tasks: Mutex::new(JoinSet::new()),
            pings: AtomicUsize::new(0),
            ip_id: AtomicU16::new(rand::random()),
            epoch: Instant::now(),
        });
        // The system's firewall would turn the readdressed connections away
        crate::firewall::allow_inbound();
        shared.spawn(accept_loop(shared.clone(), listener));
        shared.spawn(sweep(shared.clone()));
        tracing::info!(listener = %me, "forwarding for the mesh through this device's own network stack");
        Ok(Forward { shared })
    }

    /// A packet from a peer on its way to the TUN device; false if it is
    /// not to go there. `forwarded`: the filter found it is for the internet
    /// or a routed network.
    pub fn inbound(&self, p: &mut [u8], forwarded: bool) -> bool {
        let s = &self.shared;
        let Some(h) = Header::parse(p) else { return true };
        if !forwarded {
            // The listener takes readdressed connections only
            return !(h.proto == TCP && h.dst == *s.me.ip() && h.dport == s.me.port());
        }
        if h.fragment {
            return false;
        }
        match h.proto {
            TCP => s.tcp_in(p, &h),
            UDP => {
                s.udp_in(p, &h);
                false
            }
            ICMP if h.icmp_type == 8 => {
                s.ping(p, &h);
                false
            }
            _ => false,
        }
    }

    /// A packet from the TUN device: the system's side of a spliced
    /// connection gets its original addresses back
    pub fn outbound(&self, p: &mut [u8]) {
        let me = self.shared.me;
        if p.len() < 40 || p[9] != TCP || p[12..16] != me.ip().octets() {
            return;
        }
        let Some(h) = Header::parse(p) else { return };
        if h.sport != me.port() {
            return;
        }
        let conn = {
            let t = self.shared.table.lock().unwrap();
            t.ports.get(&(h.dst, h.dport)).copied()
        };
        if let Some(conn) = conn {
            readdress(p, conn.dst, conn.peer);
        }
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.shared.tasks.lock().unwrap().abort_all();
        crate::firewall::release_inbound();
    }
}

impl Shared {
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> AbortHandle {
        self.tasks.lock().unwrap().spawn_on(task, &self.rt)
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn tcp_in(self: &Arc<Self>, p: &mut [u8], h: &Header) -> bool {
        let conn = Conn { peer: SocketAddrV4::new(h.src, h.sport), dst: SocketAddrV4::new(h.dst, h.dport) };
        let mut t = self.table.lock().unwrap();
        if let Some(e) = t.conns.get(&conn) {
            // Repeated SYNs wait with the first
            if matches!(e.stage, Stage::Dialing(_)) {
                return false;
            }
            readdress(p, SocketAddrV4::new(h.src, e.port), self.me);
            return true;
        }
        if h.flags & (SYN | ACK) != SYN {
            drop(t);
            // Not one of ours (from before a restart, say): the peer learns at once
            if h.flags & RST == 0 {
                self.reset(p, h);
            }
            return false;
        }
        if t.add(conn, p.to_vec()).is_none() {
            drop(t);
            self.reset(p, h);
            return false;
        }
        drop(t);
        self.spawn(dial(self.clone(), conn));
        false
    }

    /// Answers `p` with a reset from where it was going
    fn reset(&self, p: &[u8], h: &Header) {
        let (seq, ack, flags) = if h.flags & ACK != 0 {
            (h.ack, 0, RST)
        } else {
            let len = p.len().saturating_sub(h.l4 + h.tcp_len) as u32;
            let extra = u32::from(h.flags & SYN != 0) + u32::from(h.flags & FIN != 0);
            (0, h.seq.wrapping_add(len + extra), RST | ACK)
        };
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&h.dport.to_be_bytes());
        tcp[2..4].copy_from_slice(&h.sport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        let sum = l4_checksum(h.dst, h.src, TCP, &tcp);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        self.send(h.dst, h.src, TCP, &tcp);
    }

    fn accepted(&self, from: SocketAddrV4) -> Option<(Conn, TcpStream)> {
        let mut t = self.table.lock().unwrap();
        let conn = *t.ports.get(&(*from.ip(), from.port()))?;
        let e = t.conns.get_mut(&conn)?;
        let Stage::Dialled(stream, _) = &mut e.stage else { return None };
        let stream = stream.take()?;
        e.stage = Stage::Open;
        Some((conn, stream))
    }

    fn closed(&self, conn: Conn) {
        if let Some(e) = self.table.lock().unwrap().conns.get_mut(&conn) {
            e.stage = Stage::Closed(Instant::now());
        }
    }

    fn udp_in(self: &Arc<Self>, p: &[u8], h: &Header) {
        let Some(payload) = p.get(h.l4 + 8..) else { return };
        let client = SocketAddrV4::new(h.src, h.sport);
        let now = self.now();
        let sock = {
            let mut flows = self.udp.lock().unwrap();
            match flows.get(&client) {
                Some(f) => {
                    f.last.store(now, Ordering::Relaxed);
                    f.sock.clone()
                }
                None => {
                    if flows.len() >= MAX_UDP
                        && let Some(oldest) = flows.iter().min_by_key(|(_, f)| f.last.load(Ordering::Relaxed)).map(|(k, _)| *k)
                        && let Some(f) = flows.remove(&oldest)
                    {
                        f.task.abort();
                    }
                    let Ok(sock) = udp_socket() else { return };
                    let Ok(reader) = sock.try_clone() else { return };
                    let last = Arc::new(AtomicU64::new(now));
                    let task = self.spawn(udp_reader(self.clone(), client, reader, last.clone()));
                    let sock = Arc::new(sock);
                    flows.insert(client, Udp { sock: sock.clone(), last, task });
                    sock
                }
            }
        };
        // Full socket buffer: dropped, as a congested link would
        let _ = sock.send_to(payload, SocketAddrV4::new(h.dst, h.dport));
    }

    fn ping(self: &Arc<Self>, p: &[u8], h: &Header) {
        if self.pings.fetch_add(1, Ordering::Relaxed) >= MAX_PINGS {
            self.pings.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        let Some(icmp) = p.get(h.l4..).filter(|i| i.len() >= 8).map(<[u8]>::to_vec) else {
            self.pings.fetch_sub(1, Ordering::Relaxed);
            return;
        };
        let (s, src, dst) = (self.clone(), h.src, h.dst);
        self.rt.spawn_blocking(move || {
            if echo(dst, &icmp[8..]) {
                let mut reply = icmp;
                reply[0] = 0;
                reply[2..4].fill(0);
                let sum = checksum(&reply, 0);
                reply[2..4].copy_from_slice(&sum.to_be_bytes());
                s.send(dst, src, ICMP, &reply);
            }
            s.pings.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// To a peer, in fragments if it does not fit the tunnel
    fn send(&self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) {
        let Some(engine) = self.engine.upgrade() else { return };
        let id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        for p in ipv4_packets(src, dst, proto, id, l4) {
            engine.send_ip(&p);
        }
    }
}

async fn dial(s: Arc<Shared>, conn: Conn) {
    let dialled = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(conn.dst)).await;
    let syn = {
        let mut t = s.table.lock().unwrap();
        let Some(e) = t.conns.get_mut(&conn) else { return };
        match dialled {
            Ok(Ok(stream)) => {
                let Stage::Dialing(mut syn) = std::mem::replace(&mut e.stage, Stage::Dialled(Some(stream), Instant::now())) else {
                    return;
                };
                readdress(&mut syn, SocketAddrV4::new(*conn.peer.ip(), e.port), s.me);
                Ok(syn)
            }
            _ => match t.remove(&conn) {
                Some(Entry { stage: Stage::Dialing(syn), .. }) => Err(syn),
                _ => return,
            },
        }
    };
    match syn {
        Ok(syn) => {
            if let Some(engine) = s.engine.upgrade() {
                engine.write_ip(&syn).await;
            }
        }
        Err(syn) => {
            if let Some(h) = Header::parse(&syn) {
                s.reset(&syn, &h);
            }
        }
    }
}

async fn accept_loop(s: Arc<Shared>, listener: std::net::TcpListener) {
    let listener = match TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("forwarding listener: {e}");
            return;
        }
    };
    let mut splices = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((inbound, SocketAddr::V4(from))) = accepted else { continue };
                // Anything else is closed again
                let Some((conn, upstream)) = s.accepted(from) else { continue };
                let s = s.clone();
                splices.spawn(async move {
                    splice(inbound, upstream).await;
                    s.closed(conn);
                });
            }
            Some(_) = splices.join_next(), if !splices.is_empty() => {}
        }
    }
}

async fn splice(a: TcpStream, b: TcpStream) {
    let _ = a.set_nodelay(true);
    let _ = b.set_nodelay(true);
    let (ar, aw) = a.into_split();
    let (br, bw) = b.into_split();
    // An error either way ends both
    let _ = tokio::try_join!(pipe(ar, bw), pipe(br, aw));
}

/// Buffers between reads, so an idle connection holds none
static SPARE: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());
const SPARE_MAX: usize = 32;

fn give_back(buf: Box<[u8]>) {
    let mut spare = SPARE.lock().unwrap();
    if spare.len() < SPARE_MAX {
        spare.push(buf);
    }
}

async fn pipe(from: OwnedReadHalf, mut to: OwnedWriteHalf) -> io::Result<()> {
    loop {
        from.readable().await?;
        let mut buf = SPARE.lock().unwrap().pop().unwrap_or_else(|| vec![0; SPLICE_BUF].into_boxed_slice());
        let done = loop {
            match from.try_read(&mut buf) {
                Ok(0) => break Ok(true),
                Ok(n) => {
                    if let Err(e) = to.write_all(&buf[..n]).await {
                        break Err(e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break Ok(false),
                Err(e) => break Err(e),
            }
        };
        give_back(buf);
        if done? {
            return to.shutdown().await;
        }
    }
}

async fn sweep(s: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        {
            let mut t = s.table.lock().unwrap();
            let gone: Vec<Conn> = t
                .conns
                .iter()
                .filter(|(_, e)| match e.stage {
                    Stage::Dialled(_, at) => at.elapsed() > ACCEPT_TIMEOUT,
                    Stage::Closed(at) => at.elapsed() > LINGER,
                    _ => false,
                })
                .map(|(c, _)| *c)
                .collect();
            for c in gone {
                t.remove(&c);
            }
        }
        let now = s.now();
        s.udp.lock().unwrap().retain(|_, f| {
            let keep = now.saturating_sub(f.last.load(Ordering::Relaxed)) < UDP_IDLE.as_secs();
            if !keep {
                f.task.abort();
            }
            keep
        });
        let mut tasks = s.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
    }
}

fn udp_socket() -> io::Result<std::net::UdpSocket> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

thread_local! {
    static DATAGRAM: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 65536]);
}

async fn udp_reader(s: Arc<Shared>, client: SocketAddrV4, sock: std::net::UdpSocket, last: Arc<AtomicU64>) {
    let Ok(sock) = UdpSocket::from_std(sock) else { return };
    loop {
        if sock.readable().await.is_err() {
            return;
        }
        let got = DATAGRAM.with_borrow_mut(|buf| match sock.try_recv_from(buf) {
            Ok((n, SocketAddr::V4(from))) => Ok(Some((from, buf[..n].to_vec()))),
            Ok(_) => Ok(None),
            // Windows reports an earlier datagram's ICMP error here
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionReset) => Ok(None),
            Err(e) => Err(e),
        });
        match got {
            Ok(Some((from, data))) => {
                last.store(s.now(), Ordering::Relaxed);
                let udp = udp_datagram(from, client, &data);
                s.send(*from.ip(), *client.ip(), UDP, &udp);
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

/// The parts of an IPv4 packet this looks at
struct Header {
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    /// Where the transport header starts
    l4: usize,
    fragment: bool,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    tcp_len: usize,
    icmp_type: u8,
}

impl Header {
    fn parse(p: &[u8]) -> Option<Header> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let l4 = (p[0] & 0x0f) as usize * 4;
        let frag = u16::from_be_bytes([p[6], p[7]]);
        let mut h = Header {
            proto: p[9],
            src: Ipv4Addr::new(p[12], p[13], p[14], p[15]),
            dst: Ipv4Addr::new(p[16], p[17], p[18], p[19]),
            l4,
            fragment: frag & 0x3fff != 0,
            sport: 0,
            dport: 0,
            seq: 0,
            ack: 0,
            flags: 0,
            tcp_len: 0,
            icmp_type: 0,
        };
        let t = p.get(l4..)?;
        match h.proto {
            TCP if t.len() >= 20 => {
                h.sport = u16::from_be_bytes([t[0], t[1]]);
                h.dport = u16::from_be_bytes([t[2], t[3]]);
                h.seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
                h.ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
                h.tcp_len = (t[12] >> 4) as usize * 4;
                h.flags = t[13];
            }
            UDP if t.len() >= 8 => {
                h.sport = u16::from_be_bytes([t[0], t[1]]);
                h.dport = u16::from_be_bytes([t[2], t[3]]);
            }
            ICMP if t.len() >= 8 => h.icmp_type = t[0],
            TCP | UDP | ICMP if !h.fragment => return None,
            _ => {}
        }
        Some(h)
    }
}

/// Gives a TCP packet new addresses and ports, keeping its checksums right
fn readdress(p: &mut [u8], src: SocketAddrV4, dst: SocketAddrV4) {
    let l4 = (p[0] & 0x0f) as usize * 4;
    if p.len() < l4 + 18 {
        return;
    }
    let mut old = [0u8; 12];
    old[..8].copy_from_slice(&p[12..20]);
    old[8..12].copy_from_slice(&p[l4..l4 + 4]);
    let mut new = [0u8; 12];
    new[..4].copy_from_slice(&src.ip().octets());
    new[4..8].copy_from_slice(&dst.ip().octets());
    new[8..10].copy_from_slice(&src.port().to_be_bytes());
    new[10..12].copy_from_slice(&dst.port().to_be_bytes());
    p[12..20].copy_from_slice(&new[..8]);
    p[l4..l4 + 4].copy_from_slice(&new[8..]);
    let ip_sum = adjust(u16::from_be_bytes([p[10], p[11]]), &old[..8], &new[..8]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    // The addresses are in the TCP checksum's pseudo-header too
    let tcp_sum = adjust(u16::from_be_bytes([p[l4 + 16], p[l4 + 17]]), &old, &new);
    p[l4 + 16..l4 + 18].copy_from_slice(&tcp_sum.to_be_bytes());
}

/// RFC 1624: a checksum after 16-bit words changed from `old` to `new`
fn adjust(sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u32::from(!sum);
    for (o, n) in old.chunks(2).zip(new.chunks(2)) {
        acc += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        acc += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut acc = initial;
    for c in data.chunks(2) {
        acc += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> u16 {
    let mut pseudo = 0u32;
    for c in src.octets().chunks(2).chain(dst.octets().chunks(2)) {
        pseudo += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    pseudo += u32::from(proto) + l4.len() as u32;
    checksum(l4, pseudo)
}

fn udp_datagram(from: SocketAddrV4, to: SocketAddrV4, data: &[u8]) -> Vec<u8> {
    let len = 8 + data.len();
    let mut udp = Vec::with_capacity(len);
    udp.extend_from_slice(&from.port().to_be_bytes());
    udp.extend_from_slice(&to.port().to_be_bytes());
    udp.extend_from_slice(&(len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(data);
    let sum = match l4_checksum(*from.ip(), *to.ip(), UDP, &udp) {
        0 => 0xffff,
        s => s,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    udp
}

/// IPv4 packets carrying `l4`, fragmented to fit the tunnel
fn ipv4_packets(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, id: u16, l4: &[u8]) -> Vec<Vec<u8>> {
    if 20 + l4.len() > u16::MAX as usize {
        return Vec::new();
    }
    let room = (MTU - 20) & !7;
    let mut out = Vec::with_capacity(l4.len() / room + 1);
    let mut at = 0;
    loop {
        let end = (at + room).min(l4.len());
        let more = end < l4.len();
        let total = 20 + end - at;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&id.to_be_bytes());
        let frag = (at / 8) as u16 | if more { 0x2000 } else { 0 };
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let sum = checksum(&p[..20], 0);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p[20..].copy_from_slice(&l4[at..end]);
        out.push(p);
        if !more {
            return out;
        }
        at = end;
    }
}

/// Whether `dst` answers an echo request carrying `data`
#[cfg(target_os = "windows")]
fn echo(dst: Ipv4Addr, data: &[u8]) -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
    let Ok(size) = u16::try_from(data.len()) else { return false };
    let mut reply = vec![0u8; size_of::<ICMP_ECHO_REPLY>() + data.len() + 8 + 64];
    // SAFETY: valid buffers of the stated sizes for the call's duration; the handle is closed after use
    unsafe {
        let h = IcmpCreateFile();
        if h == INVALID_HANDLE_VALUE {
            return false;
        }
        let n = IcmpSendEcho(
            h,
            u32::from_ne_bytes(dst.octets()),
            data.as_ptr().cast(),
            size,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            PING_TIMEOUT.as_millis() as u32,
        );
        IcmpCloseHandle(h);
        n > 0 && std::ptr::read_unaligned(reply.as_ptr().cast::<ICMP_ECHO_REPLY>()).Status == 0
    }
}

#[cfg(unix)]
fn echo(dst: Ipv4Addr, data: &[u8]) -> bool {
    use std::io::Read;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let Ok(sock) = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) else { return false };
    let id: u16 = rand::random();
    let mut req = vec![8, 0, 0, 0];
    req.extend_from_slice(&id.to_be_bytes());
    req.extend_from_slice(&1u16.to_be_bytes());
    req.extend_from_slice(data);
    let sum = checksum(&req, 0);
    req[2..4].copy_from_slice(&sum.to_be_bytes());
    if sock.send_to(&req, &SockAddr::from(SocketAddrV4::new(dst, 0))).is_err() {
        return false;
    }
    let deadline = Instant::now() + PING_TIMEOUT;
    let mut buf = [0u8; 2048];
    while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
        if sock.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        let Ok(n) = (&sock).read(&mut buf) else { return false };
        // A raw socket sees every echo reply, with its IP header
        let p = &buf[..n];
        let Some(h) = Header::parse(p) else { continue };
        let i = &p[h.l4..];
        if h.src == dst && h.icmp_type == 0 && i.len() >= 8 && i[4..6] == id.to_be_bytes() {
            return true;
        }
    }
    false
}

#[cfg(not(any(unix, target_os = "windows")))]
fn echo(_dst: Ipv4Addr, _data: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(src: SocketAddrV4, dst: SocketAddrV4, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp.extend_from_slice(payload);
        let sum = l4_checksum(*src.ip(), *dst.ip(), TCP, &tcp);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        ipv4_packets(*src.ip(), *dst.ip(), TCP, 7, &tcp).remove(0)
    }

    fn valid(p: &[u8]) -> bool {
        let h = Header::parse(p).unwrap();
        checksum(&p[..20], 0) == 0 && l4_checksum(h.src, h.dst, h.proto, &p[h.l4..]) == 0
    }

    #[test]
    fn readdressing_keeps_checksums() {
        let peer: SocketAddrV4 = "100.64.0.2:51000".parse().unwrap();
        let dst: SocketAddrV4 = "203.0.113.80:443".parse().unwrap();
        let mut p = tcp_packet(peer, dst, SYN, b"hello, odd length");
        assert!(valid(&p));
        let me: SocketAddrV4 = "100.64.0.1:40000".parse().unwrap();
        readdress(&mut p, SocketAddrV4::new(*peer.ip(), 1024), me);
        assert!(valid(&p));
        let h = Header::parse(&p).unwrap();
        assert_eq!((h.src, h.sport, h.dst, h.dport), (*peer.ip(), 1024, *me.ip(), me.port()));
    }

    #[test]
    fn big_datagrams_are_fragmented() {
        let from: SocketAddrV4 = "8.8.8.8:53".parse().unwrap();
        let to: SocketAddrV4 = "100.64.0.2:50000".parse().unwrap();
        let udp = udp_datagram(from, to, &[7u8; 3000]);
        let parts = ipv4_packets(*from.ip(), *to.ip(), UDP, 9, &udp);
        assert_eq!(parts.len(), 3);
        let mut whole = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            assert!(p.len() <= MTU && checksum(&p[..20], 0) == 0);
            let frag = u16::from_be_bytes([p[6], p[7]]);
            assert_eq!(frag & 0x2000 != 0, i < 2);
            assert_eq!((frag & 0x1fff) as usize * 8, whole.len());
            whole.extend_from_slice(&p[20..]);
        }
        assert_eq!(l4_checksum(*from.ip(), *to.ip(), UDP, &whole), 0);
    }

    #[test]
    fn ports_are_not_reused_while_taken() {
        let mut t = Table::default();
        let dst: SocketAddrV4 = "203.0.113.80:80".parse().unwrap();
        let a = Conn { peer: "100.64.0.2:40000".parse().unwrap(), dst };
        let b = Conn { peer: "100.64.0.2:40001".parse().unwrap(), dst };
        let pa = t.add(a, vec![]).unwrap();
        let pb = t.add(b, vec![]).unwrap();
        assert_ne!(pa, pb);
        assert_eq!(t.ports[&(Ipv4Addr::new(100, 64, 0, 2), pb)], b);
        t.remove(&a);
        assert!(!t.ports.contains_key(&(Ipv4Addr::new(100, 64, 0, 2), pa)));
        assert!(t.per_peer[&Ipv4Addr::new(100, 64, 0, 2)] == 1);
        for i in 0..MAX_TCP_PER_PEER - 1 {
            t.add(Conn { peer: SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 2), 1 + i as u16), dst }, vec![]).unwrap();
        }
        assert!(t.add(Conn { peer: "100.64.0.2:9".parse().unwrap(), dst }, vec![]).is_none(), "per-peer cap");
    }
}
