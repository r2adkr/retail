//! `Tunn` needs `&mut self`, which would put all of a peer's crypto behind one
//! lock, but its sessions encrypt and decrypt with `&self`. Crypto workers
//! therefore use a session directly and lock the `Tunn` only to look it up and
//! to record the batch (see `vendor/boringtun/RETAIL-CHANGES.md`).
//!
//! The single tun-read stage reserves send counters per batch, so counter
//! order equals wire order whichever worker encrypts a packet.

use std::net::Ipv4Addr;

use boringtun::noise::Session;

/// 16-byte transport-data header plus 16-byte tag
pub const OVERHEAD: usize = 32;

/// Appends `packets` to `out` back to back, encrypted with counters
/// `first..first + packets.len()`. Packet `i` grows by `OVERHEAD` bytes.
pub fn encrypt_batch(session: &Session, first: u64, packets: &[&[u8]], out: &mut Vec<u8>) {
    let mut at = out.len();
    out.resize(at + packets.iter().map(|p| p.len() + OVERHEAD).sum::<usize>(), 0);
    for (i, p) in packets.iter().enumerate() {
        let len = p.len() + OVERHEAD;
        session.encrypt_with_counter(first + i as u64, p, &mut out[at..at + len]);
        at += len;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decrypted {
    /// An IP packet of this length now sits at `offset` in its buffer
    Packet(usize),
    /// Authentic but nothing to deliver: a keepalive, or a packet dropped
    /// after decryption (bad IP header, IPv6, spoofed source).
    Authenticated,
    /// Failed authentication or replay check
    Rejected,
}

/// Inner source addresses a peer may use: its mesh address, any address in
/// the networks it routes, plus any internet address no other peer routes if
/// it is our exit node.
#[derive(Clone, Copy)]
pub struct AllowedSrc<'a> {
    pub ip: Ipv4Addr,
    pub internet: bool,
    pub routes: &'a [retail_proto::route::Ipv4Net],
    pub foreign: &'a [retail_proto::route::Ipv4Net],
}

impl AllowedSrc<'_> {
    pub fn permits(self, src: Ipv4Addr) -> bool {
        src == self.ip
            || (self.internet && crate::filter::is_internet(src) && !self.foreign.iter().any(|r| r.contains(src)))
            || self.routes.iter().any(|r| r.contains(src))
    }
}

/// Decrypts `datagrams` into `bufs[i][offset..]`, trimming each packet to its
/// IP length and enforcing `allowed` (WireGuard's allowed-IPs rule).
pub fn decrypt_batch(
    session: &Session,
    datagrams: &[&[u8]],
    bufs: &mut [Vec<u8>],
    offset: usize,
    allowed: AllowedSrc<'_>,
    results: &mut Vec<Decrypted>,
) {
    results.clear();
    for (buf, dgram) in bufs.iter_mut().zip(datagrams) {
        results.push(decrypt_one(session, dgram, buf, offset, allowed));
    }
}

fn decrypt_one(session: &Session, dgram: &[u8], buf: &mut Vec<u8>, offset: usize, allowed: AllowedSrc<'_>) -> Decrypted {
    let need = offset + dgram.len();
    if buf.len() < need {
        buf.resize(need, 0);
    }
    let plain_len = match session.decrypt_data(dgram, &mut buf[offset..]) {
        Ok(p) => p.len(),
        Err(_) => return Decrypted::Rejected,
    };
    let p = &buf[offset..offset + plain_len];
    if p.is_empty() {
        return Decrypted::Authenticated; // Keepalive
    }
    // Mirrors boringtun's validate_decapsulated_packet, IPv4 only, plus allowed-IPs
    if p.len() < 20 || p[0] >> 4 != 4 {
        return Decrypted::Authenticated;
    }
    let ip_len = u16::from_be_bytes([p[2], p[3]]) as usize;
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    if ip_len > p.len() || ip_len < 20 || !allowed.permits(src) {
        if !allowed.permits(src) {
            tracing::debug!(%src, "dropping packet with spoofed source");
        }
        return Decrypted::Authenticated;
    }
    buf.truncate(offset + ip_len);
    Decrypted::Packet(ip_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519::{PublicKey, StaticSecret};

    fn key(b: u8) -> StaticSecret {
        StaticSecret::from([b; 32])
    }

    /// Two tunnels with a completed handshake initiated by the first
    fn pair() -> (Tunn, Tunn) {
        let (ka, kb) = (key(1), key(2));
        let (pa, pb) = (PublicKey::from(&ka), PublicKey::from(&kb));
        let mut a = Tunn::new(ka, pb, None, None, 1, None);
        let mut b = Tunn::new(kb, pa, None, None, 2, None);
        let mut buf_a = vec![0u8; 2048];
        let mut buf_b = vec![0u8; 2048];
        let init = match a.format_handshake_initiation(&mut buf_a, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            r => panic!("no initiation: {r:?}"),
        };
        let resp = match b.decapsulate(None, &init, &mut buf_b) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            r => panic!("no response: {r:?}"),
        };
        let keepalive = match a.decapsulate(None, &resp, &mut buf_a) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            r => panic!("no keepalive: {r:?}"),
        };
        // The responder switches to the new session on the first packet
        assert!(matches!(b.decapsulate(None, &keepalive, &mut buf_b), TunnResult::Done));
        (a, b)
    }

    fn ip_packet(src: Ipv4Addr, n: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&[100, 64, 0, 2]);
        p[20..22].copy_from_slice(&n.to_be_bytes());
        p
    }

    fn receiver_index(dgram: &[u8]) -> u32 {
        u32::from_le_bytes(dgram[4..8].try_into().unwrap())
    }

    #[test]
    fn concurrent_round_trip_and_replay() {
        let (mut a, mut b) = pair();
        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let packets: Vec<Vec<u8>> = (0..1000u16).map(|n| ip_packet(a_ip, n, 60 + (n as usize % 1200))).collect();
        let refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();

        let tx = a.current_send_session().expect("initiator has a session");
        let bytes: usize = refs.iter().map(|p| p.len()).sum();
        let first = tx.reserve_counters(refs.len() as u64);
        a.note_sent(bytes, true);
        // Encrypt halves on two threads as two workers would
        let (lo, hi) = refs.split_at(500);
        let (mut w1, mut w2) = (Vec::new(), Vec::new());
        std::thread::scope(|s| {
            s.spawn(|| encrypt_batch(&tx, first, lo, &mut w1));
            s.spawn(|| encrypt_batch(&tx, first + 500, hi, &mut w2));
        });
        let mut wire = w1;
        wire.extend_from_slice(&w2);

        let mut dgrams: Vec<&[u8]> = Vec::new();
        let mut at = 0;
        for p in &refs {
            dgrams.push(&wire[at..at + p.len() + OVERHEAD]);
            at += p.len() + OVERHEAD;
        }
        let counters: Vec<u64> = dgrams.iter().map(|d| u64::from_le_bytes(d[8..16].try_into().unwrap())).collect();
        assert!(counters.windows(2).all(|w| w[1] == w[0] + 1));

        let idx = receiver_index(dgrams[0]);
        let rx = b.session_for(idx).expect("responder has the session");
        let mut bufs: Vec<Vec<u8>> = (0..dgrams.len()).map(|_| vec![0u8; 2048]).collect();
        let mut results = Vec::new();
        decrypt_batch(&rx, &dgrams, &mut bufs, 10, only(a_ip), &mut results);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(*r, Decrypted::Packet(refs[i].len()), "packet {i}");
            assert_eq!(&bufs[i][10..], refs[i], "packet {i} content");
        }
        b.note_received(idx, bytes, true);
        assert_eq!(b.stats().2, bytes, "rx bytes recorded");

        decrypt_batch(&rx, &dgrams[..32], &mut bufs, 10, only(a_ip), &mut results);
        assert!(results.iter().all(|r| *r == Decrypted::Rejected));

        // A spoofed inner source still authenticates, a tampered datagram does not
        let mut spoofed = ip_packet(Ipv4Addr::new(100, 64, 0, 9), 1, 80);
        spoofed[21] = 7;
        let mut wire2 = Vec::new();
        encrypt_batch(&tx, tx.reserve_counters(2), &[&spoofed, &packets[0]], &mut wire2);
        let mut tampered = wire2[80 + OVERHEAD..].to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        decrypt_batch(&rx, &[&wire2[..80 + OVERHEAD], &tampered], &mut bufs, 10, only(a_ip), &mut results);
        assert_eq!(results, vec![Decrypted::Authenticated, Decrypted::Rejected]);
    }

    #[test]
    fn keepalive_is_authenticated_without_a_packet() {
        let (a, b) = pair();
        let tx = a.current_send_session().unwrap();
        let mut wire = Vec::new();
        encrypt_batch(&tx, tx.reserve_counters(1), &[&[]], &mut wire);
        let rx = b.session_for(receiver_index(&wire)).unwrap();
        let mut bufs = vec![vec![0u8; 64]];
        let mut results = Vec::new();
        decrypt_batch(&rx, &[&wire], &mut bufs, 0, only(Ipv4Addr::new(100, 64, 0, 1)), &mut results);
        assert_eq!(results, vec![Decrypted::Authenticated]);
    }

    fn only(ip: Ipv4Addr) -> AllowedSrc<'static> {
        AllowedSrc { ip, internet: false, routes: &[], foreign: &[] }
    }

    #[test]
    fn exit_node_may_send_from_internet_but_not_other_mesh_addresses() {
        let me = Ipv4Addr::new(100, 64, 0, 2);
        let foreign = ["203.0.113.0/24".parse().unwrap()];
        let exit = AllowedSrc { ip: me, internet: true, routes: &[], foreign: &foreign };
        assert!(exit.permits(me));
        let routes = ["192.168.7.0/24".parse().unwrap()];
        let router = AllowedSrc { ip: me, internet: false, routes: &routes, foreign: &[] };
        assert!(router.permits(Ipv4Addr::new(192, 168, 7, 9)));
        assert!(!router.permits(Ipv4Addr::new(192, 168, 8, 9)));
        assert!(exit.permits(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(!exit.permits(Ipv4Addr::new(100, 64, 0, 9)), "mesh addresses stay bound to their node");
        assert!(!exit.permits(Ipv4Addr::new(203, 0, 113, 5)), "another peer routes it");
        assert!(!exit.permits(Ipv4Addr::new(192, 168, 1, 1)), "not from the internet");
        assert!(!only(me).permits(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn unknown_receiver_index_has_no_session() {
        let (_, b) = pair();
        assert!(b.session_for(0xdead_beef).is_none());
    }
}
