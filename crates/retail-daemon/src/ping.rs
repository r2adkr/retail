//! Round-trip times to peers, for the tray's connection graph. While traffic
//! flows between two devices, each sends the other a small UDP packet inside
//! the tunnel every 2 seconds; the other's daemon answers it itself, so no
//! firewall or ICMP setting is involved. Idle peers get none.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Source and destination port of both packets
pub const PORT: u16 = 41617;
const MAGIC: [u8; 4] = *b"rtlP";
const LEN: usize = 20 + 8 + 12;
pub const INTERVAL: Duration = Duration::from_secs(2);
/// Kept: 5 minutes of samples
pub const HISTORY: usize = 150;
/// A sample in the history for a ping with no answer
pub const LOST: u16 = u16::MAX;
/// Bytes moved between two timer ticks that count as traffic (more than pings)
const ACTIVE_BYTES: u64 = 400;
const ACTIVE_FOR: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Reply,
}

pub fn build(kind: Kind, src: Ipv4Addr, dst: Ipv4Addr, nonce: u32) -> [u8; LEN] {
    let mut p = [0u8; LEN];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(LEN as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p[20..22].copy_from_slice(&PORT.to_be_bytes());
    p[22..24].copy_from_slice(&PORT.to_be_bytes());
    p[24..26].copy_from_slice(&((LEN - 20) as u16).to_be_bytes());
    // UDP checksum 0: none (IPv4)
    p[28..32].copy_from_slice(&MAGIC);
    p[32] = matches!(kind, Kind::Reply) as u8;
    p[36..40].copy_from_slice(&nonce.to_be_bytes());
    p
}

pub fn parse(p: &[u8]) -> Option<(Kind, u32)> {
    if p.len() != LEN || p[0] != 0x45 || p[9] != 17 || p[20..22] != PORT.to_be_bytes() || p[22..24] != PORT.to_be_bytes() || p[28..32] != MAGIC {
        return None;
    }
    let kind = match p[32] {
        0 => Kind::Request,
        1 => Kind::Reply,
        _ => return None,
    };
    Some((kind, u32::from_be_bytes(p[36..40].try_into().unwrap())))
}

fn checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = h.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One peer's pings
#[derive(Default)]
pub struct Log {
    nonce: u32,
    /// The ping waiting for its answer
    sent: Option<(u32, Instant)>,
    last_sent: Option<Instant>,
    bytes_seen: u64,
    active_until: Option<Instant>,
    history: VecDeque<u16>,
    last: Option<(u16, Instant)>,
}

impl Log {
    /// Called each timer tick with the tunnel's byte count: the nonce of a
    /// ping to send now, if one is due
    pub fn due(&mut self, bytes: u64, now: Instant) -> Option<u32> {
        if bytes.saturating_sub(self.bytes_seen) > ACTIVE_BYTES {
            self.active_until = Some(now + ACTIVE_FOR);
        }
        self.bytes_seen = bytes;
        if self.active_until.is_none_or(|t| now >= t) || self.last_sent.is_some_and(|at| now.duration_since(at) < INTERVAL) {
            return None;
        }
        if self.sent.is_some() {
            self.push(LOST);
        }
        self.nonce = self.nonce.wrapping_add(1);
        self.sent = Some((self.nonce, now));
        self.last_sent = Some(now);
        Some(self.nonce)
    }

    pub fn answered(&mut self, nonce: u32, now: Instant) {
        let Some((sent, at)) = self.sent else { return };
        if sent != nonce {
            return;
        }
        self.sent = None;
        let ms = now.duration_since(at).as_millis().min(u128::from(LOST - 1)) as u16;
        self.last = Some((ms, now));
        self.push(ms);
    }

    fn push(&mut self, sample: u16) {
        if self.history.len() == HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(sample);
    }

    /// The latest round trip if recent, and the samples, oldest first
    pub fn snapshot(&self) -> (Option<u32>, Vec<u16>) {
        let now = self.last.filter(|(_, at)| at.elapsed() < Duration::from_secs(30)).map(|(ms, _)| u32::from(ms));
        (now, self.history.iter().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip() {
        let (a, b) = (Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
        let p = build(Kind::Request, a, b, 7);
        assert_eq!(parse(&p), Some((Kind::Request, 7)));
        assert_eq!(checksum(&p[..20]), 0);
        assert_eq!(parse(&build(Kind::Reply, b, a, 9)), Some((Kind::Reply, 9)));
        let mut other = p;
        other[29] = b'x';
        assert_eq!(parse(&other), None);
    }

    #[test]
    fn pings_only_while_traffic_flows() {
        let mut log = Log::default();
        let t = Instant::now();
        assert_eq!(log.due(100, t), None);
        let n = log.due(100_000, t + Duration::from_millis(250)).unwrap();
        log.answered(n, t + Duration::from_millis(280));
        assert_eq!(log.snapshot(), (Some(30), vec![30]));
        assert_eq!(log.due(100_100, t + Duration::from_secs(1)), None);
        // Unanswered: counted lost when the next one goes
        assert!(log.due(100_200, t + Duration::from_millis(2300)).is_some());
        assert!(log.due(100_300, t + Duration::from_millis(4400)).is_some());
        assert_eq!(log.snapshot().1, vec![30, LOST]);
        // Quiet for long enough: no more pings
        assert_eq!(log.due(100_300, t + Duration::from_secs(20)), None);
    }
}
