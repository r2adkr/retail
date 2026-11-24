//! TCP receive coalescing for writes to a Linux TUN device with
//! `IFF_VNET_HDR`: a run of segments becomes one `GSO_TCPV4` + `NEEDS_CSUM`
//! write, saving a syscall and a kernel receive-path trip per segment.
//!
//! Merge rules follow Linux's `tcp_gro_receive`. Segments with a bad checksum
//! are never merged, so the kernel still sees and drops them individually.
//! Only IPv4 without IP options is coalesced.

/// Size of `struct virtio_net_hdr`
pub const VNET_HDR_LEN: usize = 10;
const MAX_IP_PACKET: usize = 65535;

const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const IPPROTO_TCP: u8 = 6;

struct Segment {
    tcph_len: usize,
    seq: u32,
    payload: usize,
    psh: bool,
}

fn candidate(pkt: &[u8]) -> Option<Segment> {
    if pkt.len() < 40 || pkt[0] != 0x45 || pkt[9] != IPPROTO_TCP {
        return None; // Not IPv4 without options, or not TCP
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total != pkt.len() {
        return None;
    }
    // More-fragments flag or a fragment offset
    if pkt[6] & 0x20 != 0 || u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
        return None;
    }
    let tcph_len = ((pkt[32] >> 4) as usize) * 4;
    if tcph_len < 20 || 20 + tcph_len > pkt.len() {
        return None;
    }
    let flags = pkt[33];
    if flags != TCP_FLAG_ACK && flags != TCP_FLAG_ACK | TCP_FLAG_PSH {
        return None;
    }
    let payload = pkt.len() - 20 - tcph_len;
    if payload == 0 || !tcp_checksum_valid(pkt) {
        return None;
    }
    Some(Segment {
        tcph_len,
        seq: u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]),
        payload,
        psh: flags & TCP_FLAG_PSH != 0,
    })
}

/// Unfolded sum of big-endian 16-bit words
fn sum16(data: &[u8], mut acc: u64) -> u64 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u64) << 8;
    }
    acc
}

fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

fn pseudo_header_sum(pkt: &[u8], tcp_len: usize) -> u64 {
    sum16(&pkt[12..20], IPPROTO_TCP as u64 + tcp_len as u64)
}

fn tcp_checksum_valid(pkt: &[u8]) -> bool {
    let tcp = &pkt[20..];
    fold(sum16(tcp, pseudo_header_sum(pkt, tcp.len()))) == 0xffff
}

pub struct Coalescer {
    /// virtio-net header followed by the IP packet being built
    buf: Vec<u8>,
    active: bool,
    tcph_len: usize,
    gso_size: usize,
    next_seq: u32,
    count: usize,
    closed: bool,
}

impl Default for Coalescer {
    fn default() -> Self {
        Self::new()
    }
}

impl Coalescer {
    pub fn new() -> Self {
        Coalescer {
            buf: Vec::with_capacity(VNET_HDR_LEN + MAX_IP_PACKET),
            active: false,
            tcph_len: 0,
            gso_size: 0,
            next_seq: 0,
            count: 0,
            closed: false,
        }
    }

    /// Returns false, leaving `pkt` unused, if it does not continue the packet being built
    pub fn try_append(&mut self, pkt: &[u8]) -> bool {
        if !self.active || self.closed {
            return false;
        }
        let Some(seg) = candidate(pkt) else {
            return false;
        };
        let head = &self.buf[VNET_HDR_LEN..];
        let hdr_len = 20 + self.tcph_len;
        let same_flow_and_headers = seg.tcph_len == self.tcph_len
            && seg.seq == self.next_seq
            && seg.payload <= self.gso_size
            && pkt[1] == head[1] // TOS
            && pkt[6] & 0x40 == head[6] & 0x40 // DF
            && pkt[8] == head[8] // TTL
            && pkt[12..24] == head[12..24] // Addresses and ports
            && pkt[28..32] == head[28..32] // ACK number
            && pkt[34..36] == head[34..36] // Window
            && pkt[40..hdr_len] == head[40..hdr_len]; // TCP options
        if !same_flow_and_headers || head.len() + seg.payload > MAX_IP_PACKET {
            return false;
        }
        self.buf.extend_from_slice(&pkt[hdr_len..]);
        self.next_seq = self.next_seq.wrapping_add(seg.payload as u32);
        self.count += 1;
        if seg.psh {
            // PSH ends a run and is carried on the merged packet
            self.buf[VNET_HDR_LEN + 33] |= TCP_FLAG_PSH;
            self.closed = true;
        }
        if seg.payload < self.gso_size {
            self.closed = true; // Only the last segment may be short
        }
        true
    }

    /// Starts a new packet with `pkt`. Returns false if `pkt` cannot be
    /// coalesced, in which case the caller writes it unchanged.
    pub fn start(&mut self, pkt: &[u8]) -> bool {
        debug_assert!(!self.active, "finish() the previous packet first");
        let Some(seg) = candidate(pkt) else {
            return false;
        };
        self.buf.clear();
        self.buf.extend_from_slice(&[0u8; VNET_HDR_LEN]);
        self.buf.extend_from_slice(pkt);
        self.active = true;
        self.tcph_len = seg.tcph_len;
        self.gso_size = seg.payload;
        self.next_seq = seg.seq.wrapping_add(seg.payload as u32);
        self.count = 1;
        self.closed = seg.psh;
        true
    }

    /// Completes the current packet and returns it, virtio header included
    pub fn finish(&mut self) -> Option<&[u8]> {
        if !self.active {
            return None;
        }
        self.active = false;
        if self.count == 1 {
            // Untouched original behind an all-zero header, which requests no offload
            return Some(&self.buf);
        }
        let hdr_len = 20 + self.tcph_len;
        let ip_len = self.buf.len() - VNET_HDR_LEN;
        let pkt = &mut self.buf[VNET_HDR_LEN..];
        pkt[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        pkt[10..12].copy_from_slice(&[0, 0]);
        let ip_csum = !fold(sum16(&pkt[..20], 0));
        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        // NEEDS_CSUM expects the folded pseudo-header sum, which the kernel completes
        let partial = fold(pseudo_header_sum(pkt, ip_len - 20));
        pkt[36..38].copy_from_slice(&partial.to_be_bytes());

        let mut hdr = [0u8; VNET_HDR_LEN];
        hdr[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        hdr[1] = VIRTIO_NET_HDR_GSO_TCPV4;
        hdr[2..4].copy_from_slice(&(hdr_len as u16).to_ne_bytes());
        hdr[4..6].copy_from_slice(&(self.gso_size as u16).to_ne_bytes());
        hdr[6..8].copy_from_slice(&20u16.to_ne_bytes()); // csum_start
        hdr[8..10].copy_from_slice(&16u16.to_ne_bytes()); // csum_offset within TCP
        self.buf[..VNET_HDR_LEN].copy_from_slice(&hdr);
        Some(&self.buf)
    }

    #[cfg(test)]
    fn merged(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4/TCP packet with valid checksums and the 12-byte timestamp option Linux sends
    fn tcp(seq: u32, payload: &[u8], flags: u8) -> Vec<u8> {
        let tcph = 32;
        let total = 20 + tcph + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&[100, 64, 0, 1]);
        p[16..20].copy_from_slice(&[100, 64, 0, 2]);
        let ip = !fold(sum16(&p[..20], 0));
        p[10..12].copy_from_slice(&ip.to_be_bytes());
        p[20..22].copy_from_slice(&5201u16.to_be_bytes());
        p[22..24].copy_from_slice(&40000u16.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&777u32.to_be_bytes());
        p[32] = ((tcph / 4) as u8) << 4;
        p[33] = flags;
        p[34..36].copy_from_slice(&512u16.to_be_bytes());
        p[40..52].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        p[20 + tcph..].copy_from_slice(payload);
        let c = !fold(sum16(&p[20..], pseudo_header_sum(&p, total - 20)));
        p[36..38].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn merges_a_run_and_builds_a_valid_gso_header() {
        let mut c = Coalescer::new();
        let a = tcp(1000, &[1; 100], TCP_FLAG_ACK);
        let b = tcp(1100, &[2; 100], TCP_FLAG_ACK);
        let d = tcp(1200, &[3; 40], TCP_FLAG_ACK | TCP_FLAG_PSH);
        assert!(c.start(&a));
        assert!(c.try_append(&b));
        assert!(c.try_append(&d));
        assert!(!c.try_append(&tcp(1240, &[4; 40], TCP_FLAG_ACK)), "closed after short/PSH segment");
        assert_eq!(c.merged(), 3);

        let out = c.finish().unwrap().to_vec();
        let (hdr, pkt) = out.split_at(VNET_HDR_LEN);
        assert_eq!(hdr[0], VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr[1], VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(u16::from_ne_bytes([hdr[2], hdr[3]]), 52, "hdr_len");
        assert_eq!(u16::from_ne_bytes([hdr[4], hdr[5]]), 100, "gso_size");
        assert_eq!(pkt.len(), 52 + 240);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
        assert_eq!(fold(sum16(&pkt[..20], 0)), 0xffff, "IP header checksum");
        assert_eq!(pkt[33], TCP_FLAG_ACK | TCP_FLAG_PSH);
        let partial = u16::from_be_bytes([pkt[36], pkt[37]]);
        assert_eq!(partial, fold(pseudo_header_sum(pkt, pkt.len() - 20)));
        assert_eq!(&pkt[52..152], &[1; 100][..]);
        assert_eq!(&pkt[152..252], &[2; 100][..]);
        assert_eq!(&pkt[252..], &[3; 40][..]);
    }

    #[test]
    fn single_segment_is_written_unchanged() {
        let mut c = Coalescer::new();
        let a = tcp(5, &[9; 64], TCP_FLAG_ACK);
        assert!(c.start(&a));
        let out = c.finish().unwrap();
        assert_eq!(&out[..VNET_HDR_LEN], &[0; VNET_HDR_LEN]);
        assert_eq!(&out[VNET_HDR_LEN..], &a[..]);
        assert!(c.finish().is_none());
    }

    #[test]
    fn rejects_what_linux_gro_would_not_merge() {
        let mut c = Coalescer::new();
        assert!(c.start(&tcp(1000, &[1; 100], TCP_FLAG_ACK)));
        assert!(!c.try_append(&tcp(1200, &[1; 100], TCP_FLAG_ACK)), "sequence gap");
        assert!(!c.try_append(&tcp(1100, &[1; 120], TCP_FLAG_ACK)), "longer than gso_size");
        let mut other_ack = tcp(1100, &[1; 100], TCP_FLAG_ACK);
        other_ack[31] ^= 1;
        assert!(!c.try_append(&other_ack), "different ACK (and now a bad checksum)");
        let mut corrupt = tcp(1100, &[1; 100], TCP_FLAG_ACK);
        corrupt[60] ^= 0xff;
        assert!(!c.try_append(&corrupt), "bad TCP checksum");
        assert!(c.try_append(&tcp(1100, &[1; 100], TCP_FLAG_ACK)));
        c.finish();

        assert!(!c.start(&tcp(1, &[], TCP_FLAG_ACK)), "pure ACK");
        assert!(!c.start(&tcp(1, &[1; 10], 0x02)), "SYN");
        let mut udp = tcp(1, &[1; 10], TCP_FLAG_ACK);
        udp[9] = 17;
        assert!(!c.start(&udp), "not TCP");
    }

    #[test]
    fn respects_the_64k_limit() {
        let mut c = Coalescer::new();
        let seg = 1228;
        let mut seq = 0u32;
        assert!(c.start(&tcp(seq, &vec![0; seg], TCP_FLAG_ACK)));
        seq += seg as u32;
        while c.try_append(&tcp(seq, &vec![0; seg], TCP_FLAG_ACK)) {
            seq += seg as u32;
        }
        let out = c.finish().unwrap();
        assert!(out.len() - VNET_HDR_LEN <= MAX_IP_PACKET);
        assert_eq!(c.merged(), (MAX_IP_PACKET - 52) / seg);
    }
}
