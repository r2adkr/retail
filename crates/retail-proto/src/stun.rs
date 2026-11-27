//! Minimal STUN (RFC 5389) Binding for public address discovery. No
//! authentication, fingerprint or retransmission.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;

pub type TransactionId = [u8; 12];

/// Separates STUN from WireGuard on a shared socket.
///
/// WireGuard messages start with a little-endian type (1..=4) and three zero
/// bytes, so their second byte is 0. The Binding methods used here have 0x01
/// there, and every STUN message carries the magic cookie at bytes 4..8.
pub fn is_stun(p: &[u8]) -> bool {
    p.len() >= HEADER_LEN
        && p[0] & 0xC0 == 0
        && p[1] == 0x01
        && p[4..8] == MAGIC_COOKIE.to_be_bytes()
}

fn header(msg_type: u16, body_len: u16, tx: &TransactionId) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..2].copy_from_slice(&msg_type.to_be_bytes());
    h[2..4].copy_from_slice(&body_len.to_be_bytes());
    h[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    h[8..20].copy_from_slice(tx);
    h
}

fn parse_header(p: &[u8]) -> Option<(u16, &TransactionId, &[u8])> {
    if !is_stun(p) {
        return None;
    }
    let msg_type = u16::from_be_bytes([p[0], p[1]]);
    let len = u16::from_be_bytes([p[2], p[3]]) as usize;
    let body = p.get(HEADER_LEN..HEADER_LEN + len)?;
    let tx: &TransactionId = p[8..20].try_into().ok()?;
    Some((msg_type, tx, body))
}

pub fn binding_request(tx: &TransactionId) -> [u8; HEADER_LEN] {
    header(BINDING_REQUEST, 0, tx)
}

pub fn parse_binding_request(p: &[u8]) -> Option<TransactionId> {
    match parse_header(p)? {
        (BINDING_REQUEST, tx, _) => Some(*tx),
        _ => None,
    }
}

pub fn binding_response(tx: &TransactionId, addr: SocketAddr) -> Vec<u8> {
    let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let mut value = vec![0u8];
    match addr.ip() {
        IpAddr::V4(ip) => {
            value.push(FAMILY_V4);
            value.extend_from_slice(&xport.to_be_bytes());
            value.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            value.push(FAMILY_V6);
            value.extend_from_slice(&xport.to_be_bytes());
            let mask = xor_mask_v6(tx);
            let mut o = ip.octets();
            for (b, m) in o.iter_mut().zip(mask) {
                *b ^= m;
            }
            value.extend_from_slice(&o);
        }
    }
    let mut attr = Vec::with_capacity(4 + value.len());
    attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);

    let mut out = header(BINDING_SUCCESS, attr.len() as u16, tx).to_vec();
    out.extend_from_slice(&attr);
    out
}

/// Prefers XOR-MAPPED-ADDRESS, falling back to MAPPED-ADDRESS
pub fn parse_binding_response(p: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    let (msg_type, tx, mut body) = parse_header(p)?;
    if msg_type != BINDING_SUCCESS {
        return None;
    }
    let mut fallback = None;
    while body.len() >= 4 {
        let typ = u16::from_be_bytes([body[0], body[1]]);
        let len = u16::from_be_bytes([body[2], body[3]]) as usize;
        let value = body.get(4..4 + len)?;
        match typ {
            ATTR_XOR_MAPPED_ADDRESS => return decode_address(value, Some(tx)).map(|a| (*tx, a)),
            ATTR_MAPPED_ADDRESS => fallback = decode_address(value, None),
            _ => {}
        }
        // Attributes are padded to a multiple of 4 bytes
        let advance = 4 + len.div_ceil(4) * 4;
        body = body.get(advance..).unwrap_or(&[]);
    }
    fallback.map(|a| (*tx, a))
}

fn xor_mask_v6(tx: &TransactionId) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m[4..16].copy_from_slice(tx);
    m
}

fn decode_address(v: &[u8], xor_tx: Option<&TransactionId>) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    if xor_tx.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match v[1] {
        FAMILY_V4 => {
            let raw: [u8; 4] = v.get(4..8)?.try_into().ok()?;
            let mut ip = u32::from_be_bytes(raw);
            if xor_tx.is_some() {
                ip ^= MAGIC_COOKIE;
            }
            Some(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        FAMILY_V6 => {
            let mut o: [u8; 16] = v.get(4..20)?.try_into().ok()?;
            if let Some(tx) = xor_tx {
                for (b, m) in o.iter_mut().zip(xor_mask_v6(tx)) {
                    *b ^= m;
                }
            }
            Some(SocketAddr::new(Ipv6Addr::from(o).into(), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TX: TransactionId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    #[test]
    fn request_round_trip() {
        let req = binding_request(&TX);
        assert!(is_stun(&req));
        assert_eq!(parse_binding_request(&req), Some(TX));
        assert_eq!(parse_binding_response(&req), None);
    }

    #[test]
    fn response_round_trip_v4_and_v6() {
        for addr in ["203.0.113.7:41641", "[2001:db8::1]:3478"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let resp = binding_response(&TX, addr);
            assert!(is_stun(&resp));
            assert_eq!(parse_binding_request(&resp), None);
            assert_eq!(parse_binding_response(&resp), Some((TX, addr)));
        }
    }

    #[test]
    fn wireguard_packets_are_not_stun() {
        // Handshake initiation with a magic cookie where its sender index sits
        let mut wg = vec![1u8, 0, 0, 0];
        wg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        wg.resize(148, 0);
        assert!(!is_stun(&wg));
    }
}
