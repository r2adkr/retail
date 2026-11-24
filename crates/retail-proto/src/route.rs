//! IPv4 networks a device routes for the others (subnet routes), written
//! `192.168.1.0/24`.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A device advertises at most this many
pub const MAX_ROUTES: usize = 16;

/// Host bits are always zero
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    len: u8,
}

fn mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) }
}

impl Ipv4Net {
    /// Clears host bits; `None` if `len` is over 32
    pub fn new(addr: Ipv4Addr, len: u8) -> Option<Self> {
        (len <= 32).then(|| Ipv4Net { addr: Ipv4Addr::from(u32::from(addr) & mask(len)), len })
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.len) == u32::from(self.addr)
    }

    pub fn overlaps(&self, other: &Ipv4Net) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    /// Whether a device may route this network for the others: not the whole
    /// internet (that is what exit nodes do), and nothing of retail's own
    /// range or addresses that never leave a machine or link
    pub fn check_route(&self) -> Result<(), String> {
        if self.len == 0 {
            return Err("0.0.0.0/0 is the whole internet: offer an exit node instead".into());
        }
        let reserved: [(&str, [u8; 4], u8); 6] = [
            ("retail's own addresses", [100, 64, 0, 0], 10),
            ("loopback", [127, 0, 0, 0], 8),
            ("\"this network\"", [0, 0, 0, 0], 8),
            ("link-local", [169, 254, 0, 0], 16),
            ("multicast", [224, 0, 0, 0], 4),
            ("reserved", [240, 0, 0, 0], 4),
        ];
        for (what, a, len) in reserved {
            if self.overlaps(&Ipv4Net { addr: Ipv4Addr::from(a), len }) {
                return Err(format!("{self} overlaps {what}"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl FromStr for Ipv4Net {
    type Err = String;

    /// `a.b.c.d/len`, or an address alone for one host. Host bits must be zero.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, l.parse::<u8>().map_err(|_| format!("{s}: the length after / is 0 to 32"))?),
            None => (s, 32),
        };
        let addr: Ipv4Addr = addr.parse().map_err(|_| format!("{s} is not an IPv4 network such as 192.168.1.0/24"))?;
        let net = Ipv4Net::new(addr, len).ok_or_else(|| format!("{s}: the length after / is 0 to 32"))?;
        if net.addr != addr {
            return Err(format!("{s} has host bits set; did you mean {net}?"));
        }
        Ok(net)
    }
}

impl Serialize for Ipv4Net {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ipv4Net {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // Lenient with host bits: the value came from a peer, not a person
        let (a, l) = s.split_once('/').unwrap_or((&s, "32"));
        let addr: Ipv4Addr = a.parse().map_err(serde::de::Error::custom)?;
        let len: u8 = l.parse().map_err(serde::de::Error::custom)?;
        Ipv4Net::new(addr, len).ok_or_else(|| serde::de::Error::custom("prefix length over 32"))
    }
}

/// Parses, checks and sorts routes typed by a person
pub fn parse_routes<S: AsRef<str>>(items: &[S]) -> Result<Vec<Ipv4Net>, String> {
    let mut out: Vec<Ipv4Net> = Vec::new();
    for item in items {
        for part in item.as_ref().split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let net: Ipv4Net = part.parse()?;
            net.check_route()?;
            if !out.contains(&net) {
                out.push(net);
            }
        }
    }
    if out.len() > MAX_ROUTES {
        return Err(format!("at most {MAX_ROUTES} networks"));
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_check() {
        let n: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        assert!(n.contains(Ipv4Addr::new(192, 168, 1, 77)));
        assert!(!n.contains(Ipv4Addr::new(192, 168, 2, 1)));
        assert_eq!(n.to_string(), "192.168.1.0/24");
        assert!("192.168.1.5/24".parse::<Ipv4Net>().unwrap_err().contains("192.168.1.0/24"));
        assert_eq!("10.0.0.7".parse::<Ipv4Net>().unwrap().to_string(), "10.0.0.7/32");
        assert!("10.0.0.0/33".parse::<Ipv4Net>().is_err());
        for bad in ["0.0.0.0/0", "100.64.0.0/16", "100.100.100.100", "127.0.0.0/8", "0.0.0.0/1", "224.0.0.0/8"] {
            assert!(bad.parse::<Ipv4Net>().unwrap().check_route().is_err(), "{bad}");
        }
        assert!(n.check_route().is_ok());
        assert!(n.overlaps(&"192.168.0.0/16".parse().unwrap()));
        assert_eq!(parse_routes(&["10.0.0.0/8, 192.168.1.0/24", "10.0.0.0/8"]).unwrap().len(), 2);
        // Serde is lenient with host bits, which it clears
        let v: Ipv4Net = serde_json::from_str("\"192.168.1.9/24\"").unwrap();
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"192.168.1.0/24\"");
    }
}
