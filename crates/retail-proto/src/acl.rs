//! Access between devices. Without a policy every device reaches every other.
//! With one, a device reaches another only where a rule allows it; replies to
//! traffic a device started itself always come back.
//!
//! A rule names sources and destinations with selectors: `*` (every device),
//! `tag:NAME` (devices with that tag) or `id:N` (one device), and optionally
//! ports: `22`, `tcp:443`, `udp:5000-5100`, `icmp` or `*`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AclPolicy {
    pub rules: Vec<AclRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AclRule {
    pub from: Vec<String>,
    pub to: Vec<String>,
    /// Empty: every port and protocol
    #[serde(default)]
    pub ports: Vec<String>,
}

/// What a device accepts from one peer, sent with that peer in the netmap
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Accept {
    /// Anything
    #[default]
    All,
    /// New traffic only to these ports; replies always. Empty: replies only.
    Ports { ports: Vec<PortRule> },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Proto {
    /// The IP protocol number
    pub fn number(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Icmp => 1,
        }
    }
}

/// `proto` `None` is TCP and UDP (and ICMP when the range is every port)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRule {
    #[serde(default)]
    pub proto: Option<Proto>,
    pub first: u16,
    pub last: u16,
}

impl PortRule {
    pub const ANY: PortRule = PortRule {
        proto: None,
        first: 0,
        last: u16::MAX,
    };

    /// Whether a packet of IP protocol `proto` to `port` (0 for ICMP) matches
    pub fn matches(&self, proto: u8, port: u16) -> bool {
        match (self.proto, proto) {
            (Some(Proto::Icmp), 1) => true,
            (Some(p), n) if p.number() != n => false,
            (None, 1) => self.first == 0 && self.last == u16::MAX,
            (None, n) if n != 6 && n != 17 => false,
            _ => (self.first..=self.last).contains(&port),
        }
    }

    /// `22`, `tcp:443`, `udp:5000-5100`, `icmp`, `*`
    pub fn parse(s: &str) -> Result<PortRule, String> {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" || s == "any" {
            return Ok(PortRule::ANY);
        }
        if s == "icmp" {
            return Ok(PortRule {
                proto: Some(Proto::Icmp),
                first: 0,
                last: 0,
            });
        }
        let (proto, range) = match s.split_once(':') {
            Some(("tcp", r)) => (Some(Proto::Tcp), r),
            Some(("udp", r)) => (Some(Proto::Udp), r),
            Some((p, _)) => return Err(format!("unknown protocol {p:?} (tcp, udp or icmp)")),
            None => (None, s.as_str()),
        };
        let port = |p: &str| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("not a port: {p:?}"))
        };
        let (first, last) = match range {
            "*" => (0, u16::MAX),
            r => match r.split_once('-') {
                Some((a, b)) => (port(a)?, port(b)?),
                None => (port(r)?, port(r)?),
            },
        };
        if first > last {
            return Err(format!("empty port range {first}-{last}"));
        }
        Ok(PortRule { proto, first, last })
    }
}

impl std::fmt::Display for PortRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == PortRule::ANY {
            return write!(f, "*");
        }
        match self.proto {
            Some(Proto::Icmp) => return write!(f, "icmp"),
            Some(Proto::Tcp) => write!(f, "tcp:")?,
            Some(Proto::Udp) => write!(f, "udp:")?,
            None => {}
        }
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

/// Checks a selector: `*`, `tag:NAME`, `id:N`
pub fn check_selector(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s == "*" {
        return Ok(());
    }
    if let Some(tag) = s.strip_prefix("tag:") {
        return check_tag(tag);
    }
    if let Some(id) = s.strip_prefix("id:")
        && id.parse::<i64>().is_ok()
    {
        return Ok(());
    }
    Err(format!("not a selector: {s:?} (*, tag:NAME or id:N)"))
}

/// Tags are short DNS-like labels
pub fn check_tag(tag: &str) -> Result<(), String> {
    let ok = !tag.is_empty()
        && tag.len() <= 32
        && tag
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "not a tag: {tag:?} (lowercase letters, digits and -, up to 32)"
        ))
    }
}

impl AclPolicy {
    /// Every selector and port well-formed
    pub fn check(&self) -> Result<(), String> {
        if self.rules.len() > 500 {
            return Err("too many rules".into());
        }
        for r in &self.rules {
            if r.from.is_empty() || r.to.is_empty() {
                return Err("a rule needs at least one source and one destination".into());
            }
            for s in r.from.iter().chain(&r.to) {
                check_selector(s)?;
            }
            for p in &r.ports {
                PortRule::parse(p)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_rules_parse_and_match() {
        let r = PortRule::parse("tcp:443").unwrap();
        assert!(r.matches(6, 443) && !r.matches(17, 443) && !r.matches(6, 80));
        let r = PortRule::parse("5000-5100").unwrap();
        assert!(r.matches(17, 5050) && r.matches(6, 5000) && !r.matches(1, 0));
        assert!(PortRule::parse("icmp").unwrap().matches(1, 0));
        assert!(PortRule::ANY.matches(1, 0) && PortRule::ANY.matches(6, 1));
        assert!(
            PortRule::parse("sctp:1").is_err()
                && PortRule::parse("9-1").is_err()
                && PortRule::parse("x").is_err()
        );
        for s in ["*", "icmp", "tcp:22", "udp:5000-5100", "8080"] {
            assert_eq!(PortRule::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn selectors_and_policies_are_checked() {
        assert!(
            check_selector("*").is_ok()
                && check_selector("tag:web-1").is_ok()
                && check_selector("id:7").is_ok()
        );
        assert!(
            check_selector("tag:Web").is_err()
                && check_selector("laptop").is_err()
                && check_selector("id:x").is_err()
        );
        let bad = AclPolicy {
            rules: vec![AclRule {
                from: vec!["*".into()],
                to: vec![],
                ports: vec![],
            }],
        };
        assert!(bad.check().is_err());
    }
}
