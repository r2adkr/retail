//! MagicDNS: devices answer `<name>.retail.internal` at 100.100.100.100. The
//! engine hands queries to that address to `answer`, which builds the reply
//! packet; nothing listens on a socket. The system sends only that domain
//! here (split DNS, see `configure`), so other names never come this way.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use retail_proto::{MAGIC_DNS_DOMAIN, MAGIC_DNS_IP};

const TTL: u32 = 60;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_ANY: u16 = 255;
const NXDOMAIN: u8 = 3;
const REFUSED: u8 = 5;

/// Names and addresses of this device and its peers
#[derive(Default)]
pub struct Names {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
}

impl Names {
    pub fn new<'a>(entries: impl Iterator<Item = (&'a str, Ipv4Addr)>) -> Self {
        let mut n = Names::default();
        for (name, ip) in entries {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            n.by_ip.insert(ip, name.clone());
            n.by_name.insert(name, ip);
        }
        n
    }
}

/// The reply to a DNS query in an IPv4/UDP packet to `MAGIC_DNS_IP:53`, as
/// an IPv4/UDP packet back; `None` for anything else
pub fn answer(packet: &[u8], names: &Names) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = packet.get(ihl..)?;
    if dst != MAGIC_DNS_IP || udp.len() < 8 || u16::from_be_bytes([udp[2], udp[3]]) != 53 {
        return None;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let reply = dns_reply(&udp[8..], names)?;
    Some(ipv4_udp(MAGIC_DNS_IP, src, 53, sport, &reply))
}

/// The DNS reply to one query message
fn dns_reply(q: &[u8], names: &Names) -> Option<Vec<u8>> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    // The question: labels, then type and class
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || labels.len() > 127 {
            return None;
        }
        labels.push(String::from_utf8_lossy(q.get(i..i + len)?).to_ascii_lowercase());
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let question_end = i + 4;
    q.get(..question_end)?;
    let name = labels.join(".");

    let mut rcode = 0;
    let mut record: Option<(u16, Vec<u8>)> = None;
    if let Some(ip) = reverse_ip(&labels) {
        match names.by_ip.get(&ip) {
            Some(n) if qtype == TYPE_PTR || qtype == TYPE_ANY => record = Some((TYPE_PTR, encode_name(n))),
            Some(_) => {}
            None => rcode = NXDOMAIN,
        }
    } else if name == MAGIC_DNS_DOMAIN || name.ends_with(&format!(".{MAGIC_DNS_DOMAIN}")) {
        match names.by_name.get(&name) {
            Some(ip) if qtype == TYPE_A || qtype == TYPE_ANY => record = Some((TYPE_A, ip.octets().to_vec())),
            // The name exists, with no record of that type (AAAA, say)
            Some(_) => {}
            None if name == MAGIC_DNS_DOMAIN => {}
            None => rcode = NXDOMAIN,
        }
    } else {
        rcode = REFUSED;
    }

    let mut r = Vec::with_capacity(question_end + 32);
    r.extend_from_slice(&q[..2]); // id
    // Response, authoritative, recursion desired copied, no recursion available
    r.push(0x84 | (q[2] & 0x01));
    r.push(rcode);
    r.extend_from_slice(&[0, 1]);
    r.extend_from_slice(&[0, record.is_some() as u8]);
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&q[12..question_end]);
    if let Some((ty, data)) = record {
        r.extend_from_slice(&[0xc0, 12]); // the question's name
        r.extend_from_slice(&ty.to_be_bytes());
        r.extend_from_slice(&[0, 1]);
        r.extend_from_slice(&TTL.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(&data);
    }
    Some(r)
}

/// `4.3.2.1.in-addr.arpa` for a mesh address
fn reverse_ip(labels: &[String]) -> Option<Ipv4Addr> {
    if labels.len() != 6 || labels[4] != "in-addr" || labels[5] != "arpa" {
        return None;
    }
    let o: Vec<u8> = labels[..4].iter().rev().map(|l| l.parse().ok()).collect::<Option<_>>()?;
    let ip = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
    retail_proto::in_mesh(ip).then_some(ip)
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        out.push(l.len().min(63) as u8);
        out.extend_from_slice(&l.as_bytes()[..l.len().min(63)]);
    }
    out.push(0);
    out
}

fn ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // don't fragment
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let sum = checksum(&p[..20], 0);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    // UDP checksum over the pseudo-header
    let mut pseudo = 0u32;
    for b in [src.octets(), dst.octets()] {
        pseudo += u16::from_be_bytes([b[0], b[1]]) as u32 + u16::from_be_bytes([b[2], b[3]]) as u32;
    }
    pseudo += 17 + (8 + payload.len()) as u32;
    let sum = match checksum(&p[20..], pseudo) {
        0 => 0xffff,
        s => s,
    };
    p[26..28].copy_from_slice(&sum.to_be_bytes());
    p
}

fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for c in data.chunks(2) {
        sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Sends the system's lookups for the MagicDNS domain to `MAGIC_DNS_IP`
/// while the tunnel is up; undone on drop. Other names keep the system's
/// resolvers.
pub struct SystemDns {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tun: String,
}

impl SystemDns {
    pub fn configure(tun: &str) -> Option<SystemDns> {
        let ok = setup(tun);
        if !ok {
            tracing::info!("MagicDNS: the system does not send {MAGIC_DNS_DOMAIN} names here; ask {MAGIC_DNS_IP} directly");
        }
        ok.then(|| SystemDns { tun: tun.to_string() })
    }
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        teardown(&self.tun);
    }
}

fn run(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Windows: a name resolution policy rule for the domain
#[cfg(windows)]
fn setup(_tun: &str) -> bool {
    let script = format!(
        "Get-DnsClientNrptRule | Where-Object Comment -eq 'retail' | Remove-DnsClientNrptRule -Force; \
         Add-DnsClientNrptRule -Namespace '.{MAGIC_DNS_DOMAIN}' -NameServers '{MAGIC_DNS_IP}' -Comment 'retail'"
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])
}

#[cfg(windows)]
fn teardown(_tun: &str) {
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-DnsClientNrptRule | Where-Object Comment -eq 'retail' | Remove-DnsClientNrptRule -Force"]);
}

/// macOS: a resolver file for the domain
#[cfg(target_os = "macos")]
fn setup(_tun: &str) -> bool {
    let _ = std::fs::create_dir_all("/etc/resolver");
    std::fs::write(format!("/etc/resolver/{MAGIC_DNS_DOMAIN}"), format!("# retail MagicDNS\nnameserver {MAGIC_DNS_IP}\n")).is_ok()
}

#[cfg(target_os = "macos")]
fn teardown(_tun: &str) {
    let _ = std::fs::remove_file(format!("/etc/resolver/{MAGIC_DNS_DOMAIN}"));
}

/// Linux: systemd-resolved, per link
#[cfg(target_os = "linux")]
fn setup(tun: &str) -> bool {
    run("resolvectl", &["dns", tun, &MAGIC_DNS_IP.to_string()])
        && run("resolvectl", &["domain", tun, &format!("~{MAGIC_DNS_DOMAIN}")])
}

#[cfg(target_os = "linux")]
fn teardown(tun: &str) {
    run("resolvectl", &["revert", tun]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend(encode_name(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        ipv4_udp(Ipv4Addr::new(100, 64, 0, 1), MAGIC_DNS_IP, 5353, 53, &q)
    }

    fn names() -> Names {
        Names::new(
            [("laptop.retail.internal", Ipv4Addr::new(100, 64, 0, 1)), ("nas.retail.internal.", Ipv4Addr::new(100, 64, 0, 2))].into_iter(),
        )
    }

    fn reply(p: &[u8]) -> (u8, u16, &[u8]) {
        assert_eq!(&p[12..16], &MAGIC_DNS_IP.octets());
        assert_eq!(checksum(&p[..20], 0), 0, "IP checksum");
        let dns = &p[28..];
        (dns[3] & 0x0f, u16::from_be_bytes([dns[6], dns[7]]), dns)
    }

    #[test]
    fn answers_names_of_the_network() {
        let r = answer(&query("NAS.retail.internal", TYPE_A), &names()).unwrap();
        let (rcode, answers, dns) = reply(&r);
        assert_eq!((rcode, answers), (0, 1));
        assert_eq!(&dns[dns.len() - 4..], &[100, 64, 0, 2]);
        assert_eq!(&dns[..2], &[0x12, 0x34]);
        // No IPv6 address, but the name exists
        let (rcode, answers, _) = reply(&answer(&query("nas.retail.internal", 28), &names()).unwrap());
        assert_eq!((rcode, answers), (0, 0));
        let (rcode, _, _) = reply(&answer(&query("gone.retail.internal", TYPE_A), &names()).unwrap());
        assert_eq!(rcode, NXDOMAIN);
        let (rcode, _, _) = reply(&answer(&query("example.com", TYPE_A), &names()).unwrap());
        assert_eq!(rcode, REFUSED);
    }

    #[test]
    fn answers_reverse_lookups() {
        let r = answer(&query("2.0.64.100.in-addr.arpa", TYPE_PTR), &names()).unwrap();
        let (rcode, answers, dns) = reply(&r);
        assert_eq!((rcode, answers), (0, 1));
        assert!(dns.ends_with(&encode_name("nas.retail.internal")));
    }

    #[test]
    fn ignores_what_is_not_a_query_to_it() {
        let mut q = query("nas.retail.internal", TYPE_A);
        q[19] = 99;
        assert!(answer(&q, &names()).is_none());
        assert!(answer(&[0x45; 10], &names()).is_none());
        let mut truncated = query("nas.retail.internal", TYPE_A);
        truncated.truncate(40);
        assert!(answer(&truncated, &names()).is_none());
    }
}
