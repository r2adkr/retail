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
            Some(n) if qtype == TYPE_PTR || qtype == TYPE_ANY => {
                record = Some((TYPE_PTR, encode_name(n)))
            }
            Some(_) => {}
            None => rcode = NXDOMAIN,
        }
    } else if name == MAGIC_DNS_DOMAIN || name.ends_with(&format!(".{MAGIC_DNS_DOMAIN}")) {
        match names.by_name.get(&name) {
            Some(ip) if qtype == TYPE_A || qtype == TYPE_ANY => {
                record = Some((TYPE_A, ip.octets().to_vec()))
            }
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
    let o: Vec<u8> = labels[..4]
        .iter()
        .rev()
        .map(|l| l.parse().ok())
        .collect::<Option<_>>()?;
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
            tracing::info!(
                "MagicDNS: the system does not send {MAGIC_DNS_DOMAIN} names here; ask {MAGIC_DNS_IP} directly"
            );
        }
        ok.then(|| SystemDns {
            tun: tun.to_string(),
        })
    }
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        teardown(&self.tun);
    }
}

/// Only Linux uses programs here
#[cfg(target_os = "linux")]
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
    nrpt::remove();
    nrpt::add(&format!(".{MAGIC_DNS_DOMAIN}"), &MAGIC_DNS_IP.to_string())
}

#[cfg(windows)]
fn teardown(_tun: &str) {
    nrpt::remove();
}

/// The rule written where Add-DnsClientNrptRule writes it: a PowerShell each
/// way cost about a second of every connect and disconnect
#[cfg(windows)]
mod nrpt {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE,
        REG_OPTION_VOLATILE, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
        RegDeleteKeyW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    };

    const RULES: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    /// Ours. Rules from older versions have random names and this comment.
    const RULE: &str = "{9b4f3c1e-5d2a-4e8b-a6f0-72657461696c}";
    const COMMENT: &str = "retail";
    /// NRPT_CONFIG_OPTION: the rule names DNS servers
    const GENERIC_DNS_SERVERS: u32 = 8;

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: a key this module opened
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn bytes(w: &[u16]) -> Vec<u8> {
        w.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    fn set(key: &Key, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> bool {
        // SAFETY: an open key, a terminated name and a buffer of the stated length
        unsafe {
            RegSetValueExW(
                key.0,
                wide(name).as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            ) == ERROR_SUCCESS
        }
    }

    fn create(parent: HKEY, path: &str, options: u32) -> Result<Key, u32> {
        let mut h = null_mut();
        // SAFETY: a terminated string and an out pointer valid for the call
        let r = unsafe {
            RegCreateKeyExW(
                parent,
                wide(path).as_ptr(),
                0,
                null(),
                options,
                KEY_ALL_ACCESS,
                null(),
                &mut h,
                null_mut(),
            )
        };
        if r == ERROR_SUCCESS {
            Ok(Key(h))
        } else {
            Err(r)
        }
    }

    pub fn add(namespace: &str, server: &str) -> bool {
        // The list stays an ordinary key, as other programs' rules need; only
        // ours is volatile, gone after a restart even if never undone
        let key = match create(HKEY_LOCAL_MACHINE, RULES, REG_OPTION_NON_VOLATILE)
            .and_then(|rules| create(rules.0, RULE, REG_OPTION_VOLATILE))
        {
            Ok(key) => key,
            Err(e) => {
                tracing::debug!("NRPT rule: error {e}");
                return false;
            }
        };
        let mut names = wide(namespace);
        names.push(0);
        let ok = set(&key, "Version", REG_DWORD, &2u32.to_le_bytes())
            && set(&key, "Name", REG_MULTI_SZ, &bytes(&names))
            && set(&key, "GenericDNSServers", REG_SZ, &bytes(&wide(server)))
            && set(
                &key,
                "ConfigOptions",
                REG_DWORD,
                &GENERIC_DNS_SERVERS.to_le_bytes(),
            )
            && set(&key, "IPSECCARestriction", REG_SZ, &bytes(&wide("")))
            && set(&key, "Comment", REG_SZ, &bytes(&wide(COMMENT)))
            && set(&key, "DisplayName", REG_SZ, &bytes(&wide(COMMENT)));
        drop(key);
        if ok {
            flush_cache();
        } else {
            remove();
        }
        ok
    }

    pub fn remove() {
        let mut h = null_mut();
        // SAFETY: a terminated string and an out pointer valid for the call
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(RULES).as_ptr(),
                0,
                KEY_ALL_ACCESS,
                &mut h,
            )
        } != ERROR_SUCCESS
        {
            return;
        }
        let rules = Key(h);
        let mut ours = Vec::new();
        for i in 0.. {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            // SAFETY: a buffer of `len` characters
            let r = unsafe {
                RegEnumKeyExW(
                    rules.0,
                    i,
                    name.as_mut_ptr(),
                    &mut len,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if r != ERROR_SUCCESS {
                break;
            }
            let name = name[..len as usize].to_vec();
            if String::from_utf16_lossy(&name).eq_ignore_ascii_case(RULE)
                || comment(&rules, &name).as_deref() == Some(COMMENT)
            {
                ours.push(name);
            }
        }
        if ours.is_empty() {
            return;
        }
        for mut name in ours {
            name.push(0);
            // SAFETY: an open key and a terminated name
            unsafe { RegDeleteKeyW(rules.0, name.as_ptr()) };
        }
        flush_cache();
    }

    fn comment(rules: &Key, name: &[u16]) -> Option<String> {
        let mut sub = name.to_vec();
        sub.push(0);
        let mut buf = [0u16; 64];
        let mut size = std::mem::size_of_val(&buf) as u32;
        // SAFETY: terminated strings and a buffer of `size` bytes
        let r = unsafe {
            RegGetValueW(
                rules.0,
                sub.as_ptr(),
                wide("Comment").as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        (r == ERROR_SUCCESS)
            .then(|| String::from_utf16_lossy(&buf[..(size as usize / 2).saturating_sub(1)]))
    }

    /// So names in the domain are not answered from before the change
    fn flush_cache() {
        use windows_sys::Win32::System::LibraryLoader::{
            GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
        };
        // SAFETY: dnsapi.dll from System32; DnsFlushResolverCache takes no
        // arguments and returns a BOOL
        unsafe {
            let lib = LoadLibraryExW(
                wide("dnsapi.dll").as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if lib.is_null() {
                return;
            }
            if let Some(f) = GetProcAddress(lib, c"DnsFlushResolverCache".as_ptr().cast()) {
                let flush: unsafe extern "system" fn() -> i32 = std::mem::transmute(f);
                flush();
            }
        }
    }

    /// Run by CI as an administrator: the DNS client applies the rule
    #[test]
    #[ignore]
    fn system_dns_client_applies_the_rule() {
        let policy = |ns: &str| {
            let script = format!(
                "(Get-DnsClientNrptPolicy -Namespace '{ns}' | Select-Object -ExpandProperty NameServers) -join ','"
            );
            let out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let ns = ".retail-nrpt-test.invalid";
        assert!(add(ns, "100.100.100.100"));
        assert_eq!(policy(ns), "100.100.100.100");
        remove();
        assert_eq!(policy(ns), "");
    }
}

/// macOS: a resolver file for the domain
#[cfg(target_os = "macos")]
fn setup(_tun: &str) -> bool {
    let _ = std::fs::create_dir_all("/etc/resolver");
    std::fs::write(
        format!("/etc/resolver/{MAGIC_DNS_DOMAIN}"),
        format!("# retail MagicDNS\nnameserver {MAGIC_DNS_IP}\n"),
    )
    .is_ok()
}

#[cfg(target_os = "macos")]
fn teardown(_tun: &str) {
    let _ = std::fs::remove_file(format!("/etc/resolver/{MAGIC_DNS_DOMAIN}"));
}

/// Linux: systemd-resolved, per link
#[cfg(target_os = "linux")]
fn setup(tun: &str) -> bool {
    run("resolvectl", &["dns", tun, &MAGIC_DNS_IP.to_string()])
        && run(
            "resolvectl",
            &["domain", tun, &format!("~{MAGIC_DNS_DOMAIN}")],
        )
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
            [
                ("laptop.retail.internal", Ipv4Addr::new(100, 64, 0, 1)),
                ("nas.retail.internal.", Ipv4Addr::new(100, 64, 0, 2)),
            ]
            .into_iter(),
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
        let (rcode, answers, _) =
            reply(&answer(&query("nas.retail.internal", 28), &names()).unwrap());
        assert_eq!((rcode, answers), (0, 0));
        let (rcode, _, _) =
            reply(&answer(&query("gone.retail.internal", TYPE_A), &names()).unwrap());
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
