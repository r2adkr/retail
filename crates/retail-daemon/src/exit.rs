//! Exit nodes: sending all internet traffic through a peer (client side) and
//! forwarding other nodes' traffic to the internet (exit side). Subnet
//! routes, the same on a smaller scale: routes for the networks peers route
//! (client side) and forwarding to the networks this device routes.
//!
//! Client side, the default route moves into the tunnel, so the daemon's own
//! outside sockets (WireGuard/STUN, control) must bypass it or the tunnel would
//! be carried over itself:
//! - Linux: sockets carry the fwmark [`BYPASS_MARK`] and policy rules send
//!   everything else to a table whose default route is the TUN device (the
//!   wg-quick scheme). Specific main-table routes (LAN) still win.
//! - Windows / macOS: two /1 routes cover the default route, and our sockets
//!   are pinned to the physical interface (`IP_UNICAST_IF` / `IP_BOUND_IF`).
//!
//! The tunnel carries IPv4 only, so IPv6 to the internet is blocked while an
//! exit node is in use instead of leaking around it.
//!
//! The Windows and macOS paths have not been exercised on real machines.

use std::io;
use std::process::Command;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, bail};
use retail_proto::route::Ipv4Net;

/// "RTL" in ASCII
#[cfg(target_os = "linux")]
pub const BYPASS_MARK: u32 = 0x0052_544c;
#[cfg(target_os = "linux")]
const TABLE: &str = "5254";
#[cfg(target_os = "linux")]
const PRIO_MAIN: &str = "5210";
#[cfg(target_os = "linux")]
const PRIO_TUNNEL: &str = "5230";

/// 0 when not pinned
#[cfg(any(target_os = "windows", target_os = "macos"))]
static BYPASS_IFINDEX: AtomicU32 = AtomicU32::new(0);

/// Call before `connect`/`bind`. On Windows and macOS it also works on a live
/// socket.
pub fn bypass(sock: socket2::SockRef<'_>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        sock.set_mark(BYPASS_MARK)
    }
    #[cfg(target_os = "windows")]
    {
        windows::unicast_if(&sock, BYPASS_IFINDEX.load(Ordering::Relaxed))
    }
    #[cfg(target_os = "macos")]
    {
        let idx = std::num::NonZeroU32::new(BYPASS_IFINDEX.load(Ordering::Relaxed));
        // Only one of the two applies, depending on the socket's family
        let _ = sock.bind_device_by_index_v4(idx);
        let _ = sock.bind_device_by_index_v6(idx);
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = sock;
        Ok(())
    }
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program} (is it installed?)"))?;
    if !out.status.success() {
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn run_quiet(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Routes all internet traffic into the TUN device until dropped
pub struct ClientRoutes {
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    tun_index: u32,
}

impl ClientRoutes {
    pub fn activate(tun: &str, tun_index: u32) -> Result<Self> {
        let routes = ClientRoutes { tun: tun.to_string(), tun_index };
        routes.cleanup();
        if let Err(e) = routes.install() {
            routes.cleanup();
            return Err(e);
        }
        tracing::info!(tun, "exit node routes installed");
        Ok(routes)
    }

    #[cfg(target_os = "linux")]
    fn install(&self) -> Result<()> {
        let mark = format!("{BYPASS_MARK:#x}");
        run("ip", &["-4", "route", "replace", "default", "dev", &self.tun, "table", TABLE])?;
        run("ip", &["-4", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", PRIO_MAIN])?;
        run("ip", &["-4", "rule", "add", "not", "fwmark", &mark, "table", TABLE, "priority", PRIO_TUNNEL])?;
        // IPv6 cannot go through the IPv4-only tunnel, so block it rather than leak
        let v6 = run("ip", &["-6", "route", "replace", "unreachable", "default", "table", TABLE])
            .and_then(|()| run("ip", &["-6", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", PRIO_MAIN]))
            .and_then(|()| run("ip", &["-6", "rule", "add", "not", "fwmark", &mark, "table", TABLE, "priority", PRIO_TUNNEL]));
        if let Err(e) = v6 {
            tracing::debug!("IPv6 exit rules not installed (no IPv6?): {e:#}");
        }
        // Replies to our marked sockets carry no mark, and restoring it from the
        // connection lets strict reverse-path filtering accept them
        let _ = run("sysctl", &["-qw", "net.ipv4.conf.all.src_valid_mark=1"]);
        let connmark = run_quiet("iptables", &["-t", "mangle", "-N", "RETAIL-MARK"])
            | run_quiet("iptables", &["-t", "mangle", "-F", "RETAIL-MARK"]);
        let ok = connmark
            && run_quiet("iptables", &["-t", "mangle", "-A", "RETAIL-MARK", "-m", "mark", "--mark", &mark, "-j", "CONNMARK", "--save-mark"])
            && run_quiet("iptables", &["-t", "mangle", "-I", "OUTPUT", "1", "-j", "RETAIL-MARK"])
            && run_quiet("iptables", &["-t", "mangle", "-I", "PREROUTING", "1", "-j", "CONNMARK", "--restore-mark"]);
        if !ok {
            tracing::warn!("iptables unavailable: with strict rp_filter, replies to the daemon may be dropped while an exit node is in use");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn cleanup(&self) {
        for fam in ["-4", "-6"] {
            for prio in [PRIO_MAIN, PRIO_TUNNEL] {
                while run_quiet("ip", &[fam, "rule", "del", "priority", prio]) {}
            }
            run_quiet("ip", &[fam, "route", "flush", "table", TABLE]);
        }
        while run_quiet("iptables", &["-t", "mangle", "-D", "OUTPUT", "-j", "RETAIL-MARK"]) {}
        while run_quiet("iptables", &["-t", "mangle", "-D", "PREROUTING", "-j", "CONNMARK", "--restore-mark"]) {}
        run_quiet("iptables", &["-t", "mangle", "-F", "RETAIL-MARK"]);
        run_quiet("iptables", &["-t", "mangle", "-X", "RETAIL-MARK"]);
    }

    #[cfg(target_os = "windows")]
    fn install(&self) -> Result<()> {
        let physical = windows::default_interface().context("finding the default network interface")?;
        BYPASS_IFINDEX.store(physical, Ordering::Relaxed);
        let idx = self.tun_index.to_string();
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            run("netsh", &["interface", "ipv4", "add", "route", prefix, &idx, "metric=0", "store=active"])?;
        }
        // The TUN device drops IPv6, so routing it there blocks it
        for prefix in ["::/1", "8000::/1"] {
            let _ = run("netsh", &["interface", "ipv6", "add", "route", prefix, &idx, "metric=0", "store=active"]);
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn cleanup(&self) {
        let idx = self.tun_index.to_string();
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            run_quiet("netsh", &["interface", "ipv4", "delete", "route", prefix, &idx]);
        }
        for prefix in ["::/1", "8000::/1"] {
            run_quiet("netsh", &["interface", "ipv6", "delete", "route", prefix, &idx]);
        }
        BYPASS_IFINDEX.store(0, Ordering::Relaxed);
    }

    #[cfg(target_os = "macos")]
    fn install(&self) -> Result<()> {
        let physical = macos::default_interface().context("finding the default network interface")?;
        BYPASS_IFINDEX.store(physical, Ordering::Relaxed);
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            run("route", &["-q", "-n", "add", "-inet", prefix, "-interface", &self.tun])?;
        }
        for prefix in ["::/1", "8000::/1"] {
            let _ = run("route", &["-q", "-n", "add", "-inet6", prefix, "-interface", &self.tun]);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn cleanup(&self) {
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            run_quiet("route", &["-q", "-n", "delete", "-inet", prefix, "-interface", &self.tun]);
        }
        for prefix in ["::/1", "8000::/1"] {
            run_quiet("route", &["-q", "-n", "delete", "-inet6", prefix, "-interface", &self.tun]);
        }
        BYPASS_IFINDEX.store(0, Ordering::Relaxed);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn install(&self) -> Result<()> {
        bail!("using an exit node is not supported on this system")
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn cleanup(&self) {}
}

impl Drop for ClientRoutes {
    fn drop(&mut self) {
        self.cleanup();
        tracing::info!("exit node routes removed");
    }
}

/// Forwards and NATs traffic from the mesh until dropped: to the internet
/// (an exit node), and to the networks this device routes. One set of rules
/// for both, so neither undoes the other.
pub struct Gateway {
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    tun_index: u32,
    #[allow(dead_code)]
    restore_forwarding: bool,
    exit: bool,
    routes: Vec<Ipv4Net>,
    /// macOS: the reference that keeps pf enabled for us
    #[allow(dead_code)]
    pf_token: Option<String>,
}

/// The exit's own private networks stay unreachable unless it routes them
#[cfg(target_os = "linux")]
const PRIVATE: [&str; 6] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8"];

impl Gateway {
    pub fn new(tun: &str, tun_index: u32) -> Self {
        Gateway { tun: tun.to_string(), tun_index, restore_forwarding: false, exit: false, routes: Vec::new(), pf_token: None }
    }

    pub fn exit(&self) -> bool {
        self.exit
    }

    /// Forwards for what is asked, or nothing on an error
    pub fn set(&mut self, exit: bool, routes: &[Ipv4Net]) -> Result<()> {
        if self.exit == exit && self.routes == routes {
            return Ok(());
        }
        self.cleanup();
        self.exit = exit;
        self.routes = routes.to_vec();
        if !exit && routes.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.install() {
            self.cleanup();
            self.exit = false;
            self.routes.clear();
            return Err(e);
        }
        if exit {
            tracing::info!(tun = %self.tun, "offering this node as an exit node");
        }
        if !routes.is_empty() {
            tracing::info!(?routes, "routing networks for the mesh");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn install(&mut self) -> Result<()> {
        let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
        if forwarding.trim() != "1" {
            run("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;
            self.restore_forwarding = true;
        }
        let tun = self.tun.clone();
        let tun = tun.as_str();
        let routes: Vec<String> = self.routes.iter().map(|r| r.to_string()).collect();
        let ipt = |args: &[&str]| run("iptables", args);
        // First in FORWARD because Docker and firewalls often set DROP
        ipt(&["-N", "RETAIL-FWD"])?;
        for net in &routes {
            ipt(&["-A", "RETAIL-FWD", "-i", tun, "-d", net, "-j", "ACCEPT"])?;
        }
        if self.exit {
            for net in PRIVATE {
                ipt(&["-A", "RETAIL-FWD", "-i", tun, "-d", net, "-j", "DROP"])?;
            }
            ipt(&["-A", "RETAIL-FWD", "-i", tun, "-j", "ACCEPT"])?;
        } else {
            ipt(&["-A", "RETAIL-FWD", "-i", tun, "-j", "DROP"])?;
        }
        ipt(&["-A", "RETAIL-FWD", "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
        ipt(&["-I", "FORWARD", "1", "-j", "RETAIL-FWD"])?;
        // Hosts on routed networks need no route back to the mesh
        ipt(&["-t", "nat", "-N", "RETAIL-NAT"])?;
        if self.exit {
            ipt(&["-t", "nat", "-A", "RETAIL-NAT", "-s", "100.64.0.0/10", "!", "-o", tun, "-j", "MASQUERADE"])?;
        } else {
            for net in &routes {
                ipt(&["-t", "nat", "-A", "RETAIL-NAT", "-s", "100.64.0.0/10", "-d", net, "!", "-o", tun, "-j", "MASQUERADE"])?;
            }
        }
        ipt(&["-t", "nat", "-I", "POSTROUTING", "1", "-j", "RETAIL-NAT"])?;
        ipt(&["-t", "mangle", "-N", "RETAIL-MSS"])?;
        for dir in ["-i", "-o"] {
            ipt(&["-t", "mangle", "-A", "RETAIL-MSS", dir, tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])?;
        }
        ipt(&["-t", "mangle", "-I", "FORWARD", "1", "-j", "RETAIL-MSS"])?;
        Ok(())
    }

    /// Also removes chains left behind by a crash
    #[cfg(target_os = "linux")]
    fn cleanup(&mut self) {
        for (table, parent, chain) in [
            ("filter", "FORWARD", "RETAIL-FWD"),
            ("nat", "POSTROUTING", "RETAIL-NAT"),
            ("mangle", "FORWARD", "RETAIL-MSS"),
        ] {
            while run_quiet("iptables", &["-t", table, "-D", parent, "-j", chain]) {}
            run_quiet("iptables", &["-t", table, "-F", chain]);
            run_quiet("iptables", &["-t", table, "-X", chain]);
        }
        if self.restore_forwarding {
            run_quiet("sysctl", &["-qw", "net.ipv4.ip_forward=0"]);
            self.restore_forwarding = false;
        }
    }

    /// One NAT for the mesh's addresses covers the internet and routed
    /// networks alike. Which destinations reach the system at all is the
    /// engine's choice (`filter.rs`): only approved networks, and the internet
    /// while this is an exit node.
    #[cfg(target_os = "windows")]
    fn install(&mut self) -> Result<()> {
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             Set-NetIPInterface -InterfaceIndex {idx} -Forwarding Enabled; \
             New-NetNat -Name retail-exit -InternalIPInterfaceAddressPrefix 100.64.0.0/10 | Out-Null",
            idx = self.tun_index
        );
        run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])
    }

    #[cfg(target_os = "windows")]
    fn cleanup(&mut self) {
        run_quiet(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", "Remove-NetNat -Name retail-exit -Confirm:$false"],
        );
    }

    /// IP forwarding, and pf NAT in an anchor the system's pf.conf already
    /// loads (`com.apple/*`) for each routed network, out of the interface
    /// that reaches it
    #[cfg(target_os = "macos")]
    fn install(&mut self) -> Result<()> {
        if self.exit {
            bail!("offering an exit node is supported on Linux and Windows only");
        }
        let forwarding = Command::new("sysctl").args(["-n", "net.inet.ip.forwarding"]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        if forwarding != "1" {
            run("sysctl", &["-w", "net.inet.ip.forwarding=1"])?;
            self.restore_forwarding = true;
        }
        let mut rules = String::new();
        for r in &self.routes {
            let iface = macos_route_interface(r.addr()).with_context(|| format!("finding the interface that reaches {r}"))?;
            rules.push_str(&format!("nat on {iface} inet from 100.64.0.0/10 to {r} -> ({iface})\n"));
        }
        run_with_input("pfctl", &["-a", PF_ANCHOR, "-f", "-"], &rules)?;
        // Enabling pf takes a reference, released at cleanup, so pf stays as
        // it was for everything else
        let out = Command::new("pfctl").arg("-E").output().context("running pfctl")?;
        let text = String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
        self.pf_token = text.lines().find_map(|l| l.trim().strip_prefix("Token : ")).map(|t| t.trim().to_string());
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn cleanup(&mut self) {
        run_quiet("pfctl", &["-a", PF_ANCHOR, "-F", "all"]);
        if let Some(token) = self.pf_token.take() {
            run_quiet("pfctl", &["-X", &token]);
        }
        if self.restore_forwarding {
            run_quiet("sysctl", &["-w", "net.inet.ip.forwarding=0"]);
            self.restore_forwarding = false;
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn install(&mut self) -> Result<()> {
        bail!("forwarding for the mesh is not supported on this system")
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn cleanup(&mut self) {}
}

#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.apple/retail";

/// The interface macOS sends `ip` out of
#[cfg(target_os = "macos")]
fn macos_route_interface(ip: std::net::Ipv4Addr) -> Option<String> {
    let out = Command::new("route").args(["-n", "get", &ip.to_string()]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text.lines().find_map(|l| l.trim().strip_prefix("interface:"))?.trim().to_string();
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric())).then_some(name)
}

#[cfg(target_os = "macos")]
fn run_with_input(program: &str, args: &[&str], input: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running {program}"))?;
    child.stdin.take().context("no stdin")?.write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if self.exit || !self.routes.is_empty() {
            self.cleanup();
            tracing::info!("no longer forwarding for the mesh");
        }
    }
}

/// Routes the networks peers route into the TUN device, until dropped
pub struct SubnetRoutes {
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    tun_index: u32,
    installed: Vec<Ipv4Net>,
}

impl SubnetRoutes {
    pub fn new(tun: &str, tun_index: u32) -> Self {
        SubnetRoutes { tun: tun.to_string(), tun_index, installed: Vec::new() }
    }

    /// Adds and removes routes to match `wanted`. A route that fails is
    /// reported and left out.
    pub fn set(&mut self, wanted: &[Ipv4Net]) -> Result<()> {
        let gone: Vec<Ipv4Net> = self.installed.iter().filter(|r| !wanted.contains(r)).copied().collect();
        for r in gone {
            self.remove(r);
            self.installed.retain(|x| *x != r);
        }
        let mut result = Ok(());
        for r in wanted.iter().filter(|r| !self.installed.contains(r)).copied().collect::<Vec<_>>() {
            match self.add(r) {
                Ok(()) => {
                    tracing::info!(route = %r, "routing into the mesh");
                    self.installed.push(r);
                }
                Err(e) => {
                    tracing::warn!("adding the route to {r}: {e:#}");
                    result = Err(e.context(format!("adding the route to {r}")));
                }
            }
        }
        result
    }

    #[cfg(target_os = "linux")]
    fn add(&self, r: Ipv4Net) -> Result<()> {
        run("ip", &["-4", "route", "replace", &r.to_string(), "dev", &self.tun])
    }

    #[cfg(target_os = "linux")]
    fn remove(&self, r: Ipv4Net) {
        run_quiet("ip", &["-4", "route", "del", &r.to_string(), "dev", &self.tun]);
    }

    #[cfg(target_os = "windows")]
    fn add(&self, r: Ipv4Net) -> Result<()> {
        let idx = self.tun_index.to_string();
        run("netsh", &["interface", "ipv4", "add", "route", &r.to_string(), &idx, "metric=0", "store=active"])
    }

    #[cfg(target_os = "windows")]
    fn remove(&self, r: Ipv4Net) {
        let idx = self.tun_index.to_string();
        run_quiet("netsh", &["interface", "ipv4", "delete", "route", &r.to_string(), &idx]);
    }

    #[cfg(target_os = "macos")]
    fn add(&self, r: Ipv4Net) -> Result<()> {
        run("route", &["-q", "-n", "add", "-inet", &r.to_string(), "-interface", &self.tun])
    }

    #[cfg(target_os = "macos")]
    fn remove(&self, r: Ipv4Net) {
        run_quiet("route", &["-q", "-n", "delete", "-inet", &r.to_string(), "-interface", &self.tun]);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn add(&self, _r: Ipv4Net) -> Result<()> {
        bail!("subnet routes are not supported on this system")
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn remove(&self, _r: Ipv4Net) {}
}

impl Drop for SubnetRoutes {
    fn drop(&mut self) {
        for r in std::mem::take(&mut self.installed) {
            self.remove(r);
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::io;
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, IN_ADDR, IN_ADDR_0, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKADDR, SOCKADDR_IN,
        SOCKET, setsockopt,
    };

    pub fn default_interface() -> io::Result<u32> {
        let dst = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes([1, 1, 1, 1]) } },
            sin_zero: [0; 8],
        };
        let mut index = 0u32;
        // SAFETY: valid pointers to a SOCKADDR_IN and a u32 for the call's duration
        let r = unsafe { GetBestInterfaceEx((&dst as *const SOCKADDR_IN).cast::<SOCKADDR>(), &mut index) };
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
        Ok(index)
    }

    /// Index 0 unpins
    pub fn unicast_if(sock: &socket2::SockRef<'_>, index: u32) -> io::Result<()> {
        let raw = sock.as_raw_socket() as SOCKET;
        // IPv4 takes the index in network byte order, IPv6 in host order
        let v4 = index.to_be();
        // SAFETY: valid socket handle and option buffers of the stated size
        // Errors are ignored because only the option matching the socket's family applies
        unsafe {
            setsockopt(raw, IPPROTO_IP, IP_UNICAST_IF, (&v4 as *const u32).cast(), 4);
            setsockopt(raw, IPPROTO_IPV6, IPV6_UNICAST_IF, (&index as *const u32).cast(), 4);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;

    pub fn default_interface() -> io::Result<u32> {
        let out = std::process::Command::new("route").args(["-n", "get", "default"]).output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let name = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("interface:"))
            .map(str::trim)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default route"))?;
        let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: valid NUL-terminated string
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if index == 0 { Err(io::Error::last_os_error()) } else { Ok(index) }
    }
}
