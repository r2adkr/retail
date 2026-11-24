//! Exit nodes: sending all internet traffic through a peer (client side) and
//! forwarding other nodes' traffic to the internet (exit side).
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

/// Forwards and NATs traffic from the mesh to the internet until dropped
pub struct ExitNat {
    #[allow(dead_code)]
    tun: String,
    #[allow(dead_code)]
    tun_index: u32,
    #[allow(dead_code)]
    restore_forwarding: bool,
}

/// The exit's own private networks stay unreachable since an exit node is not
/// a subnet router
#[cfg(target_os = "linux")]
const PRIVATE: [&str; 6] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8"];

impl ExitNat {
    pub fn enable(tun: &str, tun_index: u32) -> Result<Self> {
        let mut nat = ExitNat { tun: tun.to_string(), tun_index, restore_forwarding: false };
        nat.cleanup();
        if let Err(e) = nat.install() {
            nat.cleanup();
            return Err(e);
        }
        tracing::info!(tun, "offering this node as an exit node");
        Ok(nat)
    }

    #[cfg(target_os = "linux")]
    fn install(&mut self) -> Result<()> {
        let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
        if forwarding.trim() != "1" {
            run("sysctl", &["-qw", "net.ipv4.ip_forward=1"])?;
            self.restore_forwarding = true;
        }
        let tun = self.tun.as_str();
        let ipt = |args: &[&str]| run("iptables", args);
        // First in FORWARD because Docker and firewalls often set DROP
        ipt(&["-N", "RETAIL-FWD"])?;
        for net in PRIVATE {
            ipt(&["-A", "RETAIL-FWD", "-i", tun, "-d", net, "-j", "DROP"])?;
        }
        ipt(&["-A", "RETAIL-FWD", "-i", tun, "-j", "ACCEPT"])?;
        ipt(&["-A", "RETAIL-FWD", "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
        ipt(&["-I", "FORWARD", "1", "-j", "RETAIL-FWD"])?;
        ipt(&["-t", "nat", "-N", "RETAIL-NAT"])?;
        ipt(&["-t", "nat", "-A", "RETAIL-NAT", "-s", "100.64.0.0/10", "!", "-o", tun, "-j", "MASQUERADE"])?;
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
    fn cleanup(&self) {
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
        }
    }

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
    fn cleanup(&self) {
        run_quiet(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", "Remove-NetNat -Name retail-exit -Confirm:$false"],
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn install(&mut self) -> Result<()> {
        bail!("offering an exit node is supported on Linux and Windows only")
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn cleanup(&self) {}
}

impl Drop for ExitNat {
    fn drop(&mut self) {
        self.cleanup();
        tracing::info!("no longer offering this node as an exit node");
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
