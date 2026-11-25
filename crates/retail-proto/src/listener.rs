//! Who is listening on the local API port. Any program can listen there while
//! retaild is not (before it starts, while it restarts), and clients would
//! then hand it invite codes, passwords and backups, and act on its answers.
//! So before they do, clients ask the system who owns the listening socket:
//! it must be root/SYSTEM, as the daemon runs, or the user itself (a daemon
//! the user started, as in tests).

use std::net::SocketAddr;

/// `Ok` when the listener on `addr` is retaild's kind of process
pub fn check(addr: SocketAddr) -> Result<(), String> {
    imp::check(addr)
}

fn refuse(addr: SocketAddr, who: &str) -> String {
    format!("the program listening on {addr} is not retaild ({who}); not sending it anything")
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub fn check(addr: SocketAddr) -> Result<(), String> {
        let table = if addr.is_ipv4() { "/proc/net/tcp" } else { "/proc/net/tcp6" };
        let text = std::fs::read_to_string(table).map_err(|e| format!("reading {table}: {e}"))?;
        let uid = listener_uid(&text, addr).ok_or_else(|| format!("nothing is listening on {addr}"))?;
        let me = unsafe { libc::geteuid() };
        if uid == 0 || uid == me { Ok(()) } else { Err(refuse(addr, &format!("user id {uid}"))) }
    }

    /// The owner of the listening socket for `addr` in a `/proc/net/tcp` table
    pub(super) fn listener_uid(table: &str, addr: SocketAddr) -> Option<u32> {
        let want = match addr {
            SocketAddr::V4(a) => format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port()),
            SocketAddr::V6(a) => {
                let words: String = a.ip().octets().chunks(4).map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))).collect();
                format!("{words}:{:04X}", a.port())
            }
        };
        table.lines().skip(1).find_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // local, remote, state (0A is LISTEN), ..., uid
            (f.len() > 7 && f[1] == want && f[3] == "0A").then(|| f[7].parse().ok()).flatten()
        })
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn check(addr: SocketAddr) -> Result<(), String> {
        let me = unsafe { libc::geteuid() };
        // lsof sees only this user's sockets unless run as root; the root
        // daemon's is found through netstat, which lists every socket's process
        let uids = match lsof_uids(addr)? {
            u if !u.is_empty() => u,
            _ => netstat_pids(addr)?.into_iter().filter_map(uid_of).collect(),
        };
        match uids.first() {
            None => Err(format!("nothing is listening on {addr}")),
            Some(&uid) if uids.iter().all(|&u| u == uid) && (uid == 0 || uid == me) => Ok(()),
            Some(uid) => Err(refuse(addr, &format!("user id {uid}"))),
        }
    }

    fn lsof_uids(addr: SocketAddr) -> Result<Vec<u32>, String> {
        let out = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-iTCP@{}:{}", addr.ip(), addr.port()), "-sTCP:LISTEN", "-Fu"])
            .output()
            .map_err(|e| format!("lsof: {e}"))?;
        Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.strip_prefix('u')?.parse().ok()).collect())
    }

    fn netstat_pids(addr: SocketAddr) -> Result<Vec<u32>, String> {
        let out = std::process::Command::new("/usr/sbin/netstat")
            .args(["-anv", "-p", "tcp"])
            .output()
            .map_err(|e| format!("netstat: {e}"))?;
        Ok(super::netstat_listeners(&String::from_utf8_lossy(&out.stdout), addr))
    }

    fn uid_of(pid: u32) -> Option<u32> {
        let out = std::process::Command::new("/bin/ps").args(["-o", "uid=", "-p", &pid.to_string()]).output().ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
}

/// Processes listening on `addr` in `netstat -anv` output (macOS). The
/// process is a `pid` column in older versions, `name:pid` in newer ones.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn netstat_listeners(text: &str, addr: SocketAddr) -> Vec<u32> {
    let local = format!("{}.{}", addr.ip(), addr.port());
    // "Local Address" and "Foreign Address" are two words each in the header
    let pid_col = text
        .lines()
        .find(|l| l.starts_with("Proto"))
        .and_then(|h| h.split_whitespace().position(|w| w == "pid"))
        .map(|i| i - 2);
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 || f[3] != local || !f.contains(&"LISTEN") {
                return None;
            }
            let named = f.iter().find_map(|t| t.rsplit_once(':').and_then(|(name, pid)| (!name.is_empty()).then(|| pid.parse().ok()).flatten()));
            named.or_else(|| f.get(pid_col?)?.parse().ok())
        })
        .collect()
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER};
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::RemoteDesktop::{WTS_PROCESS_INFOW, WTSEnumerateProcessesW, WTSFreeMemory};
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    /// Services, retaild among them, run in session 0, where a signed-in user
    /// cannot start programs; otherwise it must be this user's own session
    pub fn check(addr: SocketAddr) -> Result<(), String> {
        let SocketAddr::V4(v4) = addr else { return Err(format!("{addr}: only IPv4 local API addresses can be checked")) };
        let pid = owner(v4).ok_or_else(|| format!("nothing is listening on {addr}"))?;
        let (theirs, mine) = sessions(pid, unsafe { GetCurrentProcessId() });
        match theirs {
            Some(0) => Ok(()),
            Some(s) if Some(s) == mine => Ok(()),
            _ => Err(refuse(addr, &format!("process {pid}, another user's session"))),
        }
    }

    /// The sessions of two processes. The system's process list has them for
    /// every process; asking a process itself needs rights a plain user
    /// lacks for services.
    fn sessions(a: u32, b: u32) -> (Option<u32>, Option<u32>) {
        let mut list: *mut WTS_PROCESS_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if unsafe { WTSEnumerateProcessesW(std::ptr::null_mut(), 0, 1, &mut list, &mut count) } == 0 || list.is_null() {
            return (None, None);
        }
        let procs = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let find = |pid: u32| procs.iter().find(|p| p.ProcessId == pid).map(|p| p.SessionId);
        let out = (find(a), find(b));
        unsafe { WTSFreeMemory(list.cast()) };
        out
    }

    fn owner(addr: std::net::SocketAddrV4) -> Option<u32> {
        let mut size = 0u32;
        unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0) };
        // Room for a few more rows appearing between the two calls
        let mut buf = vec![0u64; (size as usize + 1024) / 8 + 1];
        size = (buf.len() * 8) as u32;
        let rc = unsafe { GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_LISTENER, 0) };
        if rc != 0 {
            return None;
        }
        let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
        let ip = u32::from_ne_bytes(addr.ip().octets());
        rows.iter()
            .find(|r| {
                let port = u16::from_be((r.dwLocalPort & 0xFFFF) as u16);
                port == addr.port() && (r.dwLocalAddr == ip || r.dwLocalAddr == 0)
            })
            .map(|r| r.dwOwningPid)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use super::*;

    pub fn check(_addr: SocketAddr) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_tcp_rows() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:A0A8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1\n\
             1: 0100007F:A0A9 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1\n";
        let addr: SocketAddr = "127.0.0.1:41128".parse().unwrap();
        assert_eq!(imp::listener_uid(table, addr), Some(1000));
        // Not listening (state 01): no owner
        assert_eq!(imp::listener_uid(table, "127.0.0.1:41129".parse().unwrap()), None);
    }

    #[test]
    fn netstat_rows() {
        let addr: SocketAddr = "127.0.0.1:41112".parse().unwrap();
        let old = "Active Internet connections (including servers)\n\
            Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat shiwat    pid   epid  state    options\n\
            tcp4       0      0  127.0.0.1.41112        *.*                    LISTEN      131072 131072    321      0 0x0100 0x00000106\n\
            tcp4       0      0  127.0.0.1.41113        *.*                    LISTEN      131072 131072    999      0 0x0100 0x00000106\n";
        assert_eq!(netstat_listeners(old, addr), [321]);
        let new = "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes      txbytes  rhiwat  shiwat    process:pid       state  options\n\
            tcp4       0      0  127.0.0.1.41112        *.*                    LISTEN             0            0  131072  131072    retaild:4242  0x0100 0x00000106\n";
        assert_eq!(netstat_listeners(new, addr), [4242]);
        assert!(netstat_listeners(new, "127.0.0.1:1".parse().unwrap()).is_empty());
    }

    /// A service's socket (RPC on 135, in session 0) passes for a plain user too
    #[cfg(windows)]
    #[test]
    fn service_listener_passes() {
        assert_eq!(check("127.0.0.1:135".parse().unwrap()), Ok(()));
    }

    /// A socket this test opens is its own, so it passes
    #[test]
    fn own_listener_passes() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        assert_eq!(check(addr), Ok(()));
        drop(l);
        assert!(check(addr).is_err());
    }
}
