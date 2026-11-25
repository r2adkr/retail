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
        let out = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-iTCP@{}:{}", addr.ip(), addr.port()), "-sTCP:LISTEN", "-Fu"])
            .output()
            .map_err(|e| format!("lsof: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let me = unsafe { libc::geteuid() };
        let uids: Vec<u32> = text.lines().filter_map(|l| l.strip_prefix('u')?.parse().ok()).collect();
        match uids.first() {
            None => Err(format!("nothing is listening on {addr}")),
            Some(&uid) if uids.iter().all(|&u| u == uid) && (uid == 0 || uid == me) => Ok(()),
            Some(uid) => Err(refuse(addr, &format!("user id {uid}"))),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER};
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    /// Services, retaild among them, run in session 0, where a signed-in user
    /// cannot start programs; otherwise it must be this user's own session
    pub fn check(addr: SocketAddr) -> Result<(), String> {
        let SocketAddr::V4(v4) = addr else { return Err(format!("{addr}: only IPv4 local API addresses can be checked")) };
        let pid = owner(v4).ok_or_else(|| format!("nothing is listening on {addr}"))?;
        let session = |pid: u32| {
            let mut s = u32::MAX;
            (unsafe { ProcessIdToSessionId(pid, &mut s) } != 0).then_some(s)
        };
        let theirs = session(pid);
        let mine = session(unsafe { GetCurrentProcessId() });
        match theirs {
            Some(0) => Ok(()),
            Some(s) if Some(s) == mine => Ok(()),
            _ => Err(refuse(addr, &format!("process {pid}, another user's session"))),
        }
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
