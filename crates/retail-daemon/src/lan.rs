//! Wake-on-LAN. Each device reports its network cards on local networks
//! (`LanPort`: MAC address, address and prefix); the server keeps the last
//! report while the device is off. To wake one, any online device on the same
//! local network sends the magic packet there: this one, or peers asked
//! through the tunnel (see `Engine::wake`).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use retail_proto::api::LanPort;

/// This device's network cards on local networks
pub fn ports() -> Vec<LanPort> {
    let mut out: Vec<LanPort> = imp::ports().into_iter().filter(LanPort::valid).collect();
    out.sort_by_key(|p| (p.addr, p.mac));
    out.dedup();
    out.truncate(LanPort::MAX);
    out
}

/// Six 0xff bytes, then the MAC address 16 times, to the network's broadcast
/// address on the usual port
pub fn send_magic(mac: [u8; 6], broadcast: Ipv4Addr) -> std::io::Result<()> {
    let mut packet = vec![0xffu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.set_broadcast(true)?;
    sock.send_to(&packet, SocketAddr::from((broadcast, 9)))?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn v4_with_names() -> Vec<(String, Ipv4Addr, u8)> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    ifaces
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => {
                Some((i.name, v4.ip, u32::from(v4.netmask).count_ones() as u8))
            }
            _ => None,
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub fn ports() -> Vec<LanPort> {
        v4_with_names()
            .into_iter()
            .filter_map(|(name, addr, prefix)| {
                let text =
                    std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
                Some(LanPort {
                    mac: parse_mac(text.trim())?,
                    addr,
                    prefix,
                })
            })
            .collect()
    }

    fn parse_mac(s: &str) -> Option<[u8; 6]> {
        let mut mac = [0u8; 6];
        let mut parts = s.split(':');
        for b in &mut mac {
            *b = u8::from_str_radix(parts.next()?, 16).ok()?;
        }
        parts.next().is_none().then_some(mac)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn ports() -> Vec<LanPort> {
        let macs = link_addresses();
        v4_with_names()
            .into_iter()
            .filter_map(|(name, addr, prefix)| {
                let mac = macs.iter().find(|(n, _)| *n == name)?.1;
                Some(LanPort { mac, addr, prefix })
            })
            .collect()
    }

    /// Link-layer (AF_LINK) addresses by interface name
    fn link_addresses() -> Vec<(String, [u8; 6])> {
        let mut out = Vec::new();
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs fills a list freed below with freeifaddrs
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: nodes of the list getifaddrs returned
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null()
                || unsafe { (*ifa.ifa_addr).sa_family } as i32 != libc::AF_LINK
            {
                continue;
            }
            // SAFETY: an AF_LINK address is a sockaddr_dl
            let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
            if dl.sdl_alen != 6 {
                continue;
            }
            let start = dl.sdl_nlen as usize;
            let data: &[libc::c_char] = &dl.sdl_data;
            if start + 6 > data.len() {
                continue;
            }
            let mut mac = [0u8; 6];
            for (m, &b) in mac.iter_mut().zip(&data[start..start + 6]) {
                *m = b as u8;
            }
            // SAFETY: ifa_name is a C string
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            out.push((name, mac));
        }
        // SAFETY: the list from getifaddrs above
        unsafe { libc::freeifaddrs(head) };
        out
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    pub fn ports() -> Vec<LanPort> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut len: u32 = 16 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        for _ in 0..3 {
            buf = vec![0u64; len as usize / 8 + 1];
            // SAFETY: the buffer is `len` bytes, 8-aligned
            let r = unsafe {
                GetAdaptersAddresses(
                    AF_INET as u32,
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            match r {
                0 => break,
                111 => continue, // ERROR_BUFFER_OVERFLOW: `len` now says how much
                _ => return Vec::new(),
            }
        }
        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            // SAFETY: the list GetAdaptersAddresses wrote into `buf`
            let a = unsafe { &*cur };
            cur = a.Next;
            if a.OperStatus != IfOperStatusUp || a.PhysicalAddressLength != 6 {
                continue;
            }
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&a.PhysicalAddress[..6]);
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                // SAFETY: entries of the same list
                let ua = unsafe { &*u };
                u = ua.Next;
                let sa = ua.Address.lpSockaddr;
                if sa.is_null() || unsafe { (*sa).sa_family } != AF_INET {
                    continue;
                }
                // SAFETY: an AF_INET address is a SOCKADDR_IN
                let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                let addr = Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr }));
                out.push(LanPort {
                    mac,
                    addr,
                    prefix: ua.OnLinkPrefixLength,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_and_broadcast() {
        let a = LanPort {
            mac: [2, 0, 0, 0, 0, 1],
            addr: Ipv4Addr::new(192, 168, 0, 12),
            prefix: 24,
        };
        let b = LanPort {
            mac: [2, 0, 0, 0, 0, 2],
            addr: Ipv4Addr::new(192, 168, 0, 40),
            prefix: 24,
        };
        let c = LanPort {
            addr: Ipv4Addr::new(192, 168, 1, 40),
            ..b
        };
        assert_eq!(a.broadcast(), Ipv4Addr::new(192, 168, 0, 255));
        assert!(a.shares_network(&b) && !a.shares_network(&c));
        assert!(a.valid());
        assert!(
            !LanPort {
                addr: Ipv4Addr::new(100, 64, 0, 2),
                ..a
            }
            .valid()
        );
        assert!(
            !LanPort {
                mac: [1, 0, 0, 0, 0, 0],
                ..a
            }
            .valid()
        );
        // Whatever this machine has, every entry is usable
        assert!(ports().iter().all(LanPort::valid));
    }
}
