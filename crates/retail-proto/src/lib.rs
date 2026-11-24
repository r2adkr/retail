//! Wire types shared by the control server, the daemon and the CLI.
//!
//! Everything on the wire is JSON. Keys are standard base64, as in WireGuard tools.

pub mod api;
pub mod invite;
pub mod package;
pub mod key;
pub mod local;
pub mod relay;
pub mod stun;

pub use key::Key;

/// RFC 6598 shared address space, the block node IPs are allocated from
pub const MESH_NETWORK: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 0);
pub const MESH_PREFIX_LEN: u8 = 10;

pub const DEFAULT_STUN_PORT: u16 = 3478;
/// Shared by WireGuard and STUN traffic
pub const DEFAULT_WG_PORT: u16 = 41641;
/// Web admin page of a hosting device
pub const WEB_ADMIN_PORT: u16 = 41180;
/// Official client builds, under `v<version>/`
pub const RELEASES: &str = "https://github.com/r2adkr/retail/releases/download";
pub const LOCAL_API_ADDR: &str = "127.0.0.1:41112";
pub const TUN_MTU: u16 = 1280;

pub fn in_mesh(ip: std::net::Ipv4Addr) -> bool {
    let mask = u32::MAX << (32 - MESH_PREFIX_LEN);
    (u32::from(ip) & mask) == u32::from(MESH_NETWORK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn mesh_membership() {
        assert!(in_mesh(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(in_mesh(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!in_mesh(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!in_mesh(Ipv4Addr::new(192, 168, 0, 1)));
    }
}
