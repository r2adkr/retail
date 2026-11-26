//! WireGuard datagrams carried over the control WebSocket when no direct UDP
//! path works. A frame is one binary WebSocket message:
//!
//! ```text
//!   node key (32 bytes) | len (u16 BE) | datagram | len | datagram | ...
//! ```
//!
//! From a node the key names the destination. The server rewrites it to the
//! sender's key before forwarding. Payloads are WireGuard ciphertext, so the
//! server can neither read nor forge them.

use crate::Key;

/// Also the WebSocket message cap
pub const MAX_FRAME: usize = 64 * 1024;
/// A frame that waited longer for the connection is dropped. TCP inside backs
/// off on the loss, and what comes after it (a game's packets) does not wait
/// seconds behind a download on a slow relay.
pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// Lets a connection that carries the relay keep only a little unsent in the
/// kernel (32 KiB, about 25 ms at 10 Mbit/s). Left alone, Linux lets it grow
/// to half a second and more of queue in front of everything written after
/// it. Windows sizes its send buffer to the connection by itself.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub fn limit_unsent(socket: &impl std::os::fd::AsRawFd) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TCP_NOTSENT_LOWAT: libc::c_int = 25;
    #[cfg(target_os = "macos")]
    const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
    let bytes: libc::c_int = 32 * 1024;
    // SAFETY: a valid descriptor and an int option of the stated size
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            (&raw const bytes).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn limit_unsent<T>(_socket: &T) {}
const HEADER: usize = 32;

pub fn begin(key: &Key, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&key.0);
}

/// Returns false and appends nothing if the datagram would not fit
pub fn push(out: &mut Vec<u8>, datagram: &[u8]) -> bool {
    if datagram.len() > u16::MAX as usize || out.len() + 2 + datagram.len() > MAX_FRAME {
        return false;
    }
    out.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    out.extend_from_slice(datagram);
    true
}

pub fn parse(frame: &[u8]) -> Option<(Key, Datagrams<'_>)> {
    if frame.len() < HEADER || frame.len() > MAX_FRAME {
        return None;
    }
    let key = Key(frame[..HEADER].try_into().ok()?);
    Some((key, Datagrams { rest: &frame[HEADER..] }))
}

/// The server's only edit to a frame
pub fn set_key(frame: &mut [u8], key: &Key) {
    frame[..HEADER].copy_from_slice(&key.0);
}

pub struct Datagrams<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Datagrams<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([self.rest[0], self.rest[1]]) as usize;
        let d = self.rest.get(2..2 + len)?;
        self.rest = &self.rest[2 + len..];
        Some(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let mut f = Vec::new();
        begin(&Key([7; 32]), &mut f);
        assert!(push(&mut f, b"hello"));
        assert!(push(&mut f, b""));
        assert!(push(&mut f, &[1; 1300]));
        let (key, d) = parse(&f).unwrap();
        assert_eq!(key, Key([7; 32]));
        let d: Vec<&[u8]> = d.collect();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0], b"hello");
        assert_eq!(d[2].len(), 1300);

        set_key(&mut f, &Key([9; 32]));
        assert_eq!(parse(&f).unwrap().0, Key([9; 32]));
    }

    #[test]
    fn limits_and_truncation() {
        let mut f = Vec::new();
        begin(&Key([0; 32]), &mut f);
        let big = vec![0u8; 1400];
        while push(&mut f, &big) {}
        assert!(f.len() <= MAX_FRAME);
        assert!(parse(&[0; 10]).is_none());
        // A truncated datagram ends iteration instead of reading past the end
        let mut t = vec![0u8; 32];
        t.extend_from_slice(&[0, 50, 1, 2]);
        assert_eq!(parse(&t).unwrap().1.count(), 0);
    }
}
