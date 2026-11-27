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
/// Frames up to this size (a game's or a call's packets, TCP acknowledgements,
/// pings) go ahead of larger ones queued for the same connection
pub const SMALL_FRAME: usize = 512;
/// What TLS on a relay connection holds before the socket takes it (rustls
/// keeps 64 KiB otherwise, about 50 ms at 10 Mbit/s in front of every frame)
pub const TLS_BUFFER: usize = 16 * 1024;

/// Sets up a connection that carries the relay so a download through it
/// does not hold up a game's packets behind it:
/// - BBR where the system has it (Linux): CUBIC fills the slowest link's
///   queue, which on a 10 Mbit/s link added over 100 ms to every packet
/// - at most 32 KiB unsent in the kernel, which otherwise grows to half a
///   second and more on Linux (on Windows, `paced`)
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
pub fn tune(socket: &impl std::os::fd::AsRawFd) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TCP_NOTSENT_LOWAT: libc::c_int = 25;
    #[cfg(target_os = "macos")]
    const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
    let fd = socket.as_raw_fd();
    let bytes: libc::c_int = 32 * 1024;
    // SAFETY: a valid descriptor and options of the stated sizes; a system
    // without BBR refuses it and keeps its own congestion control
    unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, TCP_NOTSENT_LOWAT, (&raw const bytes).cast(), size_of::<libc::c_int>() as libc::socklen_t);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, b"bbr".as_ptr().cast(), 3);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn tune<T>(_socket: &T) {}

/// A relay connection's socket. On Windows, which has no limit on unsent
/// data, the send buffer follows the ideal send backlog (what keeps the path
/// busy) plus 32 KiB instead of growing by itself to seconds of a download.
/// Elsewhere `tune` did it already and this is the socket itself.
#[cfg(not(windows))]
pub fn paced<T>(socket: T) -> T {
    socket
}

#[cfg(windows)]
pub fn paced<T: std::os::windows::io::AsRawSocket>(socket: T) -> Paced<T> {
    let mut p = Paced { raw: socket.as_raw_socket() as usize, inner: socket, sndbuf: 0, checked: std::time::Instant::now() };
    p.refresh();
    p
}

#[cfg(windows)]
pub struct Paced<T> {
    inner: T,
    raw: usize,
    sndbuf: i32,
    checked: std::time::Instant,
}

#[cfg(windows)]
impl<T> Paced<T> {
    const UNSENT: u32 = 32 * 1024;
    const EVERY: std::time::Duration = std::time::Duration::from_millis(100);

    fn refresh(&mut self) {
        use windows_sys::Win32::Networking::WinSock::{SO_SNDBUF, SOL_SOCKET, WSAIoctl, setsockopt};
        // _IOR('t', 123, ULONG)
        const SIO_IDEAL_SEND_BACKLOG_QUERY: u32 = 0x4004_747B;
        self.checked = std::time::Instant::now();
        let (mut isb, mut len) = (0u32, 0u32);
        // SAFETY: the socket lives as long as `inner`; buffers of the stated sizes
        let ok = unsafe {
            WSAIoctl(self.raw, SIO_IDEAL_SEND_BACKLOG_QUERY, std::ptr::null(), 0, (&raw mut isb).cast(), 4, &mut len, std::ptr::null_mut(), None)
        } == 0;
        let want = if ok { isb.saturating_add(Self::UNSENT).min(i32::MAX as u32) as i32 } else { return };
        if want != self.sndbuf {
            // SAFETY: as above, an i32 option
            let set = unsafe { setsockopt(self.raw, SOL_SOCKET, SO_SNDBUF, (&raw const want).cast(), 4) } == 0;
            if set {
                self.sndbuf = want;
            }
        }
    }

    #[cfg(test)]
    fn sndbuf(&self) -> i32 {
        self.sndbuf
    }
}

#[cfg(windows)]
impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Paced<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(windows)]
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Paced<T> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        if self.checked.elapsed() >= Self::EVERY {
            self.refresh();
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(all(test, windows))]
mod paced_tests {
    /// The send buffer follows the backlog Windows reports, plus the limit
    #[tokio::test]
    async fn the_send_buffer_follows_the_ideal_backlog() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
        let mut p = super::paced(client.unwrap());
        assert!(p.sndbuf() >= super::Paced::<()>::UNSENT as i32, "{}", p.sndbuf());
        let (mut server, _) = accepted.unwrap();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0; 1 << 16];
            let mut n = 0;
            while n < 8 << 20 {
                n += server.read(&mut buf).await.unwrap();
            }
        });
        let chunk = vec![7u8; 1 << 16];
        for _ in 0..128 {
            p.write_all(&chunk).await.unwrap();
        }
        reader.await.unwrap();
        assert!(p.sndbuf() >= super::Paced::<()>::UNSENT as i32);
    }
}
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
