//! Files sent between devices (tray: a device's ⋯ menu → Send a file). The
//! sending tray connects to the receiver's mesh address on `PORT` and sends a
//! header line, `{"name":…,"size":…}`. The receiver's daemon knows the sender
//! by its mesh address (the tunnel and access rules let it in), holds the
//! connection and lists the offer in `status`. Its tray asks the user; on
//! accept the daemon answers `ok` and hands the bytes to that tray, which
//! writes them into the user's Downloads. On decline, or after two minutes,
//! it answers `no`. The daemon itself writes nothing to disk.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use retail_proto::api::FileOffer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::Engine;

pub const PORT: u16 = retail_proto::FILE_PORT;
const MAX_HEADER: usize = 4096;
const MAX_OFFERS: usize = 8;
const WAIT: Duration = Duration::from_secs(120);

#[derive(serde::Deserialize)]
struct Header {
    name: String,
    size: u64,
}

#[derive(Default)]
pub struct Files {
    next: AtomicU64,
    pending: Mutex<Vec<Pending>>,
}

struct Pending {
    offer: FileOffer,
    conn: TcpStream,
    at: Instant,
}

impl Files {
    /// Offers waiting for an answer; ones left too long are declined
    pub fn offers(&self) -> Vec<FileOffer> {
        let mut pending = self.pending.lock().unwrap();
        let (old, keep): (Vec<_>, Vec<_>) = pending.drain(..).partition(|p| p.at.elapsed() > WAIT);
        *pending = keep;
        for p in old {
            answer(p.conn, b"no\n");
        }
        pending.iter().map(|p| p.offer.clone()).collect()
    }

    pub fn decline(&self, id: u64) -> bool {
        match self.take(id) {
            Some((_, conn)) => {
                answer(conn, b"no\n");
                true
            }
            None => false,
        }
    }

    /// The offer and its connection, which the caller answers
    pub fn take(&self, id: u64) -> Option<(FileOffer, TcpStream)> {
        let mut pending = self.pending.lock().unwrap();
        let i = pending.iter().position(|p| p.offer.id == id)?;
        let p = pending.remove(i);
        Some((p.offer, p.conn))
    }
}

fn answer(mut conn: TcpStream, word: &'static [u8]) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.write_all(word)).await;
    });
}

/// Until `stop` turns true (the session ends)
pub async fn serve(
    engine: Arc<Engine>,
    files: Arc<Files>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = match TcpListener::bind((engine.self_ip(), PORT)).await {
        Ok(l) => l,
        Err(e) => {
            // Receiving files is not worth restarting the session for
            tracing::warn!("cannot receive files: {e}");
            return Ok(());
        }
    };
    // Windows lets no one in otherwise
    let _inbound = crate::firewall::Inbound::take();
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((conn, from)) = r else { continue };
                let (engine, files) = (engine.clone(), files.clone());
                tokio::spawn(async move {
                    if let Err(e) = offer(&engine, &files, conn, from).await {
                        tracing::debug!(%from, "file offer: {e:#}");
                    }
                });
            }
            _ = stop.wait_for(|s| *s) => return Ok(()),
        }
    }
}

async fn offer(
    engine: &Engine,
    files: &Files,
    mut conn: TcpStream,
    from: SocketAddr,
) -> Result<()> {
    let IpAddr::V4(ip) = from.ip() else {
        bail!("not a mesh address")
    };
    let (_, hostname, _) = engine.find_peer(&ip.to_string())?;
    // The sender waits for the answer before sending data, so this reads the header only
    let mut line = Vec::with_capacity(256);
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut b = [0u8; 1];
        while line.len() < MAX_HEADER {
            if conn.read(&mut b).await? == 0 {
                bail!("closed before the header");
            }
            if b[0] == b'\n' {
                return Ok(());
            }
            line.push(b[0]);
        }
        bail!("header too long")
    })
    .await
    .context("no header")??;
    let header: Header = serde_json::from_slice(&line).context("bad header")?;
    let name = safe_name(&header.name).context("no usable file name")?;
    let mut pending = files.pending.lock().unwrap();
    if pending.len() >= MAX_OFFERS {
        drop(pending);
        answer(conn, b"busy\n");
        return Ok(());
    }
    let id = files.next.fetch_add(1, Ordering::Relaxed) + 1;
    tracing::info!(from = %hostname, %name, size = header.size, "a file is offered");
    let offer = FileOffer {
        id,
        from: hostname,
        name,
        size: header.size,
    };
    pending.push(Pending {
        offer,
        conn,
        at: Instant::now(),
    });
    Ok(())
}

/// A plain file name: no folders, no control characters, nothing Windows
/// refuses, at most 200 characters
pub fn safe_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        .take(200)
        .collect();
    // Hidden or relative names become plain ones
    let clean = clean
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' '])
        .to_string();
    let stem = clean.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    (!clean.is_empty() && !reserved).then_some(clean)
}

/// The accepted offer's bytes, `size` of them, read from the sender
pub fn body(conn: TcpStream, size: u64) -> axum::body::Body {
    let stream = futures_util::stream::unfold((conn, size), |(mut conn, left)| async move {
        if left == 0 {
            return None;
        }
        let mut buf = vec![0u8; (64 * 1024).min(left as usize)];
        match tokio::time::timeout(Duration::from_secs(60), conn.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.truncate(n);
                Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from(buf)),
                    (conn, left - n as u64),
                ))
            }
            _ => Some((Err(std::io::Error::other("the sender stopped")), (conn, 0))),
        }
    });
    axum::body::Body::from_stream(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_plain() {
        assert_eq!(safe_name("photo.jpg").as_deref(), Some("photo.jpg"));
        assert_eq!(safe_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(
            safe_name("C:\\Windows\\evil.exe").as_deref(),
            Some("evil.exe")
        );
        assert_eq!(
            safe_name("a\u{1b}[31mb?.txt").as_deref(),
            Some("a[31mb.txt")
        );
        assert_eq!(safe_name(".bashrc").as_deref(), Some("bashrc"));
        assert_eq!(safe_name("CON.txt"), None);
        assert_eq!(safe_name("com1"), None);
        assert_eq!(safe_name("..."), None);
        assert_eq!(safe_name("report. "), Some("report".into()));
    }
}
