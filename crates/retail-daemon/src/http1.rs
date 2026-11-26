//! Reads one HTTP/1.1 response and leaves the connection usable for the next
//! request or, after `CONNECT`, for the tunnel

use anyhow::{Context, Result, bail};
use retail_control::{BoxIo, Prefixed};
use tokio::io::AsyncReadExt;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1 << 20;
/// A chunk-size or trailer line
const MAX_LINE: usize = 4096;

#[derive(Debug, Default)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The server closes the connection after this response
    pub close: bool,
}

impl Response {
    pub fn headers_named(&self, name: &str) -> Vec<String> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).collect()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// With `tunnel`, a 2xx answer (to `CONNECT`) has no body and the rest of the
/// stream belongs to the tunnel
pub async fn read_response(mut io: BoxIo, tunnel: bool) -> Result<(BoxIo, Response)> {
    let mut buf = Vec::with_capacity(1024);
    let split = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            bail!("HTTP response header too large");
        }
        let mut chunk = [0u8; 2048];
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before a response");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..split]).context("non-UTF-8 HTTP headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut words = status_line.split_whitespace();
    let version = words.next().unwrap_or_default();
    let status: u16 = words.next().and_then(|s| s.parse().ok()).context("malformed HTTP status line")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut resp = Response { status, headers, ..Default::default() };
    let connection = resp.header("connection").or(resp.header("proxy-connection")).unwrap_or("").to_ascii_lowercase();
    resp.close = connection.contains("close") || (version == "HTTP/1.0" && !connection.contains("keep-alive"));
    let mut rest = buf.split_off(split + 4);

    let no_body = (tunnel && (200..300).contains(&status)) || status / 100 == 1 || status == 204 || status == 304;
    if !no_body {
        let chunked = resp.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = resp.header("content-length").and_then(|v| v.parse::<usize>().ok());
        if chunked {
            let (body, left) = read_chunked(&mut io, rest).await?;
            resp.body = body;
            rest = left;
        } else if let Some(n) = length {
            if n > MAX_BODY {
                bail!("HTTP response too large");
            }
            while rest.len() < n {
                let mut chunk = vec![0u8; (n - rest.len()).min(64 * 1024)];
                let got = io.read(&mut chunk).await?;
                if got == 0 {
                    bail!("truncated HTTP body");
                }
                rest.extend_from_slice(&chunk[..got]);
            }
            let left = rest.split_off(n);
            resp.body = rest;
            rest = left;
        } else {
            // Delimited by the end of the connection
            (&mut io).take(MAX_BODY as u64).read_to_end(&mut rest).await?;
            resp.body = std::mem::take(&mut rest);
            resp.close = true;
        }
    }
    let io: BoxIo = if rest.is_empty() { io } else { Box::new(Prefixed::new(rest, io)) };
    Ok((io, resp))
}

async fn read_chunked(io: &mut BoxIo, mut data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut body = Vec::new();
    let fill = async |data: &mut Vec<u8>, io: &mut BoxIo| -> Result<()> {
        let mut chunk = [0u8; 8192];
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            bail!("truncated chunked body");
        }
        data.extend_from_slice(&chunk[..n]);
        Ok(())
    };
    // Finds the end of a line, scanning only new bytes and refusing an endless one
    let line = async |data: &mut Vec<u8>, io: &mut BoxIo| -> Result<usize> {
        let mut from = 0;
        loop {
            if let Some(i) = data[from..].windows(2).position(|w| w == b"\r\n") {
                return Ok(from + i);
            }
            if data.len() > MAX_LINE {
                bail!("HTTP chunk line too long");
            }
            from = data.len().saturating_sub(1);
            fill(data, io).await?;
        }
    };
    let mut trailers = 0;
    loop {
        let eol = line(&mut data, io).await?;
        let size_str = std::str::from_utf8(&data[..eol])?.split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_str, 16).context("malformed chunk size")?;
        data.drain(..eol + 2);
        if size == 0 {
            // Trailers end with an empty line
            loop {
                let i = line(&mut data, io).await?;
                data.drain(..i + 2);
                if i == 0 {
                    return Ok((body, data));
                }
                trailers += i + 2;
                if trailers > MAX_HEAD {
                    bail!("HTTP trailers too long");
                }
            }
        }
        // Checked one at a time: a size near usize::MAX must not wrap the sum
        if size > MAX_BODY - body.len() {
            bail!("HTTP response too large");
        }
        while data.len() < size + 2 {
            fill(&mut data, io).await?;
        }
        body.extend_from_slice(&data[..size]);
        data.drain(..size + 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn feed(bytes: &'static [u8]) -> BoxIo {
        let (a, mut b) = tokio::io::duplex(4096);
        b.write_all(bytes).await.unwrap();
        drop(b);
        Box::new(a)
    }

    #[tokio::test]
    async fn keep_alive_and_chunked() {
        let io = feed(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 407 X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nde\r\n0\r\n\r\n").await;
        let (io, r) = read_response(io, false).await.unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.close), (200, &b"abc"[..], false));
        let (_, r) = read_response(io, false).await.unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.close), (407, &b"de"[..], true));
    }

    #[tokio::test]
    async fn connect_leaves_the_tunnel() {
        let io = feed(b"HTTP/1.1 200 Connection established\r\n\r\nTLS").await;
        let (mut io, r) = read_response(io, true).await.unwrap();
        assert_eq!(r.status, 200);
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"TLS");
    }

    #[tokio::test]
    async fn hostile_chunks_fail_cleanly() {
        let huge = feed(b"HTTP/1.1 407 X\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nffffffffffffffff\r\nxxxx").await;
        assert!(read_response(huge, true).await.is_err());

        // A size line that never ends
        let (a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = b.write_all(b"HTTP/1.1 407 X\r\nTransfer-Encoding: chunked\r\n\r\n").await;
            let _ = b.write_all(&[b'1'; 64 * 1024]).await;
        });
        let err = read_response(Box::new(a), true).await.err().unwrap();
        assert!(err.to_string().contains("too long"), "{err}");
    }
}
