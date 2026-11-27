//! Reaching the server from whatever network the device is on. Every way
//! there is raced, started one after another: each starts when the previous
//! has failed or after its delay, whichever comes first, and the first to
//! finish wins. A working network therefore connects at the speed of plain
//! HTTPS, and a hostile one tries the rest within seconds.
//!
//! Ways, each directly and through every known proxy:
//! 1. HTTPS with the pinned certificate
//! 2. REALITY, when the server offers it
//! 3. A WebSocket tunnel over plain HTTP, HTTPS or a CDN front, for networks
//!    that only let web traffic out or decrypt TLS
//! 4. HTTP polling through the same, for middleboxes that strip `Upgrade`
//!
//! Tunnels carry the pinned TLS inside, so a proxy or CDN that decrypts the
//! outer layer still cannot read or alter the connection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use retail_control::BoxIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::http::{Target, parse_url};
use crate::proxy::{self, Proxy};

/// Each way gets this long, its handshakes included
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(12);
const REALITY_DELAY: Duration = Duration::from_millis(1500);
const TUNNEL_DELAY: Duration = Duration::from_millis(3000);
const POLL_DELAY: Duration = Duration::from_millis(6000);
/// Longer than the server holds a poll
const POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
const PIPE: usize = 64 * 1024;
/// How long a poll request waits for more data after the first bytes
const POLL_GATHER: Duration = Duration::from_millis(2);
/// Bytes per tunnel message: larger ones cost fewer frames and flushes
const TUNNEL_CHUNK: usize = 64 * 1024;

/// A connection to the server's HTTP API with TLS (or REALITY) done
pub struct Dialed {
    pub io: BoxIo,
    /// For status, e.g. "HTTPS" or "WebSocket tunnel via proxy http://p:3128"
    pub via: String,
    /// The server's address when reached directly, where its STUN server is
    pub server_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
enum Carrier {
    Direct,
    Proxy(Proxy),
}

#[derive(Clone, Debug)]
enum Mode {
    /// TLS, or plain HTTP for an `http://` server
    Direct,
    Reality,
    WebSocket(String),
    Poll(String),
}

#[derive(Clone, Debug)]
struct Way {
    carrier: Carrier,
    mode: Mode,
    delay: Duration,
}

impl Way {
    fn label(&self) -> String {
        let what = match &self.mode {
            Mode::Direct => "HTTPS".to_string(),
            Mode::Reality => "REALITY".to_string(),
            Mode::WebSocket(u) => format!("WebSocket tunnel ({u})"),
            Mode::Poll(u) => format!("HTTP polling ({u})"),
        };
        match &self.carrier {
            Carrier::Direct => what,
            Carrier::Proxy(p) => format!("{what} via proxy {}", p.label()),
        }
    }
}

/// The way that last worked per server URL, tried first next time
static LAST: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

pub async fn dial(target: &Target) -> Result<Dialed> {
    dial_reporting(target, |_| {}).await
}

/// `dial`, telling `report` the most telling error so far each time a way
/// fails: the slowest way can take long to give up
pub async fn dial_reporting(target: &Target, report: impl Fn(&anyhow::Error)) -> Result<Dialed> {
    let ways = ways(target, &proxy::current());
    let last = LAST
        .lock()
        .unwrap()
        .iter()
        .find(|(u, _)| *u == target.url)
        .map(|(_, l)| l.clone());
    let mut ways = ways;
    if let Some(last) = last
        && let Some(i) = ways.iter().position(|w| w.label() == last)
    {
        let mut w = ways.remove(i);
        w.delay = Duration::ZERO;
        ways.insert(0, w);
    }
    ways.sort_by_key(|w| w.delay);

    let target = Arc::new(target.clone());
    let failed = Arc::new(tokio::sync::watch::channel(0usize).0);
    let mut set = JoinSet::new();
    for (rank, way) in ways.into_iter().enumerate() {
        let (target, failed) = (target.clone(), failed.clone());
        set.spawn(async move {
            // Start after the delay, or once every way ahead has failed
            let mut rx = failed.subscribe();
            let _ = tokio::time::timeout(way.delay, rx.wait_for(|n| *n >= rank)).await;
            let label = way.label();
            tracing::debug!(via = %label, "trying");
            let r = match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt(&target, &way)).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
            };
            if let Err(e) = &r {
                tracing::debug!(via = %label, "failed: {e:#}");
                failed.send_modify(|n| *n += 1);
            }
            (label, r)
        });
    }
    let mut first_err: Option<anyhow::Error> = None;
    while let Some(done) = set.join_next().await {
        let Ok((label, result)) = done else { continue };
        match result {
            Ok((io, server_addr)) => {
                let mut last = LAST.lock().unwrap();
                last.retain(|(u, _)| *u != target.url);
                last.push((target.url.clone(), label.clone()));
                tracing::debug!(via = %label, "connected to the server");
                // Dropping the set cancels the other attempts
                return Ok(Dialed {
                    io,
                    via: label,
                    server_addr,
                });
            }
            Err(e) => {
                tracing::debug!(via = %label, "{e:#}");
                // The most telling, not the first: that may be an IPv6 or proxy try
                let e = e.context(label);
                let best = match first_err.take() {
                    Some(f) => crate::failure::better(f, e),
                    None => e,
                };
                report(&best);
                first_err = Some(best);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| anyhow!("no way to reach the server")))
}

fn ways(target: &Target, proxies: &[Proxy]) -> Vec<Way> {
    let Ok(url) = parse_url(&target.url) else {
        return Vec::new();
    };
    let carriers: Vec<Carrier> = std::iter::once(Carrier::Direct)
        .chain(proxies.iter().cloned().map(Carrier::Proxy))
        .collect();
    let mut tunnels = Vec::new();
    if url.tls {
        let authority = url.authority_string();
        tunnels.push(format!("http://{authority}"));
        tunnels.push(format!("https://{authority}"));
        if url.port != 80 {
            tunnels.push(format!("http://{}", host_port(url.host, 80)));
        }
        tunnels.extend(
            target
                .fronts
                .iter()
                .map(|f| f.trim_end_matches('/').to_string()),
        );
    }
    let mut out = Vec::new();
    for c in &carriers {
        out.push(Way {
            carrier: c.clone(),
            mode: Mode::Direct,
            delay: Duration::ZERO,
        });
        if url.tls && target.reality.is_some() {
            out.push(Way {
                carrier: c.clone(),
                mode: Mode::Reality,
                delay: REALITY_DELAY,
            });
        }
        for t in &tunnels {
            out.push(Way {
                carrier: c.clone(),
                mode: Mode::WebSocket(t.clone()),
                delay: TUNNEL_DELAY,
            });
        }
        for t in &tunnels {
            out.push(Way {
                carrier: c.clone(),
                mode: Mode::Poll(t.clone()),
                delay: POLL_DELAY,
            });
        }
    }
    out
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The server's other addresses, on `port`
fn alts_on(target: &Target, port: u16) -> Vec<String> {
    target
        .alts
        .iter()
        .filter_map(|a| {
            a.parse::<SocketAddr>()
                .ok()
                .map(|s| SocketAddr::new(s.ip(), port).to_string())
        })
        .collect()
}

/// A byte stream to `host:port`, and the address when direct
async fn carry(
    carrier: &Carrier,
    host: &str,
    port: u16,
    alts: &[String],
) -> Result<(BoxIo, Option<SocketAddr>)> {
    match carrier {
        Carrier::Direct => {
            let tcp = crate::happy::connect_many(host, port, alts).await?;
            tcp.set_nodelay(true)?;
            retail_proto::relay::tune(&tcp);
            let peer = tcp.peer_addr().ok();
            Ok((Box::new(retail_proto::relay::paced(tcp)), peer))
        }
        Carrier::Proxy(p) => Ok((p.connect(host, port).await?, None)),
    }
}

async fn attempt(target: &Target, way: &Way) -> Result<(BoxIo, Option<SocketAddr>)> {
    let url = parse_url(&target.url)?;
    match &way.mode {
        Mode::Direct => {
            let (io, peer) = carry(&way.carrier, url.host, url.port, &target.alts).await?;
            if !url.tls {
                return Ok((io, peer));
            }
            Ok((tls(io, target.tls(), url.host).await?, peer))
        }
        Mode::Reality => {
            let params = target.reality.as_ref().context("no REALITY")?;
            let (io, peer) = carry(&way.carrier, url.host, url.port, &target.alts).await?;
            let stream = crate::reality::connect(io, params)
                .await
                .context("REALITY handshake")?;
            Ok((Box::new(stream), peer))
        }
        Mode::WebSocket(t) => {
            let inner = websocket(target, &way.carrier, t).await?;
            Ok((tls(Box::new(inner), target.tls(), url.host).await?, None))
        }
        Mode::Poll(t) => {
            let inner = poll(target, &way.carrier, t).await?;
            Ok((tls(Box::new(inner), target.tls(), url.host).await?, None))
        }
    }
}

async fn tls(io: BoxIo, config: Arc<rustls::ClientConfig>, host: &str) -> Result<BoxIo> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .context("invalid TLS server name")?;
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, io)
        .await?;
    stream
        .get_mut()
        .1
        .set_buffer_limit(Some(retail_proto::relay::TLS_BUFFER));
    Ok(Box::new(stream))
}

/// The outer connection of a tunnel: to `t`'s host, with TLS that accepts any
/// certificate if `https` (a CDN's, or an inspecting proxy's). The pinned TLS
/// inside authenticates the server.
async fn outer(target: &Target, carrier: &Carrier, t: &str) -> Result<BoxIo> {
    let u = parse_url(t)?;
    let server = parse_url(&target.url)?;
    let alts = if u.host == server.host {
        alts_on(target, u.port)
    } else {
        Vec::new()
    };
    let (io, _) = carry(carrier, u.host, u.port, &alts).await?;
    if u.tls {
        tls(io, any_cert(), u.host).await
    } else {
        Ok(io)
    }
}

async fn websocket(target: &Target, carrier: &Carrier, t: &str) -> Result<DuplexStream> {
    let u = parse_url(t)?;
    let io = outer(target, carrier, t).await?;
    let scheme = if u.tls { "wss" } else { "ws" };
    let req = format!(
        "{scheme}://{}{}/api/v1/tunnel",
        u.authority_string(),
        u.base
    )
    .into_client_request()?;
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .read_buffer_size(TUNNEL_CHUNK)
        .write_buffer_size(0)
        .max_message_size(Some(256 * 1024));
    tracing::debug!(tunnel = t, "outer connection up");
    let (ws, _) = tokio_tungstenite::client_async_with_config(req, io, Some(config))
        .await
        .context("WebSocket upgrade")?;
    tracing::debug!(tunnel = t, "WebSocket up");
    let (ours, theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let (mut tx, mut rx) = ws.split();
        let (mut pipe_rx, mut pipe_tx) = tokio::io::split(ours);
        let down = async {
            while let Some(Ok(msg)) = rx.next().await {
                match msg {
                    Message::Binary(data) => {
                        if pipe_tx.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        };
        let up = async {
            let mut buf = vec![0u8; TUNNEL_CHUNK];
            loop {
                match pipe_rx.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx
                            .send(Message::Binary(buf[..n].to_vec().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = tx.send(Message::Close(None)).await;
        };
        tokio::select! {
            _ = down => {}
            _ = up => {}
        }
    });
    Ok(theirs)
}

/// Requests to a tunnel endpoint over a keep-alive connection, which the
/// caller holds and which is reopened as needed
struct HttpLink {
    target: Target,
    carrier: Carrier,
    url: String,
}

impl HttpLink {
    /// Plain HTTP through an HTTP proxy goes as absolute-form requests, which
    /// proxies pass more readily than `CONNECT` to port 80
    fn forward_proxy(&self) -> Option<&Proxy> {
        match &self.carrier {
            Carrier::Proxy(p)
                if p.kind == proxy::Kind::Http && !self.url.starts_with("https://") =>
            {
                Some(p)
            }
            _ => None,
        }
    }

    async fn open(&self) -> Result<BoxIo> {
        match self.forward_proxy() {
            Some(p) => Ok(Box::new(p.dial().await?)),
            None => outer(&self.target, &self.carrier, &self.url).await,
        }
    }

    async fn request(
        &self,
        conn: &mut Option<BoxIo>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<crate::http1::Response> {
        let u = parse_url(&self.url)?;
        let authority = u.authority_string();
        let forward = self.forward_proxy().cloned();
        let target = match forward {
            Some(_) => format!("http://{authority}{}{path}", u.base),
            None => format!("{}{path}", u.base),
        };
        let make = |auth: Option<&str>| {
            let mut r = format!(
                "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nCache-Control: no-cache\r\n\
                 Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
                body.len()
            );
            if let Some(a) = auth {
                r.push_str(&format!("Proxy-Authorization: {a}\r\n"));
            }
            r.push_str("\r\n");
            let mut r = r.into_bytes();
            r.extend_from_slice(body);
            r
        };
        let mut last = None;
        for _ in 0..2 {
            let io = match conn.take() {
                Some(c) => c,
                None => self.open().await?,
            };
            let sent = async {
                match &forward {
                    Some(p) => p.request(io, make, false).await,
                    None => {
                        let mut io = io;
                        io.write_all(&make(None)).await?;
                        io.flush().await?;
                        crate::http1::read_response(io, false).await
                    }
                }
            };
            match tokio::time::timeout(POLL_REQUEST_TIMEOUT, sent).await {
                Ok(Ok((io, resp))) => {
                    if !resp.close {
                        *conn = Some(io);
                    }
                    return Ok(resp);
                }
                Ok(Err(e)) => last = Some(e),
                Err(_) => last = Some(anyhow!("request timed out")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("request failed")))
    }
}

async fn poll(target: &Target, carrier: &Carrier, t: &str) -> Result<DuplexStream> {
    let link = HttpLink {
        target: target.clone(),
        carrier: carrier.clone(),
        url: t.to_string(),
    };
    let mut down_conn = None;
    let resp = link
        .request(&mut down_conn, "POST", "/api/v1/tunnel/poll", &[])
        .await?;
    if resp.status != 200 {
        bail!("tunnel refused: HTTP {}", resp.status);
    }
    let id = String::from_utf8(resp.body)
        .ok()
        .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    let id = id.context("malformed tunnel id")?;
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let (mut pipe_rx, mut pipe_tx) = tokio::io::split(ours);
    let mut up_conn = None;
    let path = format!("/api/v1/tunnel/poll/{id}");
    let down_path = path.clone();
    tokio::spawn(async move {
        let receive = async {
            let mut n = 0u64;
            let mut errors = 0;
            loop {
                n += 1;
                match link
                    .request(&mut down_conn, "GET", &format!("{down_path}?n={n}"), &[])
                    .await
                {
                    Ok(r) if r.status == 200 => {
                        errors = 0;
                        if pipe_tx.write_all(&r.body).await.is_err() {
                            return;
                        }
                    }
                    Ok(r) if r.status == 404 || r.status == 410 => return,
                    Ok(_) | Err(_) => {
                        errors += 1;
                        if errors > 3 {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        };
        let send = async {
            let mut buf = vec![0u8; PIPE];
            loop {
                let mut n = match pipe_rx.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                // Every request costs a round trip, so send fuller ones
                let until = tokio::time::Instant::now() + POLL_GATHER;
                while n < buf.len() {
                    match tokio::time::timeout_at(until, pipe_rx.read(&mut buf[n..])).await {
                        Ok(Ok(m)) if m > 0 => n += m,
                        _ => break,
                    }
                }
                match link.request(&mut up_conn, "POST", &path, &buf[..n]).await {
                    Ok(r) if r.status == 200 => {}
                    _ => return,
                }
            }
        };
        tokio::select! {
            _ = receive => {}
            _ = send => {}
        }
    });
    Ok(theirs)
}

/// For the outer layer of tunnels only
fn any_cert() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
            let mut c = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
                .with_no_client_auth();
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(c)
        })
        .clone()
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every way to a real server, each checked with a request over it
    #[tokio::test]
    async fn every_way_reaches_the_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("retail-transport-{}", std::process::id()));
        let server = retail_control::Server::start(retail_control::Config {
            data_dir: dir.clone(),
            listen: "127.0.0.1:0".parse().unwrap(),
            extra_listen: Vec::new(),
            stun_listen: "127.0.0.1:0".parse().unwrap(),
            stun_advertise: vec![],
            tls: retail_control::Tls::SelfSigned,
            reality: None,
        })
        .await
        .unwrap();
        let base = format!("127.0.0.1:{}", server.port());
        let target = Target {
            url: format!("https://{base}"),
            pin: server.pin(),
            ..Default::default()
        };
        let modes = [
            Mode::Direct,
            Mode::WebSocket(format!("http://{base}")),
            Mode::WebSocket(format!("https://{base}")),
            Mode::Poll(format!("http://{base}")),
            Mode::Poll(format!("https://{base}")),
        ];
        for mode in modes {
            let way = Way {
                carrier: Carrier::Direct,
                mode,
                delay: Duration::ZERO,
            };
            let (mut io, _) = attempt(&target, &way)
                .await
                .unwrap_or_else(|e| panic!("{}: {e:#}", way.label()));
            io.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), io.read_to_end(&mut resp))
                .await
                .unwrap()
                .unwrap();
            let text = String::from_utf8_lossy(&resp);
            assert!(
                text.starts_with("HTTP/1.1 200") && text.ends_with("ok"),
                "{}: {text}",
                way.label()
            );
        }
        // Plain HTTP reaches only the tunnel endpoints
        let mut plain = tokio::net::TcpStream::connect(&base).await.unwrap();
        plain.write_all(b"POST /api/v1/register HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        let mut resp = Vec::new();
        plain.read_to_end(&mut resp).await.unwrap();
        assert!(
            String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 403"),
            "{}",
            String::from_utf8_lossy(&resp)
        );
        // And a pin mismatch inside a tunnel fails
        let wrong = Target {
            pin: Some([9; 32]),
            ..target.clone()
        };
        let way = Way {
            carrier: Carrier::Direct,
            mode: Mode::WebSocket(format!("http://{base}")),
            delay: Duration::ZERO,
        };
        assert!(attempt(&wrong, &way).await.is_err());
        server.stop().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
