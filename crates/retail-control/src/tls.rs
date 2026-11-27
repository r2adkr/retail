use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Creates the certificate on first use. Also returns the SHA-256 of its
/// SPKI, which clients pin.
pub fn self_signed(dir: &Path) -> Result<(Arc<ServerConfig>, [u8; 32])> {
    use sha2::{Digest, Sha256};
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    if !cert_path.exists() || !key_path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = rcgen::CertificateParams::new(vec!["retail".to_string()])?;
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let cert = params.self_signed(&key)?;
        write_private(&key_path, key.serialize_pem().as_bytes())?;
        std::fs::write(&cert_path, cert.pem())
            .with_context(|| format!("writing {}", cert_path.display()))?;
        tracing::info!("created the server certificate in {}", dir.display());
    }
    let pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let key = rcgen::KeyPair::from_pem(&pem)?;
    let pin: [u8; 32] = Sha256::digest(key.public_key_der()).into();
    let resolver = Arc::new(StaticResolver(load_key(&cert_path, &key_path)?));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), pin))
}

/// Owner-only on Unix. On Windows the data directory's ACL protects it.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .and_then(|mut f| f.write_all(data))
        .with_context(|| format!("writing {}", path.display()))
}

#[derive(Debug)]
struct StaticResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn load_key(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {}", cert.display()))?;
    if chain.is_empty() {
        bail!("{} contains no certificates", cert.display());
    }
    let key =
        PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading {}", key.display()))?;
    let provider = rustls::crypto::CryptoProvider::get_default()
        .context("no TLS crypto provider installed")?;
    let signing = provider
        .key_provider
        .load_private_key(key)
        .context("unsupported private key")?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

/// Any byte stream a connection can arrive on: TCP, or one carried inside a
/// tunnel or forwarded by a helper node
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}
pub type BoxIo = Box<dyn Io>;

/// Hands the listener a connection that did not arrive on its sockets, with
/// the client address it stands for
pub type Injector = mpsc::Sender<(BoxIo, SocketAddr)>;

/// A connection's handshake; `None` when it went to the camouflage site or
/// was dropped
type Handshake = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Conn>>> + Send>>;

/// Concurrent unauthenticated connections spliced to the camouflage site
const MAX_CAMOUFLAGE: usize = 64;
const MAX_HELLO: usize = 16 * 1024;

/// TLS, or plain HTTP, which the router limits to the tunnel endpoints.
/// Proxies that inspect TLS often refuse self-signed servers but pass plain
/// HTTP, and the tunnel carries the pinned TLS inside.
pub enum Conn {
    Tls(Box<TlsStream<Prefixed>>),
    Plain(Prefixed),
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Handshakes run in their own tasks with a timeout, so a slow or stalled
/// client cannot hold up other connections.
pub struct TlsListener {
    rx: mpsc::Receiver<(Conn, ConnInfo)>,
    local: ConnInfo,
    inject: Injector,
    /// Own the TCP sockets, so aborting them on drop frees the ports
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl TlsListener {
    /// The first socket's address is the one reported as local
    pub fn new(
        listeners: Vec<TcpListener>,
        config: Arc<ServerConfig>,
        reality: Option<Arc<crate::reality::ServerConfig>>,
    ) -> Result<Self> {
        let local = listeners
            .first()
            .context("no listening socket")?
            .local_addr()?;
        let acceptor = TlsAcceptor::from(config);
        let replay = Arc::new(crate::reality::ReplayGuard::default());
        let camouflage = Arc::new(tokio::sync::Semaphore::new(MAX_CAMOUFLAGE));
        let (raw_tx, mut raw_rx) = mpsc::channel::<(BoxIo, SocketAddr)>(64);
        let (tx, rx) = mpsc::channel(64);
        let mut tasks = Vec::new();
        for tcp in listeners {
            let raw_tx = raw_tx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match tcp.accept().await {
                        Ok((stream, peer)) => {
                            let _ = stream.set_nodelay(true);
                            retail_proto::relay::tune(&stream);
                            if raw_tx
                                .send((Box::new(retail_proto::relay::paced(stream)), peer))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("accept: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }));
        }
        tasks.push(tokio::spawn(async move {
            while let Some((stream, peer)) = raw_rx.recv().await {
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                let (reality, replay, camouflage) =
                    (reality.clone(), replay.clone(), camouflage.clone());
                tokio::spawn(async move {
                    let handshake = async move {
                        let mut stream = stream;
                        let (prefix, hello) = read_client_hello(&mut stream).await?;
                        let io = Prefixed {
                            prefix,
                            at: 0,
                            inner: stream,
                        };
                        let Some(hello) = hello else {
                            return Ok(looks_like_http(&io.prefix).then_some(Conn::Plain(io)));
                        };
                        let decision = match &reality {
                            Some(cfg) => crate::reality::decide(cfg, &replay, &hello, peer.ip()),
                            None => crate::reality::Decision::Normal,
                        };
                        match decision {
                            crate::reality::Decision::Normal => Ok(Some(Conn::Tls(Box::new(
                                small_buffer(acceptor.accept(io).await?),
                            )))),
                            crate::reality::Decision::Reality { auth } => {
                                let config = reality_tls_config(&auth)?;
                                Ok(Some(Conn::Tls(Box::new(small_buffer(
                                    TlsAcceptor::from(config).accept(io).await?,
                                )))))
                            }
                            crate::reality::Decision::Camouflage => {
                                let dest =
                                    reality.as_ref().map(|r| r.dest.clone()).unwrap_or_default();
                                if let Ok(permit) = camouflage.try_acquire_owned() {
                                    tokio::spawn(async move {
                                        splice(io, &dest).await;
                                        drop(permit);
                                    });
                                }
                                Ok(None)
                            }
                        }
                    };
                    let handshake: Handshake = Box::pin(handshake);
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
                        Ok(Ok(Some(conn))) => {
                            let secure = matches!(conn, Conn::Tls(_));
                            let _ = tx
                                .send((
                                    conn,
                                    ConnInfo {
                                        addr: canonical(peer),
                                        secure,
                                    },
                                ))
                                .await;
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => tracing::debug!(%peer, "handshake failed: {e:#}"),
                        Err(_) => tracing::debug!(%peer, "handshake timed out"),
                    }
                });
            }
        }));
        Ok(TlsListener {
            rx,
            local: ConnInfo {
                addr: local,
                secure: true,
            },
            inject: raw_tx,
            tasks,
        })
    }

    pub fn injector(&self) -> Injector {
        self.inject.clone()
    }
}

/// An HTTP/1 request line starts with an upper-case method
fn looks_like_http(prefix: &[u8]) -> bool {
    prefix.len() >= 4
        && prefix[..4]
            .iter()
            .all(|b| b.is_ascii_uppercase() || *b == b' ')
}

/// Reads raw TLS records up to the end of the first handshake message, before
/// rustls sees the connection, so REALITY can still hand it to the camouflage
/// site untouched. Returns the bytes read, to replay, and the message if the
/// first record is a handshake.
pub(crate) async fn read_client_hello<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let mut raw = Vec::with_capacity(2048);
    let mut msg = Vec::new();
    loop {
        let start = raw.len();
        raw.resize(start + 5, 0);
        stream.read_exact(&mut raw[start..]).await?;
        if raw[start] != 22 {
            return Ok((raw, None)); // Not a handshake: plain HTTP or garbage
        }
        let len = u16::from_be_bytes([raw[start + 3], raw[start + 4]]) as usize;
        if raw.len() + len > MAX_HELLO {
            bail!("ClientHello too large");
        }
        let body = raw.len();
        raw.resize(body + len, 0);
        stream.read_exact(&mut raw[body..]).await?;
        msg.extend_from_slice(&raw[body..]);
        if msg.len() >= 4 {
            let need = 4 + ((msg[1] as usize) << 16 | (msg[2] as usize) << 8 | msg[3] as usize);
            if msg.len() >= need {
                msg.truncate(need);
                return Ok((raw, Some(msg)));
            }
        }
    }
}
/// A throwaway Ed25519 certificate whose signature is replaced by
/// HMAC-SHA512(auth key, public key), which is what the REALITY client checks.
/// Limited to TLS 1.3, AES-128-GCM and X25519, all the client speaks.
fn reality_tls_config(auth: &[u8; 32]) -> Result<Arc<ServerConfig>> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(Vec::<String>::new())?.self_signed(&key)?;
    let mut der = cert.der().to_vec();
    let mac = crate::reality::cert_hmac(auth, key.public_key_raw());
    let n = der.len();
    // An Ed25519 signature is the certificate's last 64 bytes
    der[n - 64..].copy_from_slice(&mac);
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der)],
            PrivateKeyDer::try_from(key.serialize_der()).map_err(anyhow::Error::msg)?,
        )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Hands a probe to the real website, ClientHello included
async fn splice(mut io: Prefixed, dest: &str) {
    let Ok(Ok(mut upstream)) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(dest)).await
    else {
        return;
    };
    let prefix = std::mem::take(&mut io.prefix);
    if upstream.write_all(&prefix).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut io.inner, &mut upstream).await;
}

/// Replays bytes already read before reading the stream
pub struct Prefixed {
    prefix: Vec<u8>,
    at: usize,
    inner: BoxIo,
}

impl Prefixed {
    pub fn new(prefix: Vec<u8>, inner: BoxIo) -> Self {
        Prefixed {
            prefix,
            at: 0,
            inner,
        }
    }
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.prefix[at..at + n]);
            self.at += n;
            if self.at == self.prefix.len() {
                self.prefix = Vec::new();
                self.at = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = Conn;
    type Addr = ConnInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The accept task never ends while the listener lives
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Canonical client address, and whether the connection is encrypted
#[derive(Clone, Copy, Debug)]
pub struct ConnInfo {
    pub addr: SocketAddr,
    pub secure: bool,
}

/// Client address for registration throttling, and whether the connection
/// may use more than the tunnel endpoints
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr, pub bool);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        let info = stream.remote_addr();
        PeerAddr(info.addr, info.secure)
    }
}

/// Test servers without TLS allow everything
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TcpListener>>
    for PeerAddr
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TcpListener>) -> Self {
        PeerAddr(canonical(*stream.remote_addr()), true)
    }
}
/// IPv4 clients of a dual-stack listener appear as ::ffff:a.b.c.d
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Relay frames wait in the socket, not in TLS (`relay::TLS_BUFFER`)
pub fn small_buffer<IO>(
    mut s: tokio_rustls::server::TlsStream<IO>,
) -> tokio_rustls::server::TlsStream<IO> {
    s.get_mut()
        .1
        .set_buffer_limit(Some(retail_proto::relay::TLS_BUFFER));
    s
}
