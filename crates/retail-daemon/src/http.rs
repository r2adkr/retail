//! Minimal HTTP/1.1 client for `POST /api/v1/register`, the one request made
//! outside the WebSocket. A full client stack (reqwest/hyper) would cost
//! megabytes of resident memory for a call made once per login.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE: usize = 1 << 20;

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Target {
    pub url: String,
    /// SHA-256 of the server's SPKI, trusted instead of certificate authorities
    /// for device-hosted servers joined by invite
    pub pin: Option<[u8; 32]>,
    /// More `host:port` addresses of the same server, raced with the URL's host
    /// for LANs where the router does not hairpin
    pub alts: Vec<String>,
    pub reality: Option<crate::reality::Params>,
    /// CDN URLs in front of the server, for tunnels
    pub fronts: Vec<String>,
}

impl Target {
    pub fn url(url: impl Into<String>) -> Self {
        Target {
            url: url.into(),
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub async fn connect(&self) -> Result<tokio::net::TcpStream> {
        let u = parse_url(&self.url)?;
        let tcp = crate::happy::connect_many(u.host, u.port, &self.alts)
            .await
            .with_context(|| format!("connecting to {}", self.url))?;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    pub fn tls(&self) -> Arc<rustls::ClientConfig> {
        match self.pin {
            Some(pin) => pinned_config(pin),
            None => tls_config(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct Url<'a> {
    pub tls: bool,
    pub host: &'a str,
    pub port: u16,
    authority: &'a str,
    pub base: &'a str,
}

impl Url<'_> {
    pub fn authority_string(&self) -> String {
        self.authority.to_string()
    }
}

pub(crate) fn parse_url(url: &str) -> Result<Url<'_>> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("URL must start with http:// or https://");
    };
    let (authority, base) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').context("unterminated IPv6 address")?;
        (h, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().context("invalid port")?,
        None if tls => 443,
        None => 80,
    };
    if host.is_empty() {
        bail!("URL has no host");
    }
    Ok(Url {
        tls,
        host,
        port,
        authority,
        base: base.trim_end_matches('/'),
    })
}

/// Trusts the public web roots plus the PEM certificates in `RETAIL_CA_FILE`,
/// for servers behind a private CA
pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = std::env::var_os("RETAIL_CA_FILE") {
                use rustls::pki_types::CertificateDer;
                use rustls::pki_types::pem::PemObject;
                match CertificateDer::pem_file_iter(&path) {
                    Ok(certs) => {
                        let (added, ignored) = roots.add_parsable_certificates(certs.flatten());
                        tracing::info!(file = ?path, added, ignored, "extra CA certificates loaded");
                    }
                    Err(e) => tracing::warn!(file = ?path, "reading RETAIL_CA_FILE: {e}"),
                }
            }
            Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
        })
        .clone()
}

fn pinned_config(pin: [u8; 32]) -> Arc<rustls::ClientConfig> {
    static CONFIGS: Mutex<Vec<([u8; 32], Arc<rustls::ClientConfig>)>> = Mutex::new(Vec::new());
    let mut configs = CONFIGS.lock().unwrap();
    if let Some((_, c)) = configs.iter().find(|(p, _)| *p == pin) {
        return c.clone();
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedKey { pin, provider }))
        .with_no_client_auth();
    let config = Arc::new(config);
    configs.push((pin, config.clone()));
    config
}

/// Accepts only the pinned public key, with no fallback to certificate
/// authorities. Handshake signatures are still verified, so presenting the
/// pinned certificate without its private key fails.
#[derive(Debug)]
struct PinnedKey {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

pub(crate) fn spki_sha256(cert: &rustls::pki_types::CertificateDer<'_>) -> Option<[u8; 32]> {
    let cert = webpki::EndEntityCert::try_from(cert).ok()?;
    let spki = cert.subject_public_key_info();
    ring::digest::digest(&ring::digest::SHA256, spki.as_ref())
        .as_ref()
        .try_into()
        .ok()
}

impl rustls::client::danger::ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match spki_sha256(end_entity) {
            // The pin is public (invite codes carry it), so no constant-time comparison
            Some(hash) if hash == self.pin => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Some(_) => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )),
            None => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            )),
        }
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Over whichever way reaches the server (see [`crate::transport`])
pub async fn post_json(target: &Target, path: &str, body: &[u8]) -> Result<Response> {
    let url = parse_url(&target.url)?;
    let request = format!(
        "POST {}{path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: retaild/{}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        url.base,
        url.authority,
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    let exchanged = async {
        let dialed = crate::transport::dial(target).await?;
        exchange(dialed.io, request.as_bytes(), body).await
    };
    tokio::time::timeout(TIMEOUT, exchanged)
        .await
        .context("request timed out")?
}
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    head: &[u8],
    body: &[u8],
) -> Result<Response> {
    s.write_all(head).await?;
    s.write_all(body).await?;
    s.flush().await?;
    let mut raw = Vec::new();
    (&mut s)
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut raw)
        .await?;
    if raw.len() > MAX_RESPONSE {
        bail!("response too large");
    }
    parse_response(&raw)
}

pub(crate) fn parse_response(raw: &[u8]) -> Result<Response> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    let head = std::str::from_utf8(&raw[..split]).context("non-UTF-8 HTTP headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed HTTP status line")?;
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked") {
            chunked = true;
        } else if k.eq_ignore_ascii_case("content-length") {
            length = v.parse::<usize>().ok();
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(n) = length {
        rest.get(..n).context("truncated HTTP body")?.to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response { status, body })
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("malformed chunk")?;
        let size_str = std::str::from_utf8(&data[..eol])?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16).context("malformed chunk size")?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(data.get(..size).context("truncated chunk")?);
        data = data.get(size + 2..).context("truncated chunk")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://vpn.example.com").unwrap();
        assert_eq!(
            (u.tls, u.host, u.port, u.authority, u.base),
            (true, "vpn.example.com", 443, "vpn.example.com", "")
        );
        let u = parse_url("http://10.0.0.1:8080/retail/").unwrap();
        assert_eq!(
            (u.tls, u.host, u.port, u.base),
            (false, "10.0.0.1", 8080, "/retail")
        );
        let u = parse_url("http://[2001:db8::1]:9000").unwrap();
        assert_eq!(
            (u.host, u.port, u.authority),
            ("2001:db8::1", 9000, "[2001:db8::1]:9000")
        );
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("http://:80").is_err());
    }

    #[tokio::test]
    async fn pinned_tls_accepts_only_the_pinned_key() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let make = || {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = rcgen::CertificateParams::new(vec!["retail".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            (
                cert.der().clone(),
                rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
        };
        let (good_cert, good_key) = make();
        let (other_cert, other_key) = make();
        let pin = spki_sha256(&good_cert).unwrap();

        #[derive(Debug)]
        struct Fixed(Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for Fixed {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }

        async fn attempt(
            cert: rustls::pki_types::CertificateDer<'static>,
            key: rustls::pki_types::PrivateKeyDer<'static>,
            pin: [u8; 32],
        ) -> bool {
            // Not `with_single_cert`, which refuses a key that does not match the
            // certificate, the case under test
            let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
            let signing = provider.key_provider.load_private_key(key).unwrap();
            let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert], signing));
            let server = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(Fixed(certified)));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                if let Ok((tcp, _)) = listener.accept().await {
                    let _ = tokio_rustls::TlsAcceptor::from(Arc::new(server))
                        .accept(tcp)
                        .await;
                }
            });
            let target = Target {
                url: format!("https://{addr}"),
                pin: Some(pin),
                ..Default::default()
            };
            let tcp = target.connect().await.unwrap();
            let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
            tokio_rustls::TlsConnector::from(target.tls())
                .connect(name.to_owned(), tcp)
                .await
                .is_ok()
        }
        assert!(
            attempt(good_cert.clone(), good_key.clone_key(), pin).await,
            "pinned key accepted"
        );
        assert!(
            !attempt(other_cert, other_key, pin).await,
            "another key rejected"
        );
        // The pinned certificate without its private key fails CertificateVerify
        let (_, wrong_key) = make();
        assert!(
            !attempt(good_cert, wrong_key, pin).await,
            "bad handshake signature rejected"
        );
    }

    #[test]
    fn responses() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        let r = parse_response(b"HTTP/1.1 401 Unauthorized\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (401, &b"abcde"[..]));
        assert!(parse_response(b"garbage").is_err());
    }
}
