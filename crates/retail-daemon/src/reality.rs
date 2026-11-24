//! REALITY client (scheme in `retail_control::reality`) for when plain HTTPS
//! to the control server does not get through.
//!
//! A TLS 1.3 client of its own because the scheme needs control over the
//! ClientHello session id and key share, which rustls does not offer. It speaks
//! only what the REALITY server answers with: TLS 1.3, TLS_AES_128_GCM_SHA256,
//! X25519 and an Ed25519 certificate checked against the auth key rather than
//! a certificate authority.

use anyhow::{Context, Result, bail, ensure};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::RngCore;
use retail_control::reality as shared;
use ring::{aead, digest, hkdf, hmac, signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use retail_control::BoxIo;

type OwnedReadHalf = tokio::io::ReadHalf<BoxIo>;
type OwnedWriteHalf = tokio::io::WriteHalf<BoxIo>;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const MAX_RECORD: usize = 16384;
/// DER of an Ed25519 SubjectPublicKeyInfo up to the 32-byte key
const ED25519_SPKI: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[derive(Clone, Debug, PartialEq)]
pub struct Params {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    /// The camouflage website's name, sent as SNI
    pub server_name: String,
}

impl Params {
    pub fn from_invite(r: &retail_proto::invite::RealityInvite) -> Option<Self> {
        Some(Params {
            public_key: retail_proto::invite::decode_pin(&r.public_key)?,
            short_id: crate::host::unhex(&r.short_id)?,
            server_name: r.server_name.clone(),
        })
    }
}

/// Returns a stream carrying the plaintext
pub async fn connect(io: BoxIo, p: &Params) -> Result<DuplexStream> {
    let (rd, mut wr) = tokio::io::split(io);
    let mut records = Records { rd, buf: Vec::new() };

    // The session id is sealed with the zeroed-id hello as AAD, then written into it
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let share = PublicKey::from(&eph).to_bytes();
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let (mut hello, sid_at) = client_hello(&random, &share, &p.server_name);
    let auth = shared::auth_key(eph.diffie_hellman(&PublicKey::from(p.public_key)).as_bytes(), &random);
    let plain = shared::session_plaintext(shared::now_secs(), p.short_id);
    let sid = shared::seal_session_id(&auth, &random, &hello, &plain);
    hello[sid_at..sid_at + 32].copy_from_slice(&sid);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    wr.write_all(&record).await?;
    let mut transcript = digest::Context::new(&digest::SHA256);
    transcript.update(&hello);

    let (kind, sh) = records.next().await?;
    ensure!(kind == 22, "the server did not answer with a handshake (record type {kind})");
    let server_share = parse_server_hello(&sh)?;
    transcript.update(&sh);
    let ecdhe = eph.diffie_hellman(&PublicKey::from(server_share));

    let zeros = [0u8; 32];
    let empty_hash = digest::digest(&digest::SHA256, b"");
    let early = extract(&zeros, &zeros);
    let derived = expand_label(&early, "derived", empty_hash.as_ref());
    let hs = extract(&derived, ecdhe.as_bytes());
    let th = transcript.clone().finish();
    let c_hs = expand_label(&hs, "c hs traffic", th.as_ref());
    let s_hs = expand_label(&hs, "s hs traffic", th.as_ref());
    let master = extract(&expand_label(&hs, "derived", empty_hash.as_ref()), &zeros);
    let mut server_keys = Keys::new(&s_hs);

    let mut msgs = Vec::new();
    let mut cert_key: Option<[u8; 32]> = None;
    loop {
        while let Some(len) = whole_message(&msgs) {
            let msg: Vec<u8> = msgs.drain(..len).collect();
            match msg[0] {
                8 => transcript.update(&msg), // EncryptedExtensions
                11 => {
                    cert_key = Some(check_certificate(&msg, &auth)?);
                    transcript.update(&msg);
                }
                15 => {
                    let key = cert_key.context("CertificateVerify before Certificate")?;
                    verify_certificate_verify(&msg, &key, transcript.clone().finish().as_ref())?;
                    transcript.update(&msg);
                }
                20 => {
                    let expected = finished(&s_hs, transcript.clone().finish().as_ref());
                    ensure!(msg.len() == 36 && msg[4..] == expected[..], "server Finished does not verify");
                    transcript.update(&msg);
                    return finish(records, wr, server_keys, &c_hs, &master, transcript).await;
                }
                t => bail!("unexpected handshake message {t}"),
            }
        }
        let (kind, payload) = records.next().await?;
        match kind {
            20 => continue, // ChangeCipherSpec (middlebox compatibility)
            23 => {
                let (inner, data) = server_keys.open(&payload)?;
                ensure!(inner == 22, "expected handshake data, got content type {inner}");
                msgs.extend_from_slice(&data);
            }
            21 => bail!("the server refused the handshake"),
            t => bail!("unexpected record type {t}"),
        }
    }
}

/// Sends the client Finished and starts moving application data
async fn finish(
    records: Records,
    mut wr: OwnedWriteHalf,
    _handshake_keys: Keys,
    c_hs: &[u8; 32],
    master: &[u8; 32],
    transcript: digest::Context,
) -> Result<DuplexStream> {
    let th = transcript.clone().finish();
    let c_ap = expand_label(master, "c ap traffic", th.as_ref());
    let s_ap = expand_label(master, "s ap traffic", th.as_ref());
    let verify = finished(c_hs, th.as_ref());
    let mut msg = vec![20, 0, 0, 32];
    msg.extend_from_slice(&verify);
    let mut client_hs = Keys::new(c_hs);
    let mut out = vec![20, 3, 3, 0, 1, 1]; // ChangeCipherSpec, as browsers send
    client_hs.seal(22, &msg, &mut out);
    wr.write_all(&out).await?;

    let (app, pump) = tokio::io::duplex(64 * 1024);
    let (mut from_app, mut to_app) = tokio::io::split(pump);
    let mut server = Keys::new(&s_ap);
    let mut client = Keys::new(&c_ap);
    let mut records = records;
    tokio::spawn(async move {
        let down = async {
            loop {
                let (kind, payload) = records.next().await?;
                match kind {
                    23 => {
                        let (inner, data) = server.open(&payload)?;
                        match inner {
                            23 => to_app.write_all(&data).await?,
                            22 => {} // NewSessionTicket and the like
                            _ => return anyhow::Ok(()), // Alert, so closed
                        }
                    }
                    20 => {}
                    _ => return Ok(()),
                }
            }
        };
        let up = async {
            let mut buf = vec![0u8; MAX_RECORD];
            let mut out = Vec::with_capacity(MAX_RECORD + 64);
            loop {
                let n = from_app.read(&mut buf).await?;
                if n == 0 {
                    return anyhow::Ok(());
                }
                out.clear();
                client.seal(23, &buf[..n], &mut out);
                wr.write_all(&out).await?;
            }
        };
        tokio::select! {
            r = down => if let Err(e) = r { tracing::debug!("REALITY read: {e:#}") },
            r = up => if let Err(e) = r { tracing::debug!("REALITY write: {e:#}") },
        }
    });
    Ok(app)
}

/// A browser-like ClientHello with a zeroed session id. Returns it and the
/// session id's offset.
fn client_hello(random: &[u8; 32], share: &[u8; 32], server_name: &str) -> (Vec<u8>, usize) {
    let grease = |seed: u8| {
        let b = 0x0a | ((seed & 0x0f) << 4);
        [b, b]
    };
    let mut seed = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(32);
    let sid_at = 4 + body.len();
    body.extend_from_slice(&[0u8; 32]);
    let suites: [u16; 15] = [
        u16::from_be_bytes(grease(seed[0])),
        0x1301,
        0x1302,
        0x1303,
        0xc02b,
        0xc02f,
        0xc02c,
        0xc030,
        0xcca9,
        0xcca8,
        0xc013,
        0xc014,
        0x009c,
        0x009d,
        0x002f,
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // Null compression

    let mut ext = Vec::new();
    let mut add = |kind: u16, data: &[u8]| {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(data);
    };
    add(u16::from_be_bytes(grease(seed[1])), &[]);
    let name = server_name.as_bytes();
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    add(0, &sni); // server_name
    add(23, &[]); // extended_master_secret
    add(0xff01, &[0]); // renegotiation_info
    let g = grease(seed[2]);
    add(10, &[0, 8, g[0], g[1], 0, 0x1d, 0, 0x17, 0, 0x18]); // supported_groups
    add(11, &[1, 0]); // ec_point_formats
    add(35, &[]); // session_ticket
    add(16, &[0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']); // ALPN
    add(5, &[1, 0, 0, 0, 0]); // status_request
    let sigs: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0807];
    let mut sa = ((sigs.len() * 2) as u16).to_be_bytes().to_vec();
    for s in sigs {
        sa.extend_from_slice(&s.to_be_bytes());
    }
    add(13, &sa); // signature_algorithms
    add(18, &[]); // signed_certificate_timestamp
    // GREASE entry (2 + 2 + 1) and X25519 (2 + 2 + 32)
    let mut ks = 41u16.to_be_bytes().to_vec();
    ks.extend_from_slice(&g);
    ks.extend_from_slice(&[0, 1, 0, 0, 0x1d, 0, 32]);
    ks.extend_from_slice(share);
    add(51, &ks); // key_share: GREASE, X25519
    add(45, &[1, 1]); // psk_key_exchange_modes: psk_dhe_ke
    let v = grease(seed[3]);
    add(43, &[6, v[0], v[1], 3, 4, 3, 3]); // supported_versions
    add(27, &[2, 0, 2]); // compress_certificate: brotli
    // The second GREASE extension must differ from the first or the server
    // rejects the hello as a duplicate (Chrome does the same)
    add(u16::from_be_bytes(grease(seed[1].wrapping_add(1 + seed[0] % 15))), &[0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut msg = vec![1];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    (msg, sid_at)
}

fn parse_server_hello(m: &[u8]) -> Result<[u8; 32]> {
    ensure!(m.len() > 4 && m[0] == 2, "expected ServerHello");
    let mut r = Cursor { b: &m[4..], at: 0 };
    r.take(2)?;
    let random = r.take(32)?;
    // SHA-256("HelloRetryRequest")
    ensure!(random[..8] != [0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11], "the server asked to retry the handshake");
    let sid = r.u8()? as usize;
    r.take(sid)?;
    ensure!(r.u16()? == TLS_AES_128_GCM_SHA256, "unexpected cipher suite");
    r.take(1)?;
    let ext_len = r.u16()? as usize;
    let mut e = Cursor { b: r.take(ext_len)?, at: 0 };
    let (mut tls13, mut key) = (false, None);
    while e.at < e.b.len() {
        let kind = e.u16()?;
        let n = e.u16()? as usize;
        let data = e.take(n)?;
        match kind {
            43 => tls13 = data == [3, 4],
            51 if data.len() == 36 && data[..4] == [0, 0x1d, 0, 32] => key = data[4..].try_into().ok(),
            _ => {}
        }
    }
    ensure!(tls13, "the server did not choose TLS 1.3");
    key.context("no X25519 key share from the server")
}

/// The certificate must be Ed25519 with HMAC(auth key, public key) as its
/// signature. Returns the public key.
fn check_certificate(msg: &[u8], auth: &[u8; 32]) -> Result<[u8; 32]> {
    let mut r = Cursor { b: &msg[4..], at: 0 };
    let ctx = r.u8()? as usize;
    r.take(ctx)?;
    r.take(3)?;
    let len = r.u24()?;
    let der = r.take(len)?;
    let at = der.windows(ED25519_SPKI.len()).position(|w| w == ED25519_SPKI).context("not an Ed25519 certificate")?;
    let key: [u8; 32] = der.get(at + 12..at + 44).context("truncated certificate")?.try_into()?;
    ensure!(der.len() > 64, "truncated certificate");
    let mac = shared::cert_hmac(auth, &key);
    ensure!(der[der.len() - 64..] == mac[..], "the server is not the REALITY server it claims to be");
    Ok(key)
}

fn verify_certificate_verify(msg: &[u8], key: &[u8; 32], transcript_hash: &[u8]) -> Result<()> {
    let mut r = Cursor { b: &msg[4..], at: 0 };
    ensure!(r.u16()? == 0x0807, "unexpected signature scheme");
    let n = r.u16()? as usize;
    let sig = r.take(n)?;
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(transcript_hash);
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&content, sig)
        .map_err(|_| anyhow::anyhow!("CertificateVerify does not verify"))
}

fn whole_message(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let len = 4 + ((buf[1] as usize) << 16 | (buf[2] as usize) << 8 | buf[3] as usize);
    (buf.len() >= len).then_some(len)
}

fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // HKDF-Extract is HMAC(salt, ikm)
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, ikm).as_ref().try_into().expect("32-byte HMAC-SHA256")
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label_n(secret: &[u8], label: &str, context: &[u8], n: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = (n as u16).to_be_bytes().to_vec();
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let mut out = vec![0u8; n];
    prk.expand(&[&info], Len(n)).and_then(|okm| okm.fill(&mut out)).expect("valid HKDF length");
    out
}

fn expand_label(secret: &[u8], label: &str, context: &[u8]) -> [u8; 32] {
    expand_label_n(secret, label, context, 32).try_into().expect("32 bytes")
}

fn finished(secret: &[u8; 32], transcript_hash: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &expand_label(secret, "finished", b""));
    hmac::sign(&key, transcript_hash).as_ref().try_into().expect("32 bytes")
}

/// One direction's AEAD state
struct Keys {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn new(secret: &[u8; 32]) -> Self {
        let key = expand_label_n(secret, "key", b"", 16);
        let iv: [u8; 12] = expand_label_n(secret, "iv", b"", 12).try_into().expect("12 bytes");
        Keys { key: aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).expect("16-byte key")), iv, seq: 0 }
    }

    fn nonce(&mut self) -> aead::Nonce {
        let mut n = self.iv;
        for (b, s) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *b ^= s;
        }
        self.seq += 1;
        aead::Nonce::assume_unique_for_key(n)
    }

    /// Appends one record carrying `data` of content type `inner`
    fn seal(&mut self, inner: u8, data: &[u8], out: &mut Vec<u8>) {
        let len = data.len() + 1 + 16;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        let start = out.len();
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        out.push(inner);
        let nonce = self.nonce();
        let mut body = out.split_off(start + 5);
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(header), &mut body)
            .expect("record sizes are bounded");
        out.extend_from_slice(&body);
    }

    /// Returns the record's inner content type and data
    fn open(&mut self, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        let header = [23, 3, 3, (payload.len() >> 8) as u8, payload.len() as u8];
        let nonce = self.nonce();
        let mut buf = payload.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(header), &mut buf)
            .map_err(|_| anyhow::anyhow!("record does not decrypt"))?;
        let end = plain.iter().rposition(|&b| b != 0).context("empty record")?;
        Ok((plain[end], plain[..end].to_vec()))
    }
}

struct Records {
    rd: OwnedReadHalf,
    buf: Vec<u8>,
}

impl Records {
    async fn next(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        self.rd.read_exact(&mut header).await.context("connection closed")?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        ensure!(len <= MAX_RECORD + 256, "record too large");
        self.buf.resize(len, 0);
        self.rd.read_exact(&mut self.buf).await?;
        Ok((header[0], std::mem::take(&mut self.buf)))
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self.b.get(self.at..self.at + n).context("truncated message")?;
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_extensions_never_repeat() {
        for _ in 0..200 {
            let (hello, _) = client_hello(&[1; 32], &[2; 32], "www.example.com");
            let h = retail_control::reality::parse_client_hello(&hello).expect("parses");
            assert_eq!(h.server_name.as_deref(), Some("www.example.com"));
            // Skip version, random, session id, cipher suites and compression
            let body = &hello[4..];
            let mut at = 2 + 32 + 1 + 32;
            at += 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
            at += 1 + body[at] as usize;
            let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
            at += 2;
            let mut seen = std::collections::HashSet::new();
            while at < end {
                let kind = u16::from_be_bytes([body[at], body[at + 1]]);
                assert!(seen.insert(kind), "extension {kind:#06x} repeated");
                at += 4 + u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            }
        }
    }

    #[tokio::test]
    async fn handshake_against_the_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("retail-reality-{}", rand::random::<u64>()));
        // Stands in for the camouflage website
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_addr = site.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = site.accept().await {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"real website").await;
            }
        });
        let server_secret = [11u8; 32];
        let server = retail_control::Server::start(retail_control::Config {
            data_dir: dir.clone(),
            listen: "127.0.0.1:0".parse().unwrap(),
            extra_listen: Vec::new(),
            stun_listen: "127.0.0.1:0".parse().unwrap(),
            stun_advertise: vec![],
            tls: retail_control::Tls::SelfSigned,
            reality: Some(retail_control::reality::ServerConfig {
                private_key: server_secret,
                short_ids: vec![[4u8; 8]],
                server_names: vec!["www.example.com".into()],
                dest: site_addr.to_string(),
            }),
        })
        .await
        .unwrap();
        let addr = format!("127.0.0.1:{}", server.port());
        let public = PublicKey::from(&StaticSecret::from(server_secret)).to_bytes();
        let params = Params { public_key: public, short_id: [4u8; 8], server_name: "www.example.com".into() };

        let tcp: BoxIo = Box::new(tokio::net::TcpStream::connect(&addr).await.unwrap());
        let mut s = connect(tcp, &params).await.expect("REALITY handshake");
        s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp).ends_with("ok"), "{}", String::from_utf8_lossy(&resp));

        // A client with the wrong server key is treated as a probe
        let wrong = Params { public_key: [1u8; 32], ..params.clone() };
        let tcp: BoxIo = Box::new(tokio::net::TcpStream::connect(&addr).await.unwrap());
        assert!(connect(tcp, &wrong).await.is_err());

        // A plain probe naming the camouflage site gets the real site
        let mut probe = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let (hello, _) = client_hello(&[9u8; 32], &[3u8; 32], "www.example.com");
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hello);
        probe.write_all(&rec).await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), probe.read_to_end(&mut got)).await;
        assert_eq!(got, b"real website");

        server.stop().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
