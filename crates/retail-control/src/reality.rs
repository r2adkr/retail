//! REALITY, following Xray's scheme: when plain HTTPS to the server is blocked
//! by server name or handshake fingerprint, devices reach it through TLS that
//! names an unrelated, allowed website.
//!
//! - The client derives an auth key from X25519(its key share, the server's
//!   static key) and hides an AES-GCM sealed timestamp and short id in the
//!   ClientHello session id.
//! - A server that can open it finishes TLS itself with a throwaway
//!   certificate whose signature field is HMAC-SHA512(auth key, its public
//!   key), which the client checks instead of a certificate authority.
//! - Anyone else, such as an active probe, is spliced to the real website and
//!   sees its real handshake and content.
//!
//! This defeats blocking by name or fingerprint and active probing, not
//! blocking of the server's IP address. Clocks must agree within `MAX_SKEW`.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::{aead, hkdf, hmac};

/// Seconds of clock difference accepted between client and server
pub const MAX_SKEW: u64 = 120;
const VERSION: [u8; 3] = [1, 8, 0];

/// The invite carries the public half
#[derive(Clone)]
pub struct ServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    /// A ClientHello naming one of these is checked for REALITY
    pub server_names: Vec<String>,
    /// `host:port` of the real website unauthenticated connections go to
    pub dest: String,
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA256(ikm = shared secret, salt = client_random[..20], info = "REALITY")
pub fn auth_key(shared: &[u8; 32], client_random: &[u8; 32]) -> [u8; 32] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &client_random[..20]);
    let mut out = [0u8; 32];
    salt.extract(shared)
        .expand(&[b"REALITY"], Len32)
        .and_then(|okm| okm.fill(&mut out))
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// Version, reserved byte, time and short id
pub fn session_plaintext(time: u64, short_id: [u8; 8]) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..3].copy_from_slice(&VERSION);
    p[4..8].copy_from_slice(&(time as u32).to_be_bytes());
    p[8..].copy_from_slice(&short_id);
    p
}

fn gcm(auth: &[u8; 32]) -> aead::LessSafeKey {
    aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, auth).expect("32-byte key"))
}

fn nonce(client_random: &[u8; 32]) -> aead::Nonce {
    aead::Nonce::assume_unique_for_key(client_random[20..32].try_into().expect("12 bytes"))
}

/// `hello` is the ClientHello handshake message with its session id zeroed,
/// used as AAD.
pub fn seal_session_id(auth: &[u8; 32], client_random: &[u8; 32], hello: &[u8], plain: &[u8; 16]) -> [u8; 32] {
    let mut buf = plain.to_vec();
    gcm(auth)
        .seal_in_place_append_tag(nonce(client_random), aead::Aad::from(hello), &mut buf)
        .expect("sealing 16 bytes");
    buf.try_into().expect("16 bytes + 16-byte tag")
}

pub fn open_session_id(auth: &[u8; 32], client_random: &[u8; 32], hello: &[u8], sid: &[u8; 32]) -> Option<[u8; 16]> {
    let mut buf = sid.to_vec();
    let plain = gcm(auth).open_in_place(nonce(client_random), aead::Aad::from(hello), &mut buf).ok()?;
    plain.try_into().ok()
}

/// Carried in the throwaway certificate's signature field
pub fn cert_hmac(auth: &[u8; 32], ed25519_public: &[u8]) -> [u8; 64] {
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth);
    hmac::sign(&key, ed25519_public).as_ref().try_into().expect("SHA-512 output")
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    /// Offset of the session id within the handshake message
    pub session_id_at: usize,
    pub server_name: Option<String>,
    pub x25519: Option<[u8; 32]>,
}

/// `msg` starts at the handshake type byte
pub fn parse_client_hello(msg: &[u8]) -> Option<Hello> {
    let mut r = Reader { b: msg, at: 0 };
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    if len + 4 != msg.len() {
        return None;
    }
    r.skip(2)?; // legacy_version
    let random: [u8; 32] = r.take(32)?.try_into().ok()?;
    let sid_len = r.u8()? as usize;
    let session_id_at = r.at;
    let session_id = r.take(sid_len)?.to_vec();
    let suites = r.u16()? as usize;
    r.skip(suites)?;
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    let mut hello = Hello { random, session_id, session_id_at, server_name: None, x25519: None };
    let ext_len = r.u16()? as usize;
    let mut ext = Reader { b: r.take(ext_len)?, at: 0 };
    while ext.at < ext.b.len() {
        let kind = ext.u16()?;
        let n = ext.u16()? as usize;
        let data = ext.take(n)?;
        let mut d = Reader { b: data, at: 0 };
        match kind {
            0 => {
                // server_name: list, first entry of type host_name
                d.skip(2)?;
                if d.u8()? == 0 {
                    let n = d.u16()? as usize;
                    hello.server_name = std::str::from_utf8(d.take(n)?).ok().map(str::to_ascii_lowercase);
                }
            }
            51 => {
                // key_share: list of (group, key)
                let total = d.u16()? as usize;
                let mut shares = Reader { b: d.take(total)?, at: 0 };
                while shares.at < shares.b.len() {
                    let group = shares.u16()?;
                    let n = shares.u16()? as usize;
                    let key = shares.take(n)?;
                    if group == 0x001d && key.len() == 32 {
                        hello.x25519 = key.try_into().ok();
                    }
                }
            }
            _ => {}
        }
    }
    Some(hello)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

pub enum Decision {
    /// Not a camouflage name, so the ordinary HTTPS server handles it
    Normal,
    Reality { auth: [u8; 32] },
    /// Names the camouflage site but fails authentication, so it goes to the real site
    Camouflage,
}

/// Session ids remembered at most. Anyone holding an invite can mint
/// authenticated hellos, so the memory and the work per hello stay bounded;
/// when full, new hellos are treated as probes until old ones age out.
const MAX_SEEN: usize = 65536;

/// A replayed ClientHello is treated as a probe
#[derive(Default)]
pub struct ReplayGuard {
    seen: Mutex<Seen>,
}

#[derive(Default)]
struct Seen {
    ids: HashSet<[u8; 32]>,
    /// The same ids, oldest first
    order: VecDeque<(Instant, [u8; 32])>,
}

impl ReplayGuard {
    fn fresh(&self, sid: &[u8; 32]) -> bool {
        let mut seen = self.seen.lock().unwrap();
        let Seen { ids, order } = &mut *seen;
        // A sealed timestamp stays acceptable for at most 2 * MAX_SKEW
        let window = Duration::from_secs(2 * MAX_SKEW);
        while let Some((at, old)) = order.front() {
            if at.elapsed() < window {
                break;
            }
            ids.remove(old);
            order.pop_front();
        }
        if ids.contains(sid) || ids.len() >= MAX_SEEN {
            return false;
        }
        ids.insert(*sid);
        order.push_back((Instant::now(), *sid));
        true
    }
}

pub fn decide(cfg: &ServerConfig, replay: &ReplayGuard, msg: &[u8]) -> Decision {
    let Some(hello) = parse_client_hello(msg) else { return Decision::Normal };
    let Some(name) = hello.server_name.as_deref() else { return Decision::Normal };
    if !cfg.server_names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return Decision::Normal;
    }
    match authenticate(cfg, replay, msg, &hello) {
        Some(auth) => Decision::Reality { auth },
        None => Decision::Camouflage,
    }
}

fn authenticate(cfg: &ServerConfig, replay: &ReplayGuard, msg: &[u8], hello: &Hello) -> Option<[u8; 32]> {
    let client_share = hello.x25519?;
    let sid: [u8; 32] = hello.session_id.as_slice().try_into().ok()?;
    let secret = x25519_dalek::StaticSecret::from(cfg.private_key);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(client_share));
    let auth = auth_key(shared.as_bytes(), &hello.random);
    let mut aad = msg.to_vec();
    aad[hello.session_id_at..hello.session_id_at + 32].fill(0);
    let plain = open_session_id(&auth, &hello.random, &aad, &sid)?;
    let time = u32::from_be_bytes(plain[4..8].try_into().ok()?) as u64;
    let short_id: [u8; 8] = plain[8..].try_into().ok()?;
    let now = now_secs() as u32 as u64;
    if plain[..3] != VERSION || now.abs_diff(time) > MAX_SKEW || !cfg.short_ids.contains(&short_id) {
        return None;
    }
    replay.fresh(&sid).then_some(auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_guard_is_bounded() {
        let g = ReplayGuard::default();
        let sid = |i: usize| {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(i as u64).to_be_bytes());
            s
        };
        assert!(g.fresh(&sid(0)));
        assert!(!g.fresh(&sid(0)), "a replay is refused");
        for i in 1..MAX_SEEN {
            assert!(g.fresh(&sid(i)));
        }
        // Full: new hellos count as probes rather than growing the set
        assert!(!g.fresh(&sid(MAX_SEEN)));
        let s = g.seen.lock().unwrap();
        assert_eq!((s.ids.len(), s.order.len()), (MAX_SEEN, MAX_SEEN));
    }

    pub(crate) fn hello(sni: &str, share: [u8; 32], sid: [u8; 32], random: [u8; 32]) -> Vec<u8> {
        let mut ext = Vec::new();
        let name = sni.as_bytes();
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&38u16.to_be_bytes());
        ext.extend_from_slice(&36u16.to_be_bytes());
        ext.extend_from_slice(&0x001du16.to_be_bytes());
        ext.extend_from_slice(&32u16.to_be_bytes());
        ext.extend_from_slice(&share);
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&sid);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut msg = vec![1, 0, 0, 0];
        msg[1..4].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn authenticated_probed_and_plain_hellos() {
        let server = x25519_dalek::StaticSecret::from([3u8; 32]);
        let cfg = ServerConfig {
            private_key: [3u8; 32],
            short_ids: vec![[9u8; 8]],
            server_names: vec!["www.example.com".into()],
            dest: "www.example.com:443".into(),
        };
        let replay = ReplayGuard::default();
        let client = x25519_dalek::StaticSecret::from([5u8; 32]);
        let share = x25519_dalek::PublicKey::from(&client).to_bytes();
        let random = [7u8; 32];

        let mut msg = hello("www.example.com", share, [0; 32], random);
        let parsed = parse_client_hello(&msg).unwrap();
        let shared = client.diffie_hellman(&x25519_dalek::PublicKey::from(&server));
        let auth = auth_key(shared.as_bytes(), &random);
        let sid = seal_session_id(&auth, &random, &msg, &session_plaintext(now_secs(), [9u8; 8]));
        msg[parsed.session_id_at..parsed.session_id_at + 32].copy_from_slice(&sid);

        assert!(matches!(decide(&cfg, &replay, &msg), Decision::Reality { auth: a } if a == auth));
        assert!(matches!(decide(&cfg, &replay, &msg), Decision::Camouflage), "a replay is a probe");
        let probe = hello("www.example.com", share, [1; 32], [8; 32]);
        assert!(matches!(decide(&cfg, &replay, &probe), Decision::Camouflage));
        let other = hello("retail.example.net", share, [1; 32], [8; 32]);
        assert!(matches!(decide(&cfg, &replay, &other), Decision::Normal));

        // Wrong short id or a stale clock is a probe too
        for (time, id) in [(now_secs(), [1u8; 8]), (now_secs() - 3 * MAX_SKEW, [9u8; 8])] {
            let random = [time as u8; 32];
            let mut m = hello("www.example.com", share, [0; 32], random);
            let shared = client.diffie_hellman(&x25519_dalek::PublicKey::from(&server));
            let a = auth_key(shared.as_bytes(), &random);
            let sid = seal_session_id(&a, &random, &m, &session_plaintext(time, id));
            m[parsed.session_id_at..parsed.session_id_at + 32].copy_from_slice(&sid);
            assert!(matches!(decide(&cfg, &replay, &m), Decision::Camouflage));
        }
    }
}
