//! Reaching the server through a proxy, for networks where only a proxy can
//! get out. HTTP proxies take `CONNECT` (or absolute-form requests for plain
//! HTTP), SOCKS5 proxies their own handshake. Authentication: Basic or SOCKS5
//! user/password from the proxy URL, and on Windows the signed-in user's
//! Negotiate (Kerberos) or NTLM through SSPI, with no password stored.
//!
//! Which proxies: the `proxy` preference if set, otherwise the system's: what
//! the tray app reports for the signed-in user, `HTTPS_PROXY`/`ALL_PROXY`, the
//! WinHTTP machine setting and the console user's own proxy on Windows, and
//! the network settings on macOS.
//!
//! The Windows sign-in is someone's identity (the console user's, or the
//! computer's), so it goes only to proxies that identity's owner or an
//! administrator chose: the console user's own settings, the machine
//! settings, the daemon's environment, and a `proxy` preference an
//! administrator set. Any local user who may control retail can name other
//! proxies, which get Basic authentication only.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use retail_control::BoxIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OS_REFRESH: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Http,
    Socks5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
    /// May be given the Windows sign-in (see the module notes)
    pub sign_in: bool,
}

impl Proxy {
    /// `http://[user:pass@]host:port`, `socks5://…`, `socks5h://…` or a bare
    /// `host:port` (HTTP)
    pub fn parse(s: &str) -> Option<Proxy> {
        let s = s.trim().trim_end_matches('/');
        let (kind, rest) = match s.split_once("://") {
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "http" | "https" => (Kind::Http, rest),
                "socks5" | "socks5h" | "socks" => (Kind::Socks5, rest),
                _ => return None,
            },
            None => (Kind::Http, s),
        };
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((cred, hp)) => {
                let (u, p) = cred.split_once(':').unwrap_or((cred, ""));
                (Some((percent_decode(u), percent_decode(p))), hp)
            }
            None => (None, rest),
        };
        let hostport = hostport.split('/').next()?;
        let (host, port) = match hostport.strip_prefix('[') {
            Some(v6) => {
                let (h, after) = v6.split_once(']')?;
                (h, after.strip_prefix(':').and_then(|p| p.parse().ok()))
            }
            None => match hostport.rsplit_once(':') {
                Some((h, p)) => (h, p.parse().ok()),
                None => (hostport, None),
            },
        };
        if host.is_empty() {
            return None;
        }
        let port = port.unwrap_or(match kind {
            Kind::Http => 8080,
            Kind::Socks5 => 1080,
        });
        Some(Proxy { kind, host: host.to_string(), port, auth, sign_in: false })
    }

    /// For logs and status, without the password
    pub fn label(&self) -> String {
        let scheme = match self.kind {
            Kind::Http => "http",
            Kind::Socks5 => "socks5",
        };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    /// A byte stream to `host:port` through the proxy
    pub async fn connect(&self, host: &str, port: u16) -> Result<BoxIo> {
        let tcp = self.dial().await?;
        match self.kind {
            Kind::Socks5 => socks5(tcp, self, host, port).await,
            Kind::Http => {
                let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
                let (io, resp) = self
                    .request(Box::new(tcp), |auth| {
                        let mut r = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
                        if let Some(a) = auth {
                            r.push_str(&format!("Proxy-Authorization: {a}\r\n"));
                        }
                        r.push_str("\r\n");
                        r.into_bytes()
                    }, true)
                    .await?;
                if !(200..300).contains(&resp.status) {
                    bail!("proxy {} refused CONNECT {target}: HTTP {}", self.label(), resp.status);
                }
                Ok(io)
            }
        }
    }

    pub async fn dial(&self) -> Result<tokio::net::TcpStream> {
        let tcp = crate::happy::connect_many(&self.host, self.port, &[])
            .await
            .with_context(|| format!("connecting to proxy {}", self.label()))?;
        tcp.set_nodelay(true)?;
        Ok(tcp)
    }

    /// Sends what `make` builds, answering `407` challenges on the same
    /// connection (or a new one if the proxy closes it). `make` gets the
    /// `Proxy-Authorization` value to include. With `connect`, a 2xx answer
    /// has no body and the stream continues as the tunnel.
    pub async fn request<F>(&self, io: BoxIo, mut make: F, connect: bool) -> Result<(BoxIo, crate::http1::Response)>
    where
        F: FnMut(Option<&str>) -> Vec<u8>,
    {
        let basic = self.auth.as_ref().map(|(u, p)| format!("Basic {}", B64.encode(format!("{u}:{p}"))));
        let mut io = io;
        let mut auth = basic.clone();
        let mut negotiator: Option<crate::sspi::Negotiator> = None;
        for _ in 0..5 {
            io.write_all(&make(auth.as_deref())).await?;
            io.flush().await?;
            let (rest, resp) = crate::http1::read_response(io, connect).await?;
            io = rest;
            if resp.status != 407 {
                return Ok((io, resp));
            }
            let challenges = resp.headers_named("proxy-authenticate");
            let pick = |scheme: &str| {
                challenges.iter().find_map(|c| {
                    let (s, data) = c.split_once(' ').unwrap_or((c.as_str(), ""));
                    s.eq_ignore_ascii_case(scheme).then(|| data.trim().to_string())
                })
            };
            let next = if let Some(n) = negotiator.as_mut() {
                let data = pick(n.scheme()).filter(|d| !d.is_empty()).context("proxy rejected the sign-in")?;
                let token = n.step(Some(&B64.decode(data).context("malformed proxy challenge")?))?;
                format!("{} {}", n.scheme(), B64.encode(token))
            } else if let Some(scheme) = ["Negotiate", "NTLM"].into_iter().find(|s| pick(s).is_some())
                && crate::sspi::available()
                && self.sign_in
            {
                let mut n = crate::sspi::Negotiator::new(scheme, &self.host)?;
                let token = n.step(None)?;
                negotiator = Some(n);
                format!("{scheme} {}", B64.encode(token))
            } else if pick("Basic").is_some() && basic.is_some() && auth.is_none() {
                basic.clone().unwrap_or_default()
            } else {
                if !self.sign_in && crate::sspi::available() && ["Negotiate", "NTLM"].into_iter().any(|s| pick(s).is_some()) {
                    bail!(
                        "proxy {} asks for the Windows sign-in, which retail gives only to proxies in this computer's settings \
                         or set by an administrator (`retail set --proxy` in an administrator terminal)",
                        self.label()
                    );
                }
                bail!("proxy {} needs a sign-in retail cannot give (set one with `retail set --proxy http://user:password@host:port`)", self.label());
            };
            auth = Some(next);
            if resp.close {
                io = Box::new(self.dial().await?);
            }
        }
        bail!("proxy {} kept asking for a sign-in", self.label())
    }
}

async fn socks5(mut tcp: tokio::net::TcpStream, p: &Proxy, host: &str, port: u16) -> Result<BoxIo> {
    let methods: &[u8] = if p.auth.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    tcp.write_all(methods).await?;
    let mut r = [0u8; 2];
    tcp.read_exact(&mut r).await?;
    match r {
        [5, 0] => {}
        [5, 2] => {
            let (u, pw) = p.auth.clone().unwrap_or_default();
            let mut m = vec![1, u.len() as u8];
            m.extend_from_slice(u.as_bytes());
            m.push(pw.len() as u8);
            m.extend_from_slice(pw.as_bytes());
            tcp.write_all(&m).await?;
            tcp.read_exact(&mut r).await?;
            if r[1] != 0 {
                bail!("SOCKS5 proxy {} rejected the user name or password", p.label());
            }
        }
        _ => bail!("SOCKS5 proxy {} offers no usable sign-in", p.label()),
    }
    let mut req = vec![5, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[1] != 0 {
        bail!("SOCKS5 proxy {} could not reach {host}:{port} (code {})", p.label(), head[1]);
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            tcp.read_exact(&mut n).await?;
            n[0] as usize
        }
        _ => bail!("malformed SOCKS5 reply"),
    } + 2;
    let mut rest = vec![0u8; skip];
    tcp.read_exact(&mut rest).await?;
    Ok(Box::new(tcp))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `None` follows the system; `Some(None)` is off
static PREFERENCE: Mutex<Option<Option<Proxy>>> = Mutex::new(None);
/// From the tray app, for the signed-in user
static USER: Mutex<Vec<Proxy>> = Mutex::new(Vec::new());
static OS: Mutex<Option<(Instant, Vec<Proxy>)>> = Mutex::new(None);

/// From the `proxy` preference: unset, `off`, or a proxy URL. `sign_in`:
/// an administrator set it.
pub fn set_preference(pref: Option<&str>, sign_in: bool) {
    let value = match pref.map(str::trim) {
        None | Some("") | Some("auto") => None,
        Some("off") | Some("none") | Some("direct") => Some(None),
        Some(url) => Some(Proxy::parse(url).map(|p| Proxy { sign_in, ..p })),
    };
    *PREFERENCE.lock().unwrap() = value;
}

pub fn set_user(proxies: &[String]) {
    *USER.lock().unwrap() = proxies.iter().filter_map(|p| Proxy::parse(p)).collect();
}

/// Proxies worth trying, most specific first. Direct connections are tried
/// alongside them in any case.
pub fn current() -> Vec<Proxy> {
    if let Some(pref) = PREFERENCE.lock().unwrap().clone() {
        return pref.into_iter().collect();
    }
    let mut out: Vec<Proxy> = USER.lock().unwrap().clone();
    // The daemon's environment is the administrator's
    for var in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Some(p) = std::env::var(var).ok().as_deref().and_then(Proxy::parse) {
            out.push(Proxy { sign_in: true, ..p });
        }
    }
    out.extend(os_proxies());
    dedup(out)
}

/// One entry per proxy, in the first one's place; it may be given the sign-in
/// if any source that names it may
fn dedup(list: Vec<Proxy>) -> Vec<Proxy> {
    let key = |p: &Proxy| (p.kind, p.host.to_ascii_lowercase(), p.port);
    let mut out: Vec<Proxy> = Vec::new();
    for p in list {
        match out.iter_mut().find(|q| key(q) == key(&p)) {
            Some(q) => q.sign_in |= p.sign_in,
            None => out.push(p),
        }
    }
    out
}

fn os_proxies() -> Vec<Proxy> {
    let mut cache = OS.lock().unwrap();
    if let Some((at, v)) = cache.as_ref()
        && at.elapsed() < OS_REFRESH
    {
        return v.clone();
    }
    let v = read_os_proxies();
    *cache = Some((Instant::now(), v.clone()));
    v
}

/// Entries of a Windows proxy list: `host:port` or `https=host:port;http=…`
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn parse_proxy_list(list: &str) -> Vec<Proxy> {
    let mut https = Vec::new();
    let mut other = Vec::new();
    for entry in list.split([';', ' ']).map(str::trim).filter(|e| !e.is_empty()) {
        match entry.split_once('=') {
            Some((scheme, addr)) => match scheme.to_ascii_lowercase().as_str() {
                "https" => https.extend(Proxy::parse(addr)),
                "http" => other.extend(Proxy::parse(addr)),
                "socks" => other.extend(Proxy::parse(&format!("socks5://{addr}"))),
                _ => {}
            },
            None => https.extend(Proxy::parse(entry)),
        }
    }
    https.extend(other);
    https
}

#[cfg(windows)]
fn read_os_proxies() -> Vec<Proxy> {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinHttp::{
        WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_PROXY_INFO, WinHttpGetDefaultProxyConfiguration,
    };
    let mut info: WINHTTP_PROXY_INFO = unsafe { std::mem::zeroed() };
    if unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) } == 0 {
        return Vec::new();
    }
    let take = |p: *mut u16| {
        if p.is_null() {
            return String::new();
        }
        let s = unsafe { wide_to_string(p) };
        unsafe { GlobalFree(p as _) };
        s
    };
    let list = take(info.lpszProxy);
    let _ = take(info.lpszProxyBypass);
    let mut out = if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY { parse_proxy_list(&list) } else { Vec::new() };
    if let Some(user) = crate::sspi::console_user_proxy() {
        out.extend(parse_proxy_list(&user));
    }
    // The machine's settings are an administrator's, the console user's their own
    out.into_iter().map(|p| Proxy { sign_in: true, ..p }).collect()
}

/// # Safety
/// `p` points at a NUL-terminated UTF-16 string
#[cfg(windows)]
pub unsafe fn wide_to_string(p: *const u16) -> String {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// `scutil --proxy` prints the network settings' proxies
#[cfg(target_os = "macos")]
fn read_os_proxies() -> Vec<Proxy> {
    let Ok(out) = std::process::Command::new("scutil").arg("--proxy").output() else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    };
    let mut out = Vec::new();
    for (enable, host, port, scheme) in
        [("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "http"), ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "socks5"), ("HTTPEnable", "HTTPProxy", "HTTPPort", "http")]
    {
        if get(enable).as_deref() == Some("1")
            && let (Some(h), Some(p)) = (get(host), get(port))
        {
            out.extend(Proxy::parse(&format!("{scheme}://{h}:{p}")));
        }
    }
    out
}

#[cfg(not(any(windows, target_os = "macos")))]
fn read_os_proxies() -> Vec<Proxy> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let p = Proxy::parse("http://alice:p%40ss@proxy.corp:3128").unwrap();
        assert_eq!((p.kind, p.host.as_str(), p.port), (Kind::Http, "proxy.corp", 3128));
        assert_eq!(p.auth, Some(("alice".into(), "p@ss".into())));
        assert_eq!(p.label(), "http://proxy.corp:3128");
        let p = Proxy::parse("socks5h://[2001:db8::1]:1081").unwrap();
        assert_eq!((p.kind, p.host.as_str(), p.port), (Kind::Socks5, "2001:db8::1", 1081));
        assert_eq!(Proxy::parse("10.0.0.1:8080").unwrap().port, 8080);
        assert!(Proxy::parse("ftp://x:1").is_none());
        let list = parse_proxy_list("http=a:80;https=b:443;socks=c:1080");
        let hosts: Vec<_> = list.iter().map(|p| p.host.as_str()).collect();
        assert_eq!(hosts, ["b", "a", "c"]);
    }

    /// A proxy that answers 407 on a closed connection, then accepts the
    /// credentials sent up front
    #[tokio::test]
    async fn connect_with_basic_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("CONNECT example.net:443 HTTP/1.1"), "{req}");
            assert!(req.contains("Proxy-Authorization: Basic YTpi"), "{req}");
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello").await.unwrap();
        });
        let p = Proxy { kind: Kind::Http, host: "127.0.0.1".into(), port: addr.port(), auth: Some(("a".into(), "b".into())), sign_in: false };
        let mut io = p.connect("example.net", 443).await.unwrap();
        let mut got = [0u8; 5];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn missing_credentials_fail_clearly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let p = Proxy { kind: Kind::Http, host: "127.0.0.1".into(), port: addr.port(), auth: None, sign_in: false };
        let err = p.connect("example.net", 443).await.err().unwrap().to_string();
        assert!(err.contains("sign-in"), "{err}");
    }

    /// A proxy any local user could have named asks for NTLM: it gets no
    /// Windows sign-in, only a refusal
    #[tokio::test]
    async fn untrusted_proxy_gets_no_windows_sign_in() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = tokio::spawn(async move {
            let mut requests = Vec::new();
            while let Ok(Ok((mut s, _))) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                requests.push(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = s
                    .write_all(b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: NTLM\r\nProxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
            requests
        });
        let p = Proxy { kind: Kind::Http, host: "127.0.0.1".into(), port: addr.port(), auth: None, sign_in: false };
        let err = p.connect("example.net", 443).await.err().unwrap().to_string();
        assert!(err.contains("sign-in"), "{err}");
        let requests = seen.await.unwrap();
        assert!(requests.iter().all(|r| !r.contains("Proxy-Authorization")), "{requests:?}");
        // Settings of the machine, the console user or an administrator may
        let trusted = dedup(vec![p.clone(), Proxy { sign_in: true, ..p.clone() }]);
        assert_eq!(trusted.len(), 1);
        assert!(trusted[0].sign_in);
    }
}
