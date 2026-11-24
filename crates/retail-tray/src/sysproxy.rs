//! Tells the daemon which proxy the signed-in user's Windows settings pick
//! for the server. The daemon runs as a service and sees neither per-user
//! proxy settings nor the result of PAC scripts, so the tray looks them up
//! and sends them over the local API every minute when they change.

#[cfg(windows)]
pub fn spawn(addr: std::net::SocketAddr) {
    use std::time::Duration;
    let _ = std::thread::Builder::new().name("retail-proxy".into()).stack_size(256 * 1024).spawn(move || {
        let mut sent: Option<Vec<String>> = None;
        loop {
            let server = crate::api::status_blocking(addr).ok().and_then(|s| s.server);
            if let Some(server) = server {
                let proxies = for_url(&server);
                if sent.as_ref() != Some(&proxies) {
                    let body = serde_json::to_string(&retail_proto::api::SystemProxy { proxies: proxies.clone() })
                        .unwrap_or_default();
                    if crate::api::post_blocking(addr, "/proxy/system", &body).is_ok() {
                        sent = Some(proxies);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(60));
        }
    });
}

#[cfg(not(windows))]
pub fn spawn(_addr: std::net::SocketAddr) {}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// # Safety
/// `p` is null or a NUL-terminated UTF-16 string from WinHTTP, freed here
#[cfg(windows)]
unsafe fn take(p: *mut u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) });
    unsafe { windows_sys::Win32::Foundation::GlobalFree(p as _) };
    Some(s)
}

/// `host:port` entries, or `https=host:port;http=…`, as `http://host:port`
#[cfg(windows)]
fn parse_list(list: &str) -> Vec<String> {
    let mut https = Vec::new();
    let mut other = Vec::new();
    for entry in list.split([';', ' ']).map(str::trim).filter(|e| !e.is_empty()) {
        match entry.split_once('=') {
            Some((scheme, addr)) => match scheme.to_ascii_lowercase().as_str() {
                "https" => https.push(format!("http://{addr}")),
                "http" => other.push(format!("http://{addr}")),
                "socks" => other.push(format!("socks5://{addr}")),
                _ => {}
            },
            None => https.push(format!("http://{entry}")),
        }
    }
    https.extend(other);
    https
}

/// The proxies for `url`, empty for a direct connection
#[cfg(windows)]
fn for_url(url: &str) -> Vec<String> {
    use windows_sys::Win32::Networking::WinHttp::*;
    let mut ie: WINHTTP_CURRENT_USER_IE_PROXY_CONFIG = unsafe { std::mem::zeroed() };
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) } == 0 {
        return Vec::new();
    }
    let auto_url = unsafe { take(ie.lpszAutoConfigUrl) };
    let manual = unsafe { take(ie.lpszProxy) };
    let _ = unsafe { take(ie.lpszProxyBypass) };
    if ie.fAutoDetect != 0 || auto_url.is_some() {
        let agent = wide("retail");
        let session = unsafe { WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_NO_PROXY, std::ptr::null(), std::ptr::null(), 0) };
        if !session.is_null() {
            let auto_w = auto_url.as_deref().map(wide);
            let mut opts: WINHTTP_AUTOPROXY_OPTIONS = unsafe { std::mem::zeroed() };
            if ie.fAutoDetect != 0 {
                opts.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
                opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            }
            if let Some(w) = &auto_w {
                opts.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
                opts.lpszAutoConfigUrl = w.as_ptr();
            }
            opts.fAutoLogonIfChallenged = 1;
            let target = wide(url);
            let mut info: WINHTTP_PROXY_INFO = unsafe { std::mem::zeroed() };
            let ok = unsafe { WinHttpGetProxyForUrl(session, target.as_ptr(), &mut opts, &mut info) } != 0;
            unsafe { WinHttpCloseHandle(session) };
            if ok {
                let list = unsafe { take(info.lpszProxy) };
                let _ = unsafe { take(info.lpszProxyBypass) };
                if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
                    return list.map(|l| parse_list(&l)).unwrap_or_default();
                }
                return Vec::new();
            }
        }
    }
    manual.map(|l| parse_list(&l)).unwrap_or_default()
}
