//! Local API authentication: mutating requests carry the token from a file
//! the daemon rewrites at each start, so read access to that file is control
//! of retail. Readers are the users logged on at the computer and
//! administrators on Windows, elsewhere root and the `retail` group (`admin`
//! on macOS).

use std::path::PathBuf;

pub const TOKEN_HEADER: &str = "x-retail-token";

pub fn token_path() -> PathBuf {
    if let Some(p) = std::env::var_os("RETAIL_API_TOKEN_FILE") {
        return PathBuf::from(p);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("retail-api").join("token")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/retail-api/token")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/run/retail/api-token")
    }
}

/// `None` if this user may not read the token file
pub fn read_token() -> Option<String> {
    let t = std::fs::read_to_string(token_path()).ok()?;
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// Whether `url` is a link to the web page on this device, the only kind the
/// daemon hands out. Whatever answers on the local API port could be another
/// program, and a browser launcher also opens files and programs.
pub fn is_local_web_link(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://127.0.0.1:") else { return false };
    let port_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    (1..=5).contains(&port_len)
        && rest[port_len..].starts_with('/')
        && rest.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_web_links() {
        use super::is_local_web_link as ok;
        assert!(ok("http://127.0.0.1:41180/login?t=abc_-"));
        assert!(!ok("file:///C:/Windows/System32/calc.exe"));
        assert!(!ok("http://127.0.0.1.evil.example:41180/"));
        assert!(!ok("http://127.0.0.1:41180@evil.example/"));
        assert!(!ok("https://example.com/"));
        assert!(!ok("http://127.0.0.1:41180/x y"));
    }
}
