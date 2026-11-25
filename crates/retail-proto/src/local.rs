//! Local API authentication: mutating requests carry the token from a file
//! the daemon rewrites at each start, so read access to that file is control
//! of retail. Readers are the users logged on at the computer and
//! administrators on Windows, elsewhere root and the `retail` group (`admin`
//! on macOS).

use std::path::PathBuf;

pub use crate::listener::check as check_listener;

pub const TOKEN_HEADER: &str = "x-retail-token";
/// Carries the administrator token, for what only administrators/root may do
pub const ADMIN_HEADER: &str = "x-retail-admin";

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

/// A second token next to the first that only administrators (Windows) or
/// root can read, for stopping the daemon and for settings that hand out the
/// Windows sign-in
pub fn admin_token_path() -> PathBuf {
    token_path().with_file_name("admin-token")
}

/// `None` unless this process runs as an administrator/root
pub fn read_admin_token() -> Option<String> {
    let t = std::fs::read_to_string(admin_token_path()).ok()?;
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

/// For a sign-in link (`http://127.0.0.1:<port>/login?t=<token>`): a page
/// in this user's temporary folder, readable only by them, that posts the
/// token. Opening the page instead of the link keeps the token off the
/// browser launcher's command line, which other users may see.
pub fn sign_in_page(link: &str) -> std::io::Result<PathBuf> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a sign-in link");
    if !is_local_web_link(link) {
        return Err(bad());
    }
    let (action, token) = link.split_once("?t=").ok_or_else(bad)?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(bad());
    }
    let html = format!(
        "<!DOCTYPE html><meta charset=\"utf-8\"><title>retail</title>\
         <form method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"t\" value=\"{token}\"></form>\
         <script>document.forms[0].submit()</script>\n"
    );
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    let path = std::env::temp_dir().join(format!("retail-sign-in-{}-{nanos}.html", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(&path)?, html.as_bytes())?;
    Ok(path)
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

    #[test]
    fn sign_in_pages() {
        let page = super::sign_in_page("http://127.0.0.1:41180/login?t=abc_-9").unwrap();
        let html = std::fs::read_to_string(&page).unwrap();
        assert!(html.contains("action=\"http://127.0.0.1:41180/login\"") && html.contains("value=\"abc_-9\""), "{html}");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&page).unwrap().permissions()) & 0o777, 0o600);
        let _ = std::fs::remove_file(page);
        assert!(super::sign_in_page("http://127.0.0.1:41180/login?t=a\"><script>").is_err());
        assert!(super::sign_in_page("https://example.com/login?t=abc").is_err());
    }
}
