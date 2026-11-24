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
