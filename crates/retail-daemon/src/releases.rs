//! Official releases from GitHub Releases: a release holds one installer per
//! system (`retail-windows-x86_64.exe`, `retail-linux-aarch64.deb`,
//! `retail-macos.dmg`, ...) with every program inside, plus `VERSION` and
//! `SHA256SUMS`. The installer is checked against the checksums and its
//! programs taken out: by the updater for this device, and by a server for
//! client packages of systems it has no programs for (kept in
//! `<state>/clients/<os>-<arch>/` for the next downloads).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FILE: u64 = 200 << 20;
const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(300);

/// Where release files are published; `RETAIL_RELEASES` overrides it, and an
/// empty value turns fetching off
pub fn base() -> Option<String> {
    match std::env::var("RETAIL_RELEASES") {
        Ok(v) if v.trim().is_empty() => None,
        Ok(v) => Some(v.trim().trim_end_matches('/').to_string()),
        Err(_) => Some(retail_proto::RELEASES.to_string()),
    }
}

/// The release's installer for `<os>-<arch>`. macOS has one for both
/// processors, a disk image; Linux a Debian package per processor.
pub fn installer_asset(variant: &str) -> String {
    match variant.split_once('-').map(|(os, _)| os) {
        Some("windows") => format!("retail-{variant}.exe"),
        Some("macos") => "retail-macos.dmg".to_string(),
        _ => format!("retail-{variant}.deb"),
    }
}

/// Fetches `files` of `variant` for this daemon's own version into `dir`,
/// unless they are all there
pub async fn fetch(variant: &str, files: &[String], dir: &Path) -> Result<()> {
    if files.iter().all(|f| dir.join(f).is_file()) {
        return Ok(());
    }
    fetch_version(env!("CARGO_PKG_VERSION"), variant, files, dir).await
}

/// The newest published version. Releases carry a `VERSION` file, and
/// GitHub redirects `releases/latest/download/<file>` to the newest release's.
pub async fn latest_version() -> Result<String> {
    let base = base().context("update checks are turned off (RETAIL_RELEASES)")?;
    let url = match base.strip_suffix("/releases/download") {
        Some(repo) => format!("{repo}/releases/latest/download/VERSION"),
        None => format!("{base}/latest/VERSION"),
    };
    let body = tokio::time::timeout(Duration::from_secs(60), get(&url, None)).await.context("checking took too long")??.1;
    let v = String::from_utf8_lossy(&body).trim().trim_start_matches('v').to_string();
    if parse_version(&v).is_none() {
        bail!("the release's VERSION is not a version: {v:?}");
    }
    Ok(v)
}

/// `1.2.3` as numbers, for comparing
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    let out = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(out)
}

/// Whether `latest` is newer than `current`
pub fn newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(l), Some(c)) if l > c)
}

/// Fetches the installer of `variant` from release `version`, checks it, and
/// writes `files` from it into `dir`
pub async fn fetch_version(version: &str, variant: &str, files: &[String], dir: &Path) -> Result<()> {
    // One fetch at a time: two clicks must not race on the same files
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = LOCK.lock().await;
    let base = base().context("fetching official releases is turned off (RETAIL_RELEASES)")?;
    let release = format!("{base}/v{version}");
    let name = installer_asset(variant);
    tokio::time::timeout(TIMEOUT, async {
        let sums = get(&format!("{release}/SHA256SUMS"), None).await.context("reading the release's checksums")?;
        let sums = String::from_utf8_lossy(&sums.1);
        let want = sums
            .lines()
            .find_map(|l| {
                let (hash, n) = l.split_once(char::is_whitespace)?;
                (n.trim().trim_start_matches('*') == name).then(|| hash.to_ascii_lowercase())
            })
            .with_context(|| format!("release v{version} has no {name}"))?;
        tokio::fs::create_dir_all(dir).await?;
        let download = dir.join(format!("{name}.download"));
        let got = get(&format!("{release}/{name}"), Some(&download)).await.with_context(|| format!("downloading {name}"))?.0;
        if got != want {
            let _ = tokio::fs::remove_file(&download).await;
            bail!("{name} does not match the release checksum");
        }
        let (dir2, files2, download2) = (dir.to_path_buf(), files.to_vec(), download.clone());
        let unpacked = tokio::task::spawn_blocking(move || unpack(&download2, &dir2, &files2)).await?;
        let _ = tokio::fs::remove_file(&download).await;
        unpacked.with_context(|| format!("taking the programs out of {name}"))?;
        tracing::info!(%name, "official release fetched");
        anyhow::Ok(())
    })
    .await
    .context("fetching took too long")?
}

/// Writes `files` out of the installer at `path`: in front of a disk image
/// (macOS), in a Debian package (Linux), or the file itself (Windows)
fn unpack(path: &Path, dir: &Path, files: &[String]) -> Result<()> {
    use retail_proto::package::{DEB_INSTALLER, Window, deb_entry, dmg_prefix, extract, read_manifest};
    let mut f = std::fs::File::open(path)?;
    let name = path.to_string_lossy();
    let (start, len) = if name.ends_with(".dmg.download") {
        (0, dmg_prefix(&mut f).context("the disk image carries no installer")?)
    } else if name.ends_with(".deb.download") {
        deb_entry(&mut f, DEB_INSTALLER).context("the package carries no installer")?
    } else {
        (0, f.metadata()?.len())
    };
    let mut w = Window::new(f, start, len);
    let m = read_manifest(&mut w).context("not a retail installer")?;
    let written = extract(&mut w, &m, dir, |n| files.iter().any(|f| f == n))?;
    if let Some(missing) = files.iter().find(|f| !written.contains(f)) {
        bail!("the installer has no {missing}");
    }
    Ok(())
}

/// GETs `url`, following redirects, into `to` or memory. Returns the SHA-256
/// (hex) and, without `to`, the body.
async fn get(url: &str, to: Option<&Path>) -> Result<(String, Vec<u8>)> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let u = crate::http::parse_url(&url)?;
        if !u.tls {
            bail!("refusing a plain-HTTP download");
        }
        let io = open(u.host, u.port).await?;
        let name = rustls::pki_types::ServerName::try_from(u.host.to_string())?;
        let mut tls = tokio_rustls::TlsConnector::from(crate::http::tls_config()).connect(name, io).await?;
        let path = url.split_once("://").and_then(|(_, r)| r.find('/').map(|i| &r[i..])).unwrap_or("/");
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: retaild/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            u.authority_string(),
            env!("CARGO_PKG_VERSION")
        );
        tls.write_all(req.as_bytes()).await?;
        let (head, rest) = read_head(&mut tls).await?;
        let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).context("malformed answer")?;
        let header = |k: &str| {
            head.lines().skip(1).find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.trim().eq_ignore_ascii_case(k).then(|| v.trim().to_string())
            })
        };
        if (300..400).contains(&status) {
            url = header("location").context("redirect without a location")?;
            continue;
        }
        if status == 404 {
            bail!("not published (HTTP 404): this version may not be released yet");
        }
        if status != 200 {
            bail!("HTTP {status}");
        }
        let length: Option<u64> = header("content-length").and_then(|v| v.parse().ok());
        if length.is_some_and(|n| n > MAX_FILE) {
            bail!("file too large");
        }
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut body = Vec::new();
        let mut file = match to {
            Some(p) => Some(tokio::fs::File::create(p).await?),
            None => None,
        };
        let mut total = 0u64;
        let mut chunk = rest;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if !chunk.is_empty() {
                total += chunk.len() as u64;
                if total > MAX_FILE {
                    bail!("file too large");
                }
                hash.update(&chunk);
                match file.as_mut() {
                    Some(f) => f.write_all(&chunk).await?,
                    None => body.extend_from_slice(&chunk),
                }
            }
            let n = tls.read(&mut buf).await.or_else(|e| {
                // Servers often close without a TLS close_notify after `Connection: close`
                if e.kind() == std::io::ErrorKind::UnexpectedEof { Ok(0) } else { Err(e) }
            })?;
            if n == 0 {
                break;
            }
            chunk = buf[..n].to_vec();
        }
        if let Some(f) = file.as_mut() {
            f.flush().await?;
        }
        if length.is_some_and(|n| n != total) {
            bail!("download cut short");
        }
        let hex = hash.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
        return Ok((hex, body));
    }
    bail!("too many redirects")
}

/// Directly, or through the first proxy that works
async fn open(host: &str, port: u16) -> Result<retail_control::BoxIo> {
    let direct = tokio::time::timeout(Duration::from_secs(10), crate::happy::connect_many(host, port, &[])).await;
    if let Ok(Ok(tcp)) = direct {
        return Ok(Box::new(tcp));
    }
    for p in crate::proxy::current() {
        if let Ok(io) = p.connect(host, port).await {
            return Ok(io);
        }
    }
    bail!("cannot reach {host}")
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_string();
            return Ok((head, buf[i + 4..].to_vec()));
        }
        if buf.len() > 32 * 1024 {
            bail!("answer header too large");
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed early");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_names() {
        assert_eq!(installer_asset("linux-x86_64"), "retail-linux-x86_64.deb");
        assert_eq!(installer_asset("windows-x86_64"), "retail-windows-x86_64.exe");
        assert_eq!(installer_asset("macos-aarch64"), "retail-macos.dmg");
        assert_eq!(installer_asset("macos-x86_64"), "retail-macos.dmg");
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(newer("0.10.0", "0.9.3"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.2.0", "0.2.0"));
        assert!(!newer("0.1.9", "0.2.0"));
        assert!(!newer("0.2", "0.1.0"));
        assert!(!newer("v0.3.0", "0.1.0"));
    }
}
