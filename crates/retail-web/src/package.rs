//! Streams a client package (see `retail_proto::package`) without holding the
//! program files in memory.

use std::path::PathBuf;

use axum::body::{Body, Bytes};
use retail_proto::package::{Manifest, PackedFile, trailer};
use tokio::io::AsyncReadExt;

const CHUNK: usize = 64 * 1024;

/// Prebuilt client files for one OS and architecture
#[derive(Debug, Clone)]
pub struct ClientSource {
    /// `windows-x86_64` and the like
    pub id: String,
    pub label: String,
    pub os: String,
    /// The tray app, which the package starts as and which installs the rest
    pub tray: PathBuf,
    /// Installed next to it: daemon, CLI, and on Windows `wintun.dll`
    pub files: Vec<(String, PathBuf)>,
    /// Required files that are not there; such a client is not offered
    pub missing: Vec<String>,
}

/// The package's length and a stream of its bytes
pub async fn build(source: &ClientSource, invite: &str, network: &str) -> std::io::Result<(u64, Body)> {
    let base_len = tokio::fs::metadata(&source.tray).await?.len();
    let mut offset = base_len;
    let mut files = Vec::new();
    for (name, path) in &source.files {
        let len = tokio::fs::metadata(path).await?.len();
        files.push(PackedFile { name: name.clone(), offset, len });
        offset += len;
    }
    let manifest = Manifest { invite: invite.to_string(), network: network.to_string(), files, base_len };
    let tail = trailer(&manifest);
    let total = offset + tail.len() as u64;
    let paths: Vec<PathBuf> = std::iter::once(source.tray.clone()).chain(source.files.iter().map(|(_, p)| p.clone())).collect();
    let stream = futures_util::stream::unfold((paths.into_iter(), None::<tokio::fs::File>, Some(tail)), |(mut paths, mut file, mut tail)| async move {
        loop {
            if let Some(f) = file.as_mut() {
                let mut buf = vec![0u8; CHUNK];
                match f.read(&mut buf).await {
                    Ok(0) => drop(file.take()),
                    Ok(n) => {
                        buf.truncate(n);
                        return Some((Ok::<Bytes, std::io::Error>(Bytes::from(buf)), (paths, file, tail)));
                    }
                    Err(e) => return Some((Err(e), (paths, None, None))),
                }
            }
            match paths.next() {
                Some(p) => match tokio::fs::File::open(&p).await {
                    Ok(f) => file = Some(f),
                    Err(e) => return Some((Err(e), (paths, None, None))),
                },
                None => return tail.take().map(|t| (Ok(Bytes::from(t)), (paths, None, None))),
            }
        }
    });
    Ok((total, Body::from_stream(stream)))
}

/// `retail-family-windows.exe` and the like
pub fn file_name(source: &ClientSource, network: &str) -> String {
    let label: String = network
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let name = if label.is_empty() { format!("retail-{}", source.os) } else { format!("retail-{label}-{}", source.os) };
    if source.os == "windows" { format!("{name}.exe") } else { name }
}
