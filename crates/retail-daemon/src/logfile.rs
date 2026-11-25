//! The daemon's log as a file, where the service manager keeps no output
//! (Windows Task Scheduler, launchd): `retaild.log` in the state folder,
//! moved to `retaild.log.1` once it passes `MAX`, so at most twice that is kept.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAX: u64 = 1 << 20;

#[derive(Clone)]
pub struct LogFile(Arc<Mutex<Inner>>);

struct Inner {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl LogFile {
    pub fn open(path: &Path) -> Option<LogFile> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok()?;
        }
        let mut inner = Inner { path: path.to_path_buf(), file: None, size: 0 };
        inner.reopen();
        inner.file.is_some().then(|| LogFile(Arc::new(Mutex::new(inner))))
    }
}

impl Inner {
    fn reopen(&mut self) {
        self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        self.size = self.file.as_ref().and_then(|f| f.metadata().ok()).map_or(0, |m| m.len());
    }

    fn rotate(&mut self) {
        self.file = None;
        let old = self.path.with_extension("log.1");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&self.path, &old);
        self.reopen();
    }
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.0.lock().unwrap();
        if inner.size + buf.len() as u64 > MAX {
            inner.rotate();
        }
        // Lost lines are better than a daemon that stops on a full disk
        if let Some(f) = inner.file.as_mut()
            && f.write_all(buf).is_ok()
        {
            inner.size += buf.len() as u64;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_past_the_limit() {
        let dir = std::env::temp_dir().join(format!("retail-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("retaild.log");
        let mut log = LogFile::open(&path).unwrap();
        let line = vec![b'x'; 4096];
        for _ in 0..(MAX / 4096 + 10) {
            log.write_all(&line).unwrap();
        }
        let now = std::fs::metadata(&path).unwrap().len();
        let old = std::fs::metadata(path.with_extension("log.1")).unwrap().len();
        assert!(now <= MAX && old <= MAX && now > 0 && old > 0, "{now} {old}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
