//! Traffic counted across sessions and restarts, kept in `usage.json`.
//! WireGuard's counters start over with every tunnel, so the totals grow by
//! what each sample adds since the previous one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use retail_proto::Key;
use retail_proto::api::{PeerStatus, UsageTotal};
use serde::{Deserialize, Serialize};

/// Devices remembered; past it the least used is forgotten (the overall
/// total keeps its bytes)
const MAX_DEVICES: usize = 512;

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    since: i64,
    tx: u64,
    rx: u64,
    #[serde(default)]
    devices: HashMap<Key, (u64, u64)>,
    /// Seconds connected
    #[serde(default)]
    connected: u64,
}

#[derive(Default)]
struct Inner {
    saved: Saved,
    /// Counters at the last sample, per tunnel
    last: HashMap<Key, (u64, u64)>,
    /// The session's time counted up to here
    counted_to: Option<Instant>,
    dirty: bool,
}

pub struct Usage {
    path: PathBuf,
    inner: Mutex<Inner>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl Usage {
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join("usage.json");
        let mut saved: Saved = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if saved.since == 0 {
            saved.since = now();
        }
        Usage {
            path,
            inner: Mutex::new(Inner {
                saved,
                ..Default::default()
            }),
        }
    }

    /// Adds what the tunnels carried, and the time connected, since the last
    /// sample. Called only while a session runs.
    pub fn record(&self, peers: &[PeerStatus]) {
        let mut g = self.inner.lock().unwrap();
        let Inner {
            saved,
            last,
            counted_to,
            dirty,
        } = &mut *g;
        match *counted_to {
            None => *counted_to = Some(Instant::now()),
            Some(t) => {
                // Whole seconds, the rest carried to the next sample
                let secs = t.elapsed().as_secs();
                if secs > 0 {
                    saved.connected = saved.connected.saturating_add(secs);
                    *counted_to = Some(t + Duration::from_secs(secs));
                    *dirty = true;
                }
            }
        }
        last.retain(|k, _| peers.iter().any(|p| p.node_key == *k));
        for p in peers {
            let (tx0, rx0) = last
                .insert(p.node_key, (p.tx_bytes, p.rx_bytes))
                .unwrap_or_default();
            // Smaller than before: a new tunnel counting from zero
            let dtx = if p.tx_bytes >= tx0 {
                p.tx_bytes - tx0
            } else {
                p.tx_bytes
            };
            let drx = if p.rx_bytes >= rx0 {
                p.rx_bytes - rx0
            } else {
                p.rx_bytes
            };
            if dtx == 0 && drx == 0 {
                continue;
            }
            saved.tx = saved.tx.saturating_add(dtx);
            saved.rx = saved.rx.saturating_add(drx);
            let d = saved.devices.entry(p.node_key).or_default();
            d.0 = d.0.saturating_add(dtx);
            d.1 = d.1.saturating_add(drx);
            *dirty = true;
        }
        if saved.devices.len() > MAX_DEVICES
            && let Some(k) = saved
                .devices
                .iter()
                .min_by_key(|(_, (t, r))| t.saturating_add(*r))
                .map(|(k, _)| *k)
        {
            saved.devices.remove(&k);
        }
    }

    /// The session's tunnels are gone: the next ones count from zero
    pub fn end_session(&self) {
        let mut g = self.inner.lock().unwrap();
        g.last.clear();
        g.counted_to = None;
    }

    pub fn total(&self) -> UsageTotal {
        let g = self.inner.lock().unwrap();
        UsageTotal {
            since: g.saved.since,
            tx_bytes: g.saved.tx,
            rx_bytes: g.saved.rx,
            connected_secs: g.saved.connected,
        }
    }

    /// Fills in each peer's total
    pub fn fill(&self, peers: &mut [PeerStatus]) {
        let g = self.inner.lock().unwrap();
        for p in peers {
            let (tx, rx) = g
                .saved
                .devices
                .get(&p.node_key)
                .copied()
                .unwrap_or_default();
            p.total_tx_bytes = Some(tx);
            p.total_rx_bytes = Some(rx);
        }
    }

    pub fn save(&self) {
        let data = {
            let mut g = self.inner.lock().unwrap();
            if !g.dirty {
                return;
            }
            g.dirty = false;
            serde_json::to_vec(&g.saved).unwrap_or_default()
        };
        let tmp = self.path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, &self.path))
        {
            tracing::warn!("saving usage: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(key: u8, tx: u64, rx: u64) -> PeerStatus {
        serde_json::from_value(serde_json::json!({
            "hostname": "p", "ip": "100.64.0.2", "node_key": Key([key; 32]), "online": true, "endpoint": null,
            "candidates": [], "last_handshake_secs": null, "tx_bytes": tx, "rx_bytes": rx,
        }))
        .unwrap()
    }

    #[test]
    fn totals_survive_new_tunnels_and_restarts() {
        let dir = std::env::temp_dir().join(format!("retail-usage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let u = Usage::load(&dir);
        u.record(&[peer(1, 100, 1000), peer(2, 5, 5)]);
        u.record(&[peer(1, 150, 1500)]);
        // Peer 1's tunnel was replaced; peer 2 came back with a new one
        u.record(&[peer(1, 20, 30), peer(2, 7, 1)]);
        u.end_session();
        u.record(&[peer(1, 10, 10)]);
        let t = u.total();
        assert_eq!(
            (t.tx_bytes, t.rx_bytes),
            (150 + 20 + 10 + 5 + 7, 1500 + 30 + 10 + 5 + 1)
        );
        u.save();
        let again = Usage::load(&dir);
        let mut ps = [peer(1, 0, 0)];
        again.fill(&mut ps);
        assert_eq!(
            (ps[0].total_tx_bytes, ps[0].total_rx_bytes),
            (Some(180), Some(1540))
        );
        assert_eq!(again.total().since, t.since);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn connected_time_counts_sessions_only() {
        let dir = std::env::temp_dir().join(format!("retail-usage-time-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let u = Usage::load(&dir);
        u.record(&[]);
        std::thread::sleep(Duration::from_millis(1100));
        u.record(&[]);
        assert_eq!(u.total().connected_secs, 1);
        u.end_session();
        // Disconnected meanwhile: the next session starts counting afresh
        std::thread::sleep(Duration::from_millis(1100));
        u.record(&[]);
        assert_eq!(u.total().connected_secs, 1);
        u.save();
        assert_eq!(Usage::load(&dir).total().connected_secs, 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
