//! Upload limit: keeps what this device sends under its line's upload speed,
//! so the queue is not in the router, where a download fills it and every
//! packet behind waits (bufferbloat). Over the limit, big packets are dropped
//! and their TCP senders slow down; small ones (games, calls, ACKs, DNS) still
//! go, within a bounded debt.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// At most this size (IP packet) counts as small
pub const SMALL: usize = 300;

pub struct Limiter {
    /// Bytes per second, 0 when off
    rate: AtomicU64,
    bucket: Mutex<Bucket>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Default for Limiter {
    fn default() -> Self {
        Limiter {
            rate: AtomicU64::new(0),
            bucket: Mutex::new(Bucket {
                tokens: 0.0,
                last: Instant::now(),
            }),
        }
    }
}

impl Limiter {
    /// `None` or 0 turns it off
    pub fn set_mbit(&self, mbit: Option<u32>) {
        let rate = u64::from(mbit.unwrap_or(0)) * 1_000_000 / 8;
        self.rate.store(rate, Ordering::Relaxed);
        let mut b = self.bucket.lock().unwrap();
        *b = Bucket {
            tokens: burst(rate),
            last: Instant::now(),
        };
    }

    pub fn on(&self) -> bool {
        self.rate.load(Ordering::Relaxed) != 0
    }

    /// Whether a packet of `len` bytes may go now
    pub fn allow(&self, len: usize) -> bool {
        self.allow_at(len, Instant::now())
    }

    fn allow_at(&self, len: usize, now: Instant) -> bool {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return true;
        }
        let burst = burst(rate);
        let mut b = self.bucket.lock().unwrap();
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + dt * rate as f64).min(burst);
        let len = len as f64;
        let floor = if len <= SMALL as f64 {
            -burst / 2.0
        } else {
            0.0
        };
        if b.tokens - len >= floor {
            b.tokens -= len;
            true
        } else {
            false
        }
    }
}

/// About 30 ms at the rate, but room for a few full GSO bursts at low rates
fn burst(rate: u64) -> f64 {
    (rate as f64 * 0.03).max(4.0 * 65536.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn keeps_to_the_rate_and_lets_small_packets_through() {
        let l = Limiter::default();
        assert!(l.allow(1500));
        l.set_mbit(Some(80)); // 10 MB/s
        let t0 = Instant::now();
        // One second of 1500-byte packets offered at twice the rate
        let mut sent = 0usize;
        for i in 0..13_333 {
            if l.allow_at(1500, t0 + Duration::from_micros(i * 75)) {
                sent += 1500;
            }
        }
        let limit = 10_000_000.0 + burst(10_000_000);
        assert!(
            sent as f64 <= limit && sent as f64 > 0.9 * 10_000_000.0,
            "{sent}"
        );
        // Bulk is refused now, a game's packet is not
        let later = t0 + Duration::from_secs(1);
        assert!((0..10).filter(|_| l.allow_at(1500, later)).count() <= 1);
        assert!(l.allow_at(120, later));
        // ...but small packets cannot run up an endless debt
        let flood = (0..100_000).filter(|_| l.allow_at(120, later)).count();
        assert!(flood * 120 <= burst(10_000_000) as usize, "{flood}");
        l.set_mbit(None);
        assert!(!l.on() && l.allow(1500));
    }
}
