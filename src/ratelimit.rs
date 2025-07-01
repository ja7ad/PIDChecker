//! Per-client rate limiting using GCRA (the generic cell rate algorithm, an
//! exact token bucket without background refills).
//!
//! Clients are identified by API key when one is presented, otherwise by IP.
//! Responses carry the IETF `RateLimit-Limit`, `RateLimit-Remaining` and
//! `RateLimit-Reset` headers; rejected requests get `429` with `Retry-After`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub per_minute: u32,
    pub burst: u32,
}

impl Quota {
    fn interval(&self) -> Duration {
        Duration::from_secs_f64(60.0 / self.per_minute.max(1) as f64)
    }
    fn tolerance(&self) -> Duration {
        self.interval() * self.burst.max(1).saturating_sub(1)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    /// Seconds until the bucket is full again.
    pub reset_secs: u64,
    /// Seconds to wait before retrying (only when rejected).
    pub retry_after_secs: u64,
}

pub struct RateLimiter {
    /// Theoretical arrival time per client.
    state: Mutex<HashMap<String, Instant>>,
    last_sweep: Mutex<Instant>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self { state: Mutex::new(HashMap::new()), last_sweep: Mutex::new(Instant::now()) }
    }
}

impl RateLimiter {
    pub fn check(&self, client: &str, quota: Quota) -> Decision {
        self.check_at(client, quota, Instant::now())
    }

    fn check_at(&self, client: &str, quota: Quota, now: Instant) -> Decision {
        self.sweep(now);
        let t = quota.interval();
        let tau = quota.tolerance();
        let mut state = self.state.lock();
        let tat = state.get(client).copied().unwrap_or(now).max(now);
        let ahead = tat - now;
        if ahead > tau {
            let retry = ahead - tau;
            return Decision {
                allowed: false,
                limit: quota.burst,
                remaining: 0,
                reset_secs: ahead.as_secs_f64().ceil() as u64,
                retry_after_secs: retry.as_secs_f64().ceil().max(1.0) as u64,
            };
        }
        let new_tat = tat + t;
        state.insert(client.to_string(), new_tat);
        let used = (new_tat - now).as_secs_f64() / t.as_secs_f64();
        Decision {
            allowed: true,
            limit: quota.burst,
            remaining: (quota.burst as f64 - used).floor().max(0.0) as u32,
            reset_secs: (new_tat - now).as_secs_f64().ceil() as u64,
            retry_after_secs: 0,
        }
    }

    /// Drop idle clients once a minute so the map cannot grow unbounded.
    fn sweep(&self, now: Instant) {
        let mut last = self.last_sweep.lock();
        if now.duration_since(*last) < Duration::from_secs(60) {
            return;
        }
        *last = now;
        self.state.lock().retain(|_, tat| *tat > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let rl = RateLimiter::default();
        let q = Quota { per_minute: 60, burst: 3 };
        let t0 = Instant::now();
        for i in 0..3 {
            let d = rl.check_at("a", q, t0);
            assert!(d.allowed, "request {i}");
            assert_eq!(d.remaining, 2 - i);
        }
        let d = rl.check_at("a", q, t0);
        assert!(!d.allowed);
        assert_eq!(d.retry_after_secs, 1);
        // Another client is unaffected.
        assert!(rl.check_at("b", q, t0).allowed);
        // One interval later one token is back.
        assert!(rl.check_at("a", q, t0 + Duration::from_secs(1)).allowed);
        assert!(!rl.check_at("a", q, t0 + Duration::from_secs(1)).allowed);
    }
}
