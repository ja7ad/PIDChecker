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


}