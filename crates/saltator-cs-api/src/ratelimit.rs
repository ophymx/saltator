//! Token-bucket rate limiting for the abusable CS endpoints (spec "Rate
//! limiting": 429 `M_LIMIT_EXCEEDED` with `retry_after_ms`).
//!
//! Buckets are in node-local memory: each node enforces independently,
//! so a cluster's effective limit scales with node count — acceptable
//! for an abuse brake, and it keeps the hot path off the shard log.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// The limited endpoint classes; part of the bucket key so classes don't
/// share budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Login,
    Registration,
    Message,
}

/// Per-class sustained rates (events/second) and bursts. Node-local.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub message_rate: f64,
    pub message_burst: u32,
    pub login_rate: f64,
    pub login_burst: u32,
    pub registration_rate: f64,
    pub registration_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        // Synapse-shaped defaults, slightly more forgiving on messages.
        Self {
            enabled: true,
            message_rate: 1.0,
            message_burst: 20,
            login_rate: 0.17,
            login_burst: 5,
            registration_rate: 0.17,
            registration_burst: 5,
        }
    }
}

impl RateLimitConfig {
    /// No limits — test harnesses and Complement runs.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Keep the table bounded: past this size, refilled-to-full (idle)
/// buckets are dropped before inserting new ones.
const PRUNE_ABOVE: usize = 10_000;

#[derive(Default)]
pub(crate) struct RateLimiter {
    buckets: Mutex<HashMap<(Kind, String), Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one token from `(kind, key)`'s bucket; `Err(retry_after_ms)`
    /// when drained.
    pub fn check(&self, cfg: &RateLimitConfig, kind: Kind, key: &str) -> Result<(), u64> {
        if !cfg.enabled {
            return Ok(());
        }
        let (rate, burst) = match kind {
            Kind::Login => (cfg.login_rate, cfg.login_burst),
            Kind::Registration => (cfg.registration_rate, cfg.registration_burst),
            Kind::Message => (cfg.message_rate, cfg.message_burst),
        };
        let (rate, burst) = (rate.max(f64::MIN_POSITIVE), f64::from(burst.max(1)));

        let mut buckets = self.buckets.lock().expect("rate limiter poisoned");
        let now = Instant::now();
        if buckets.len() > PRUNE_ABOVE {
            buckets.retain(|(k, _), b| {
                let (rate, burst) = match k {
                    Kind::Login => (cfg.login_rate, f64::from(cfg.login_burst)),
                    Kind::Registration => {
                        (cfg.registration_rate, f64::from(cfg.registration_burst))
                    }
                    Kind::Message => (cfg.message_rate, f64::from(cfg.message_burst)),
                };
                b.tokens + now.duration_since(b.last).as_secs_f64() * rate < burst
            });
        }
        let bucket = buckets.entry((kind, key.to_owned())).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        bucket.tokens =
            (bucket.tokens + now.duration_since(bucket.last).as_secs_f64() * rate).min(burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - bucket.tokens) / rate * 1000.0).ceil() as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let limiter = RateLimiter::new();
        let cfg = RateLimitConfig {
            enabled: true,
            message_rate: 1000.0,
            message_burst: 2,
            ..RateLimitConfig::default()
        };
        assert!(limiter.check(&cfg, Kind::Message, "@a:x").is_ok());
        assert!(limiter.check(&cfg, Kind::Message, "@a:x").is_ok());
        let retry = limiter.check(&cfg, Kind::Message, "@a:x").unwrap_err();
        assert!(retry >= 1, "{retry}");
        // Distinct keys and classes have their own buckets.
        assert!(limiter.check(&cfg, Kind::Message, "@b:x").is_ok());
        assert!(limiter.check(&cfg, Kind::Login, "@a:x").is_ok());
        // At 1000/s the bucket refills within a few ms.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.check(&cfg, Kind::Message, "@a:x").is_ok());
    }

    #[test]
    fn disabled_never_limits() {
        let limiter = RateLimiter::new();
        let cfg = RateLimitConfig::disabled();
        for _ in 0..100 {
            assert!(limiter.check(&cfg, Kind::Registration, "").is_ok());
        }
    }
}
