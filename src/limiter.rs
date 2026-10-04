//! Limit on failed sign-in attempts, per email and per IP.
//!
//! - Per email: slows down whoever tries passwords against one account.
//! - Per IP: slows down whoever tries many accounts from the same place.
//!
//! A wrong password and a wrong two-factor code both count as failures.
//! Everything lives in memory: it is forgotten on restart.

use std::collections::HashMap;
use std::net::IpAddr;

use parking_lot::Mutex;
use termoak_core::time::now_ms;

/// Window in which failures are counted.
pub const WINDOW_MS: i64 = 10 * 60 * 1000;
/// Failures allowed per email in the window.
pub const MAX_PER_EMAIL: usize = 10;
/// Failures allowed per IP in the window.
pub const MAX_PER_IP: usize = 30;
/// Number of entries above which expired ones are purged.
const PURGE_AT: usize = 10_000;

#[derive(Default)]
pub struct LoginLimiter {
    by_email: Mutex<HashMap<String, Vec<i64>>>,
    by_ip: Mutex<HashMap<IpAddr, Vec<i64>>>,
}

fn blocked<K: std::hash::Hash + Eq + Clone>(
    map: &Mutex<HashMap<K, Vec<i64>>>,
    key: &K,
    max: usize,
    now: i64,
) -> bool {
    let mut map = map.lock();
    let Some(list) = map.get_mut(key) else {
        return false;
    };
    list.retain(|t| now - *t < WINDOW_MS);
    let blocked = list.len() >= max;
    if list.is_empty() {
        map.remove(key);
    }
    blocked
}

fn note<K: std::hash::Hash + Eq>(map: &Mutex<HashMap<K, Vec<i64>>>, key: K, now: i64) {
    let mut map = map.lock();
    // Purge so that random keys cannot grow the map without bound.
    if map.len() > PURGE_AT {
        map.retain(|_, list| list.last().is_some_and(|t| now - *t < WINDOW_MS));
    }
    map.entry(key).or_default().push(now);
}

impl LoginLimiter {
    /// Is this attempt blocked?
    pub fn is_blocked(&self, email: &str, ip: Option<IpAddr>) -> bool {
        let now = now_ms();
        let email = email.trim().to_lowercase();
        blocked(&self.by_email, &email, MAX_PER_EMAIL, now)
            || ip.is_some_and(|ip| blocked(&self.by_ip, &ip, MAX_PER_IP, now))
    }

    /// Records a failure.
    pub fn failure(&self, email: &str, ip: Option<IpAddr>) {
        let now = now_ms();
        note(&self.by_email, email.trim().to_lowercase(), now);
        if let Some(ip) = ip {
            note(&self.by_ip, ip, now);
        }
    }

    /// Successful sign-in: forgets that email's failures (not the IP's, so
    /// having one valid account gives no advantage).
    pub fn success(&self, email: &str) {
        self.by_email.lock().remove(&email.trim().to_lowercase());
    }
}

/// At most `max` actions per key in a sliding window (calls that cost
/// something outside, such as checking an AI key with its provider).
pub struct RateLimiter {
    max: usize,
    window_ms: i64,
    hits: Mutex<HashMap<String, Vec<i64>>>,
}

impl RateLimiter {
    pub fn new(max: usize, window_ms: i64) -> Self {
        Self {
            max,
            window_ms,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Counts an action; `false` if the limit was already reached.
    pub fn allow(&self, key: &str) -> bool {
        let now = now_ms();
        let mut hits = self.hits.lock();
        if hits.len() > PURGE_AT {
            hits.retain(|_, list| list.last().is_some_and(|t| now - *t < self.window_ms));
        }
        let list = hits.entry(key.to_string()).or_default();
        list.retain(|t| now - *t < self.window_ms);
        if list.len() >= self.max {
            return false;
        }
        list.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_by_email_and_ip() {
        let l = LoginLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..MAX_PER_EMAIL {
            assert!(!l.is_blocked("Ana@Example.com", Some(ip)));
            l.failure("ana@example.com", Some(ip));
        }
        // The account is blocked from any IP.
        assert!(l.is_blocked("ana@example.com", Some(other)));
        l.success("ana@example.com");
        assert!(!l.is_blocked("ana@example.com", Some(other)));

        // Many different emails from the same IP block the IP.
        for i in 0..MAX_PER_IP {
            l.failure(&format!("u{i}@example.com"), Some(ip));
        }
        assert!(l.is_blocked("new@example.com", Some(ip)));
        assert!(!l.is_blocked("new@example.com", Some(other)));
        assert!(!l.is_blocked("new@example.com", None));
    }

    #[test]
    fn rate_limiter() {
        let l = RateLimiter::new(2, 60_000);
        assert!(l.allow("a"));
        assert!(l.allow("a"));
        assert!(!l.allow("a"));
        assert!(l.allow("b"));
    }
}
