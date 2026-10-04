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
        if self.wait_ms(key) > 0 {
            return false;
        }
        self.hit(key);
        true
    }

    /// How long until `key` may act again (0 = now). Counts nothing.
    pub fn wait_ms(&self, key: &str) -> i64 {
        let now = now_ms();
        let mut hits = self.hits.lock();
        let Some(list) = hits.get_mut(key) else {
            return 0;
        };
        list.retain(|t| now - *t < self.window_ms);
        if list.len() < self.max {
            return 0;
        }
        // The oldest action that still counts leaves the window first.
        list.first()
            .map_or(0, |oldest| self.window_ms - (now - oldest))
    }

    /// Counts an action without checking the limit.
    pub fn hit(&self, key: &str) {
        let now = now_ms();
        let mut hits = self.hits.lock();
        if hits.len() > PURGE_AT {
            hits.retain(|_, list| list.last().is_some_and(|t| now - *t < self.window_ms));
        }
        let list = hits.entry(key.to_string()).or_default();
        list.retain(|t| now - *t < self.window_ms);
        list.push(now);
    }
}

/// Emails with a verification code, per address and per IP.
pub const CODE_EMAILS_PER_MINUTE: usize = 1;
pub const CODE_EMAILS_PER_HOUR: usize = 5;
pub const CODE_EMAILS_PER_IP_HOUR: usize = 30;

/// Limits on sending verification codes, so nobody can flood a mailbox (or
/// the server's email quota): one a minute and five an hour per address,
/// thirty an hour per IP. Every request counts, whether or not the account
/// exists, so the answer reveals nothing.
pub struct CodeEmailLimiter {
    per_minute: RateLimiter,
    per_hour: RateLimiter,
    per_ip: RateLimiter,
}

impl Default for CodeEmailLimiter {
    fn default() -> Self {
        Self {
            per_minute: RateLimiter::new(CODE_EMAILS_PER_MINUTE, 60_000),
            per_hour: RateLimiter::new(CODE_EMAILS_PER_HOUR, 3_600_000),
            per_ip: RateLimiter::new(CODE_EMAILS_PER_IP_HOUR, 3_600_000),
        }
    }
}

impl CodeEmailLimiter {
    /// Counts a code email to `email` (from `ip`, if known). `Err` with the
    /// milliseconds to wait when a limit was reached (then nothing counts).
    pub fn try_send(&self, email: &str, ip: Option<IpAddr>) -> Result<(), i64> {
        let email = email.trim().to_lowercase();
        let ip = ip.map(|ip| ip.to_string());
        let wait = self
            .per_minute
            .wait_ms(&email)
            .max(self.per_hour.wait_ms(&email))
            .max(ip.as_deref().map_or(0, |ip| self.per_ip.wait_ms(ip)));
        if wait > 0 {
            return Err(wait);
        }
        self.per_minute.hit(&email);
        self.per_hour.hit(&email);
        if let Some(ip) = &ip {
            self.per_ip.hit(ip);
        }
        Ok(())
    }

    /// Forgets every count (tests).
    pub fn reset(&self) {
        for l in [&self.per_minute, &self.per_hour, &self.per_ip] {
            l.hits.lock().clear();
        }
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
        assert_eq!(l.wait_ms("a"), 0);
        assert!(l.allow("a"));
        assert!(l.allow("a"));
        assert!(!l.allow("a"));
        let wait = l.wait_ms("a");
        assert!(wait > 59_000 && wait <= 60_000, "{wait}");
        assert!(l.allow("b"));
    }

    #[test]
    fn code_emails() {
        let l = CodeEmailLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(l.try_send("Ana@example.com", Some(ip)).is_ok());
        // Once a minute per address, whatever the case or the IP.
        let wait = l.try_send("ana@example.com ", None).unwrap_err();
        assert!(wait > 0 && wait <= 60_000, "{wait}");
        // Other addresses from the same IP, up to the IP's limit.
        for i in 1..CODE_EMAILS_PER_IP_HOUR {
            assert!(l.try_send(&format!("u{i}@example.com"), Some(ip)).is_ok());
        }
        assert!(l.try_send("new@example.com", Some(ip)).is_err());
        assert!(l.try_send("new@example.com", None).is_ok());
    }
}
