//! IP-based rate limiting for authentication attempts.
//!
//! This module provides protection against brute-force attacks by tracking
//! failed authentication attempts per IP address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::error::{AuthError, AuthResult};

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum failed attempts before lockout (default: 5)
    pub max_attempts: u32,

    /// Time window for counting attempts (default: 60 seconds)
    pub window_duration: Duration,

    /// How long to lock out after exceeding max attempts (default: 300 seconds)
    pub lockout_duration: Duration,

    /// Maximum number of IPs to track (prevents memory exhaustion)
    pub max_tracked_ips: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window_duration: Duration::from_secs(60),
            lockout_duration: Duration::from_secs(300),
            max_tracked_ips: 10000,
        }
    }
}

impl RateLimiterConfig {
    /// Create a new configuration with custom max attempts.
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max;
        self
    }

    /// Set the time window for counting attempts.
    pub fn with_window(mut self, duration: Duration) -> Self {
        self.window_duration = duration;
        self
    }

    /// Set the lockout duration.
    pub fn with_lockout(mut self, duration: Duration) -> Self {
        self.lockout_duration = duration;
        self
    }

    /// Set the maximum number of tracked IPs.
    pub fn with_max_tracked(mut self, max: usize) -> Self {
        self.max_tracked_ips = max;
        self
    }
}

/// Tracking data for a single IP address.
#[derive(Debug, Clone)]
struct IpRecord {
    /// Number of failed attempts in current window
    attempts: u32,
    /// When the current window started
    window_start: Instant,
    /// When lockout started (if any)
    lockout_start: Option<Instant>,
}

impl IpRecord {
    fn new() -> Self {
        Self {
            attempts: 0,
            window_start: Instant::now(),
            lockout_start: None,
        }
    }
}

/// IP-based rate limiter for authentication.
///
/// Thread-safe implementation using `RwLock`.
///
/// # Example
///
/// ```rust
/// use atauth::rate_limit::{RateLimiter, RateLimiterConfig};
/// use std::net::IpAddr;
///
/// let config = RateLimiterConfig::default()
///     .with_max_attempts(3)
///     .with_lockout(std::time::Duration::from_secs(600));
///
/// let limiter = RateLimiter::new(config);
///
/// // Check if IP is allowed to attempt auth
/// let ip: IpAddr = "192.168.1.1".parse().unwrap();
/// if limiter.check(&ip).is_ok() {
///     // Proceed with authentication
///     // On failure:
///     limiter.record_failure(&ip);
/// }
/// ```
pub struct RateLimiter {
    config: RateLimiterConfig,
    records: Arc<RwLock<HashMap<IpAddr, IpRecord>>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a rate limiter with default configuration.
    pub fn default_config() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Check if an IP is allowed to attempt authentication.
    ///
    /// Returns `Ok(())` if allowed, or `Err(AuthError::RateLimited)` with
    /// the number of seconds remaining in the lockout.
    pub fn check(&self, ip: &IpAddr) -> AuthResult<()> {
        let records = self.records.read().unwrap();

        if let Some(record) = records.get(ip) {
            // Check if in lockout
            if let Some(lockout_start) = record.lockout_start {
                let elapsed = lockout_start.elapsed();
                if elapsed < self.config.lockout_duration {
                    let remaining = self.config.lockout_duration - elapsed;
                    return Err(AuthError::RateLimited(remaining.as_secs()));
                }
            }
        }

        Ok(())
    }

    /// Record a failed authentication attempt for an IP.
    pub fn record_failure(&self, ip: &IpAddr) {
        let mut records = self.records.write().unwrap();

        // Cleanup if at capacity
        if records.len() >= self.config.max_tracked_ips {
            self.cleanup_internal(&mut records);
        }

        let record = records.entry(*ip).or_insert_with(IpRecord::new);

        // Reset window if expired
        if record.window_start.elapsed() >= self.config.window_duration {
            record.attempts = 0;
            record.window_start = Instant::now();
            record.lockout_start = None;
        }

        record.attempts += 1;

        // Apply lockout if exceeded
        if record.attempts >= self.config.max_attempts {
            record.lockout_start = Some(Instant::now());
            tracing::warn!(
                ip = %ip,
                attempts = record.attempts,
                "Rate limit exceeded, IP locked out"
            );
        }
    }

    /// Record a successful authentication, clearing the failure count.
    pub fn record_success(&self, ip: &IpAddr) {
        let mut records = self.records.write().unwrap();
        records.remove(ip);
    }

    /// Clear rate limiting for a specific IP.
    pub fn clear(&self, ip: &IpAddr) {
        let mut records = self.records.write().unwrap();
        records.remove(ip);
    }

    /// Get the remaining lockout time for an IP in seconds.
    ///
    /// Returns `None` if not locked out or `Some(seconds)` remaining.
    pub fn lockout_remaining(&self, ip: &IpAddr) -> Option<u64> {
        let records = self.records.read().unwrap();

        records.get(ip).and_then(|record| {
            record.lockout_start.and_then(|start| {
                let elapsed = start.elapsed();
                if elapsed < self.config.lockout_duration {
                    Some((self.config.lockout_duration - elapsed).as_secs())
                } else {
                    None
                }
            })
        })
    }

    /// Get the number of failed attempts for an IP.
    pub fn attempt_count(&self, ip: &IpAddr) -> u32 {
        let records = self.records.read().unwrap();
        records.get(ip).map(|r| r.attempts).unwrap_or(0)
    }

    /// Clean up expired records to free memory.
    pub fn cleanup(&self) {
        let mut records = self.records.write().unwrap();
        self.cleanup_internal(&mut records);
    }

    /// Internal cleanup helper.
    fn cleanup_internal(&self, records: &mut HashMap<IpAddr, IpRecord>) {
        let now = Instant::now();
        let window = self.config.window_duration;
        let lockout = self.config.lockout_duration;

        records.retain(|_, record| {
            // Keep if still in active window
            if record.window_start.elapsed() < window {
                return true;
            }

            // Keep if still locked out
            if let Some(start) = record.lockout_start {
                if now.duration_since(start) < lockout {
                    return true;
                }
            }

            false
        });
    }

    /// Get current number of tracked IPs.
    pub fn tracked_count(&self) -> usize {
        self.records.read().unwrap().len()
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            records: Arc::clone(&self.records),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_basic_rate_limiting() {
        let config = RateLimiterConfig::default()
            .with_max_attempts(3)
            .with_window(Duration::from_secs(60))
            .with_lockout(Duration::from_secs(1));

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 2 attempts should be fine
        assert!(limiter.check(&ip).is_ok());
        limiter.record_failure(&ip);
        assert!(limiter.check(&ip).is_ok());
        limiter.record_failure(&ip);

        // Third attempt triggers lockout
        limiter.record_failure(&ip);

        // Should now be rate limited
        assert!(matches!(limiter.check(&ip), Err(AuthError::RateLimited(_))));
    }

    #[test]
    fn test_lockout_expires() {
        let config = RateLimiterConfig::default()
            .with_max_attempts(2)
            .with_lockout(Duration::from_millis(100));

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Trigger lockout
        limiter.record_failure(&ip);
        limiter.record_failure(&ip);

        assert!(limiter.check(&ip).is_err());

        // Wait for lockout to expire
        sleep(Duration::from_millis(150));

        assert!(limiter.check(&ip).is_ok());
    }

    #[test]
    fn test_success_clears_record() {
        let limiter = RateLimiter::new(RateLimiterConfig::default().with_max_attempts(3));
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        limiter.record_failure(&ip);
        limiter.record_failure(&ip);
        assert_eq!(limiter.attempt_count(&ip), 2);

        limiter.record_success(&ip);
        assert_eq!(limiter.attempt_count(&ip), 0);
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = RateLimiter::new(RateLimiterConfig::default().with_max_attempts(2));
        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();

        // Lock out ip1
        limiter.record_failure(&ip1);
        limiter.record_failure(&ip1);

        // ip1 should be locked
        assert!(limiter.check(&ip1).is_err());

        // ip2 should still be allowed
        assert!(limiter.check(&ip2).is_ok());
    }
}
