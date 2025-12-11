/**
 * Rate Limiting Middleware
 *
 * IP-based rate limiting to protect against brute force and DoS attacks.
 */

import { Request, Response, NextFunction } from 'express';

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimitConfig {
  windowMs: number;      // Time window in milliseconds
  maxRequests: number;   // Max requests per window
  maxTrackedIps: number; // Max IPs to track (DoS protection)
}

const DEFAULT_CONFIG: RateLimitConfig = {
  windowMs: 60 * 1000,   // 1 minute
  maxRequests: 30,       // 30 requests per minute
  maxTrackedIps: 10000,  // Track up to 10k IPs
};

/**
 * In-memory rate limit store.
 * For production with multiple instances, use Redis instead.
 */
class RateLimitStore {
  private entries = new Map<string, RateLimitEntry>();
  private maxEntries: number;

  constructor(maxEntries: number) {
    this.maxEntries = maxEntries;
  }

  /**
   * Check and increment request count for an IP.
   * Returns remaining requests, or -1 if rate limited.
   */
  check(ip: string, windowMs: number, maxRequests: number): { remaining: number; resetAt: number } {
    const now = Date.now();
    const entry = this.entries.get(ip);

    // Clean up expired entry
    if (entry && entry.resetAt <= now) {
      this.entries.delete(ip);
    }

    const current = this.entries.get(ip);

    if (!current) {
      // New entry - check if we're at capacity
      if (this.entries.size >= this.maxEntries) {
        // Evict oldest entries (10% of max)
        this.evictOldest(Math.floor(this.maxEntries * 0.1));
      }

      const resetAt = now + windowMs;
      this.entries.set(ip, { count: 1, resetAt });
      return { remaining: maxRequests - 1, resetAt };
    }

    // Increment existing entry
    current.count++;

    if (current.count > maxRequests) {
      return { remaining: -1, resetAt: current.resetAt };
    }

    return { remaining: maxRequests - current.count, resetAt: current.resetAt };
  }

  /**
   * Evict the oldest entries.
   */
  private evictOldest(count: number): void {
    const entries = Array.from(this.entries.entries())
      .sort((a, b) => a[1].resetAt - b[1].resetAt)
      .slice(0, count);

    for (const [ip] of entries) {
      this.entries.delete(ip);
    }
  }

  /**
   * Periodic cleanup of expired entries.
   */
  cleanup(): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [ip, entry] of this.entries) {
      if (entry.resetAt <= now) {
        this.entries.delete(ip);
        cleaned++;
      }
    }

    return cleaned;
  }
}

// Global store instance
const store = new RateLimitStore(DEFAULT_CONFIG.maxTrackedIps);

// Cleanup every 5 minutes
setInterval(() => store.cleanup(), 5 * 60 * 1000);

/**
 * Get client IP address from request.
 * Handles proxied requests via X-Forwarded-For header.
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = (typeof forwarded === 'string' ? forwarded : forwarded[0]).split(',');
    return ips[0].trim();
  }
  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * Create rate limiting middleware.
 *
 * @param config - Rate limit configuration
 * @returns Express middleware
 */
export function rateLimit(config: Partial<RateLimitConfig> = {}): (req: Request, res: Response, next: NextFunction) => void {
  const { windowMs, maxRequests } = { ...DEFAULT_CONFIG, ...config };

  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = getClientIp(req);
    const { remaining, resetAt } = store.check(ip, windowMs, maxRequests);

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, remaining));
    res.setHeader('X-RateLimit-Reset', Math.ceil(resetAt / 1000));

    if (remaining < 0) {
      const retryAfter = Math.ceil((resetAt - Date.now()) / 1000);
      res.setHeader('Retry-After', retryAfter);

      res.status(429).json({
        error: 'rate_limited',
        message: 'Too many requests. Please try again later.',
        retry_after: retryAfter,
      });
      return;
    }

    next();
  };
}

/**
 * Stricter rate limit for authentication endpoints.
 */
export const authRateLimit = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  maxRequests: 10,       // 10 auth attempts per minute
});

/**
 * Standard rate limit for general API endpoints.
 */
export const apiRateLimit = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  maxRequests: 60,       // 60 requests per minute
});

/**
 * Strict rate limit for admin endpoints.
 */
export const adminRateLimit = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  maxRequests: 20,       // 20 requests per minute
});
