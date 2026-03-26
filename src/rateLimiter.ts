/**
 * Client-side token bucket rate limiter.
 * Matches the MCP server's rateLimiter.ts pattern.
 */

import { DEFAULT_RATE_LIMIT_PER_MINUTE } from './config';

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
}

/**
 * Token bucket rate limiter with continuous refill.
 *
 * Default capacity is 100 requests/minute (configurable).
 * Tokens refill continuously based on elapsed time.
 */
export class RateLimiter {
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per millisecond
  private bucket: TokenBucket;

  constructor(requestsPerMinute: number = DEFAULT_RATE_LIMIT_PER_MINUTE) {
    this.capacity = requestsPerMinute;
    this.refillRate = this.capacity / 60000;
    this.bucket = {
      tokens: this.capacity,
      lastRefill: Date.now(),
    };
  }

  /**
   * Attempt to consume one token.
   * Returns whether the request is allowed and remaining capacity.
   */
  consume(): RateLimitResult {
    const now = Date.now();

    // Refill based on elapsed time
    const elapsed = now - this.bucket.lastRefill;
    const tokensToAdd = elapsed * this.refillRate;
    this.bucket.tokens = Math.min(this.capacity, this.bucket.tokens + tokensToAdd);
    this.bucket.lastRefill = now;

    // Try to consume
    if (this.bucket.tokens >= 1) {
      this.bucket.tokens -= 1;
      return { allowed: true, remaining: Math.floor(this.bucket.tokens) };
    }

    // Rate limited
    const tokensNeeded = 1 - this.bucket.tokens;
    const retryAfterMs = Math.ceil(tokensNeeded / this.refillRate);
    return { allowed: false, remaining: 0, retryAfterMs };
  }
}
