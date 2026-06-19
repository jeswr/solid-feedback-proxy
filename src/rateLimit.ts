// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// A simple fixed-window rate limiter keyed by an opaque string (the per-WebID and
// per-IP keys are derived by the handler). IN-MEMORY ONLY — adequate for a single
// serverless instance, but a Vercel deployment scales to MANY warm instances, so a
// determined abuser hitting different instances could exceed the per-key limit. For
// PRODUCTION-GRADE rate limiting use a SHARED store (Upstash Redis / Vercel KV) and
// swap the `RateLimiter` for that backend behind the same `take()` contract — see the
// README "Production hardening" note. This in-memory limiter is the floor, not the
// ceiling: it stops casual abuse and accidental loops within an instance for free.

/** The outcome of a rate-limit check. */
export interface RateLimitResult {
  /** Whether the request is allowed (under the limit). */
  readonly allowed: boolean;
  /** How many of the window's allowance remain after this request. */
  readonly remaining: number;
  /** Seconds until the window resets (for a `Retry-After` header on a 429). */
  readonly retryAfterSec: number;
}

interface Window {
  count: number;
  /** Epoch ms at which this window resets. */
  resetAt: number;
}

/** A fixed-window in-memory rate limiter. */
export class RateLimiter {
  private readonly windows = new Map<string, Window>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    /** Injectable clock for deterministic tests. */
    private readonly now: () => number = () => Date.now(),
  ) {
    if (limit <= 0 || !Number.isInteger(limit)) {
      throw new Error("RateLimiter limit must be a positive integer.");
    }
    if (windowMs <= 0) {
      throw new Error("RateLimiter windowMs must be positive.");
    }
  }

  /**
   * Count one request against `key`. Returns whether it is allowed and the remaining
   * allowance. A request that is over the limit is NOT counted further (so the window
   * does not keep extending) but is reported as not-allowed with a `retryAfterSec`.
   */
  take(key: string): RateLimitResult {
    const now = this.now();
    const existing = this.windows.get(key);
    if (existing === undefined || now >= existing.resetAt) {
      this.windows.set(key, { count: 1, resetAt: now + this.windowMs });
      this.sweep(now);
      return this.freshResult();
    }
    if (existing.count >= this.limit) {
      return this.overLimitResult(existing, now);
    }
    existing.count += 1;
    // `remaining` after incrementing to `count` equals `limit - count` — the same value
    // peek() reports for this pre-state via `limit - count - 1` before the increment.
    return this.underLimitResult(this.limit - existing.count, existing, now);
  }

  /**
   * Report whether `key` is currently under its limit WITHOUT consuming any allowance.
   * Used to check multiple keys together so a request blocked by one key does not burn
   * the other key's quota (roborev LOW).
   */
  peek(key: string): RateLimitResult {
    const now = this.now();
    const existing = this.windows.get(key);
    if (existing === undefined || now >= existing.resetAt) {
      return this.freshResult();
    }
    if (existing.count >= this.limit) {
      return this.overLimitResult(existing, now);
    }
    // Read-only: report the allowance that a subsequent take() WOULD leave (one consumed),
    // without mutating — `limit - count - 1` matches take()'s post-increment `limit - count`.
    return this.underLimitResult(this.limit - existing.count - 1, existing, now);
  }

  /** The result for a fresh / expired window: one allowed, a full window until reset. */
  private freshResult(): RateLimitResult {
    return { allowed: true, remaining: this.limit - 1, retryAfterSec: this.toSec(this.windowMs) };
  }

  /** The result for a key that is at/over its limit within the current window. */
  private overLimitResult(existing: Window, now: number): RateLimitResult {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSec: Math.max(1, this.toSec(existing.resetAt - now)),
    };
  }

  /** The result for a key still under its limit; `remaining` is computed by the caller. */
  private underLimitResult(remaining: number, existing: Window, now: number): RateLimitResult {
    return {
      allowed: true,
      remaining,
      retryAfterSec: Math.max(1, this.toSec(existing.resetAt - now)),
    };
  }

  /**
   * Atomically (within this instance) check ALL keys, and consume one unit from each
   * ONLY when every key is under its limit. If any key is over, NOTHING is consumed and
   * the blocking key's {@link RateLimitResult} (the one with the longest retry) is
   * returned — so a request blocked by the IP limit never burns the WebID allowance.
   */
  takeAll(keys: readonly string[]): RateLimitResult {
    const peeks = keys.map((k) => ({ k, r: this.peek(k) }));
    const blocked = peeks.filter((p) => !p.r.allowed);
    if (blocked.length > 0) {
      // Return the result with the longest retry-after (the tightest constraint).
      const worst = blocked.reduce((a, b) => (b.r.retryAfterSec > a.r.retryAfterSec ? b : a));
      return worst.r;
    }
    // All allowed → now consume each. Return the tightest remaining.
    const taken = keys.map((k) => this.take(k));
    return taken.reduce((a, b) => (b.remaining < a.remaining ? b : a));
  }

  /** Drop expired windows so the map does not grow unbounded across a long-lived instance. */
  private sweep(now: number): void {
    for (const [key, win] of this.windows) {
      if (now >= win.resetAt) {
        this.windows.delete(key);
      }
    }
  }

  private toSec(ms: number): number {
    return Math.ceil(ms / 1000);
  }
}
