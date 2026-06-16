// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it } from "vitest";
import { RateLimiter } from "../src/rateLimit.js";

describe("RateLimiter", () => {
  it("allows up to the limit, then blocks within the window", () => {
    const now = 1_000_000;
    const rl = new RateLimiter(3, 60_000, () => now);
    expect(rl.take("k").allowed).toBe(true); // 1
    expect(rl.take("k").allowed).toBe(true); // 2
    const third = rl.take("k"); // 3
    expect(third.allowed).toBe(true);
    expect(third.remaining).toBe(0);
    const fourth = rl.take("k"); // over
    expect(fourth.allowed).toBe(false);
    expect(fourth.retryAfterSec).toBeGreaterThan(0);
  });

  it("resets after the window elapses", () => {
    let now = 0;
    const rl = new RateLimiter(1, 1000, () => now);
    expect(rl.take("k").allowed).toBe(true);
    expect(rl.take("k").allowed).toBe(false);
    now = 1001;
    expect(rl.take("k").allowed).toBe(true);
  });

  it("tracks keys independently", () => {
    const now = 0;
    const rl = new RateLimiter(1, 1000, () => now);
    expect(rl.take("a").allowed).toBe(true);
    expect(rl.take("b").allowed).toBe(true);
    expect(rl.take("a").allowed).toBe(false);
  });

  it("rejects invalid construction", () => {
    expect(() => new RateLimiter(0, 1000)).toThrow();
    expect(() => new RateLimiter(1, 0)).toThrow();
    expect(() => new RateLimiter(1.5, 1000)).toThrow();
  });

  it("peek does not consume allowance", () => {
    const now = 0;
    const rl = new RateLimiter(1, 1000, () => now);
    expect(rl.peek("k").allowed).toBe(true);
    expect(rl.peek("k").allowed).toBe(true); // still allowed — peek did not consume
    expect(rl.take("k").allowed).toBe(true);
    expect(rl.peek("k").allowed).toBe(false); // now consumed
  });

  it("takeAll consumes nothing when one key is over the limit (no quota burn)", () => {
    let now = 0;
    const rl = new RateLimiter(2, 1000, () => now);
    // Exhaust the IP key only.
    expect(rl.take("ip").allowed).toBe(true);
    expect(rl.take("ip").allowed).toBe(true);
    // takeAll(webid, ip) is blocked by ip — and must NOT burn the webid allowance.
    expect(rl.takeAll(["webid", "ip"]).allowed).toBe(false);
    expect(rl.takeAll(["webid", "ip"]).allowed).toBe(false);
    // The webid key is still fully available once the IP window resets.
    now = 1001;
    expect(rl.takeAll(["webid", "ip"]).allowed).toBe(true);
    // webid consumed exactly once (limit 2 → one more allowed, then blocked).
    expect(rl.take("webid").allowed).toBe(true);
    expect(rl.peek("webid").allowed).toBe(false);
  });

  it("takeAll consumes one unit from each key when all are allowed", () => {
    const now = 0;
    const rl = new RateLimiter(1, 1000, () => now);
    expect(rl.takeAll(["a", "b"]).allowed).toBe(true);
    expect(rl.peek("a").allowed).toBe(false);
    expect(rl.peek("b").allowed).toBe(false);
  });
});
