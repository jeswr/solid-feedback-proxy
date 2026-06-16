// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// DPoP-proof replay protection. `oauth4webapi` validates a proof's freshness + binding
// but does NOT remember which proofs it has seen — so within the RFC 9449 freshness
// window (≈300 s + tolerance) the SAME captured request could be replayed to create a
// duplicate issue. We close that by remembering each accepted proof's `jti` for the
// freshness window and rejecting a repeat (roborev MEDIUM).
//
// IN-MEMORY (per function instance) — same caveat as the rate limiter: a multi-instance
// Vercel deploy should back this with a shared TTL store (Upstash Redis / Vercel KV)
// behind the same `mark()` contract. Within an instance it is exact.

/** The replay-store contract: returns whether a jti is `new` (accept) or a `replay`. */
export interface ReplayStore {
  /**
   * Record `jti` and report whether it had already been seen within its TTL. A `new`
   * result means accept the proof; a `replay` means reject it.
   *
   * @param jti the DPoP proof's unique identifier
   * @param ttlSeconds how long to remember it (the proof's freshness window)
   */
  mark(jti: string, ttlSeconds: number): "new" | "replay";
}

interface Entry {
  /** Epoch ms at which this jti may be forgotten. */
  expiresAt: number;
}

/** A simple in-memory replay store with lazy TTL expiry. */
export class InProcessReplayStore implements ReplayStore {
  private readonly seen = new Map<string, Entry>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  mark(jti: string, ttlSeconds: number): "new" | "replay" {
    const now = this.now();
    const existing = this.seen.get(jti);
    if (existing !== undefined && now < existing.expiresAt) {
      return "replay";
    }
    this.seen.set(jti, { expiresAt: now + ttlSeconds * 1000 });
    this.sweep(now);
    return "new";
  }

  /** Drop expired entries so the map does not grow unbounded on a long-lived instance. */
  private sweep(now: number): void {
    for (const [key, entry] of this.seen) {
      if (now >= entry.expiresAt) {
        this.seen.delete(key);
      }
    }
  }
}
