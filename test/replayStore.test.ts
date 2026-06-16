// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it } from "vitest";
import { InProcessReplayStore } from "../src/replayStore.js";

describe("InProcessReplayStore", () => {
  it("accepts a fresh jti and rejects a repeat within the TTL", () => {
    const now = 0;
    const store = new InProcessReplayStore(() => now);
    expect(store.mark("jti-1", 300)).toBe("new");
    expect(store.mark("jti-1", 300)).toBe("replay");
    expect(store.mark("jti-2", 300)).toBe("new");
  });

  it("forgets a jti after its TTL so it is accepted again", () => {
    let now = 0;
    const store = new InProcessReplayStore(() => now);
    expect(store.mark("jti", 10)).toBe("new");
    now = 10_001; // past the 10s TTL
    expect(store.mark("jti", 10)).toBe("new");
  });
});
