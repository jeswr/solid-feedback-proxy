// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it } from "vitest";
import { corsHeaders } from "../src/cors.js";

const allowed = ["https://app.test", "https://pod-mail.test"];

describe("corsHeaders", () => {
  it("reflects an allowed origin (never a wildcard)", () => {
    const h = corsHeaders("https://app.test", allowed);
    expect(h["access-control-allow-origin"]).toBe("https://app.test");
    expect(h["access-control-allow-origin"]).not.toBe("*");
    expect(h["access-control-allow-headers"]).toContain("DPoP");
    expect(h["access-control-allow-headers"]).toContain("Authorization");
    expect(h.vary).toBe("Origin");
  });

  it("emits no ACAO for a disallowed origin", () => {
    const h = corsHeaders("https://evil.test", allowed);
    expect(h["access-control-allow-origin"]).toBeUndefined();
    expect(h.vary).toBe("Origin");
  });

  it("emits no ACAO when there is no Origin header", () => {
    const h = corsHeaders(undefined, allowed);
    expect(h["access-control-allow-origin"]).toBeUndefined();
  });
});
