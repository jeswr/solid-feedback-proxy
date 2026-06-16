// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it } from "vitest";
import {
  isValidRepoSlug,
  loadConfig,
  normalizeEndpointUrl,
  ProxyConfigError,
  parseList,
} from "../src/config.js";

const FULL = {
  FEEDBACK_GITHUB_TOKEN: "github_pat_abc",
  FEEDBACK_ALLOWED_REPOS: "jeswr/pod-mail jeswr/pod-drive",
  FEEDBACK_TRUSTED_ISSUERS: "https://idp.test https://idp2.test",
  FEEDBACK_AUDIENCE: "https://feedback.test",
  FEEDBACK_ALLOWED_ORIGINS: "https://app.test",
} as NodeJS.ProcessEnv;

describe("loadConfig", () => {
  it("loads a full, valid environment with defaults filled in", () => {
    const c = loadConfig(FULL);
    expect(c.allowedRepos).toEqual(["jeswr/pod-mail", "jeswr/pod-drive"]);
    expect(c.trustedIssuers).toEqual(["https://idp.test", "https://idp2.test"]);
    expect(c.audience).toBe("https://feedback.test");
    expect(c.webidClaim).toBe("webid");
    expect(c.rateLimitPerWindow).toBe(5);
    expect(c.rateLimitWindowMs).toBe(3_600_000);
    expect(c.maxDescriptionLength).toBe(8000);
    // publicEndpointUrl defaults to <audience>/feedback (the route the button POSTs to).
    expect(c.publicEndpointUrl).toBe("https://feedback.test/feedback");
  });

  it("derives publicEndpointUrl from the audience, tolerating a trailing slash", () => {
    expect(
      loadConfig({ ...FULL, FEEDBACK_AUDIENCE: "https://feedback.test/" }).publicEndpointUrl,
    ).toBe("https://feedback.test/feedback");
  });

  it("honours an explicit FEEDBACK_PUBLIC_URL (query/fragment stripped)", () => {
    const c = loadConfig({ ...FULL, FEEDBACK_PUBLIC_URL: "https://fb.test/api/feedback?x=1#f" });
    expect(c.publicEndpointUrl).toBe("https://fb.test/api/feedback");
  });

  it("rejects a malformed FEEDBACK_PUBLIC_URL", () => {
    expect(() => loadConfig({ ...FULL, FEEDBACK_PUBLIC_URL: "not a url" })).toThrow(
      ProxyConfigError,
    );
  });

  it("uses an explicit FEEDBACK_HASH_SECRET, else a strong per-instance random one", () => {
    expect(loadConfig({ ...FULL, FEEDBACK_HASH_SECRET: "stable-secret" }).hashSecret).toBe(
      "stable-secret",
    );
    // No secret set → a random one, different across loads (>= 32 bytes hex = 64 chars).
    const a = loadConfig(FULL).hashSecret;
    const b = loadConfig(FULL).hashSecret;
    expect(a).toHaveLength(64);
    expect(a).not.toBe(b);
  });

  it("honours overridden optional values", () => {
    const c = loadConfig({
      ...FULL,
      FEEDBACK_WEBID_CLAIM: "http://www.w3.org/ns/solid/terms#webid",
      FEEDBACK_RATE_LIMIT: "3",
      FEEDBACK_RATE_WINDOW_MS: "600000",
      FEEDBACK_MAX_DESCRIPTION: "1000",
    });
    expect(c.webidClaim).toBe("http://www.w3.org/ns/solid/terms#webid");
    expect(c.rateLimitPerWindow).toBe(3);
    expect(c.rateLimitWindowMs).toBe(600_000);
    expect(c.maxDescriptionLength).toBe(1000);
  });

  it.each([
    ["FEEDBACK_GITHUB_TOKEN", /FEEDBACK_GITHUB_TOKEN is required/],
    ["FEEDBACK_ALLOWED_REPOS", /FEEDBACK_ALLOWED_REPOS is required/],
    ["FEEDBACK_TRUSTED_ISSUERS", /FEEDBACK_TRUSTED_ISSUERS is required/],
    ["FEEDBACK_AUDIENCE", /FEEDBACK_AUDIENCE is required/],
    ["FEEDBACK_ALLOWED_ORIGINS", /FEEDBACK_ALLOWED_ORIGINS is required/],
  ])("throws when %s is missing", (key, pattern) => {
    const env = { ...FULL };
    delete env[key];
    expect(() => loadConfig(env)).toThrow(pattern);
  });

  it("rejects an invalid OWNER/REPO entry in the allowlist", () => {
    expect(() => loadConfig({ ...FULL, FEEDBACK_ALLOWED_REPOS: "not-a-repo" })).toThrow(
      /not a valid OWNER\/REPO/,
    );
  });

  it("rejects a non-positive rate limit", () => {
    expect(() => loadConfig({ ...FULL, FEEDBACK_RATE_LIMIT: "0" })).toThrow(ProxyConfigError);
    expect(() => loadConfig({ ...FULL, FEEDBACK_RATE_LIMIT: "-1" })).toThrow(ProxyConfigError);
    expect(() => loadConfig({ ...FULL, FEEDBACK_RATE_LIMIT: "abc" })).toThrow(ProxyConfigError);
  });
});

describe("parseList", () => {
  it("splits on commas, spaces and newlines and trims", () => {
    expect(parseList("a, b\nc  d")).toEqual(["a", "b", "c", "d"]);
    expect(parseList(undefined)).toEqual([]);
    expect(parseList("")).toEqual([]);
  });
});

describe("normalizeEndpointUrl", () => {
  it("strips query + fragment and returns the canonical absolute URL", () => {
    expect(normalizeEndpointUrl("https://fb.test/feedback?a=1#x")).toBe("https://fb.test/feedback");
    expect(normalizeEndpointUrl("https://fb.test/feedback")).toBe("https://fb.test/feedback");
  });
  it("throws on a malformed URL", () => {
    expect(() => normalizeEndpointUrl("nope")).toThrow();
  });
});

describe("isValidRepoSlug", () => {
  it.each(["jeswr/pod-mail", "a/b", "Foo.Bar/baz_qux-1"])("accepts %s", (s) => {
    expect(isValidRepoSlug(s)).toBe(true);
  });
  it.each([
    "no-slash",
    "a/b/c",
    "/b",
    "a/",
    "a b/c",
    "../etc",
    "owner/repo?x",
  ])("rejects %s", (s) => {
    expect(isValidRepoSlug(s)).toBe(false);
  });
});
