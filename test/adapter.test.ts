// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Vercel adapter test. The key property under test (roborev MEDIUM): the adapter passes
// the CONFIGURED public endpoint URL as the DPoP `htu` verification URL, NOT the internal
// request path — so the Vercel `/feedback` → `/api/feedback` rewrite cannot break proof
// verification. We mock the verifier module to CAPTURE the `url` the adapter hands it,
// and drive the adapter with `req.url = "/api/feedback"` (the rewritten internal path).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Capture the VerifyRequest the adapter passes to the verifier.
const verifySpy = vi.fn(async (_req: { url: string }) => ({
  webId: "https://alice.example/card#me",
  issuer: "https://idp.test",
}));

/** A verified caller with a UNIQUE WebID per call, so the per-WebID limit never interferes
 *  with a test that is isolating the per-IP rate-limit behaviour. */
let webIdCounter = 0;
function uniqueWebIdVerifier(_req: { url: string }) {
  webIdCounter += 1;
  return Promise.resolve({
    webId: `https://u${webIdCounter}.example/card#me`,
    issuer: "https://idp.test",
  });
}

vi.mock("../src/verify.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/verify.js")>();
  return {
    ...actual,
    DpopTokenVerifier: class {
      verify(req: { url: string }) {
        return verifySpy(req);
      }
    },
  };
});

const ENV = {
  FEEDBACK_GITHUB_TOKEN: "secret-token",
  FEEDBACK_ALLOWED_REPOS: "jeswr/pod-mail",
  FEEDBACK_TRUSTED_ISSUERS: "https://idp.test",
  FEEDBACK_AUDIENCE: "https://feedback.test",
  FEEDBACK_ALLOWED_ORIGINS: "https://app.test",
  // The public endpoint the client signs — distinct from the internal /api/feedback path.
  FEEDBACK_PUBLIC_URL: "https://feedback.test/feedback",
};

beforeEach(() => {
  // Reset both calls AND the implementation so a per-test `mockImplementation` (e.g. the
  // unique-WebID verifier used by the rate-limit test) never leaks into another test.
  verifySpy.mockReset();
  verifySpy.mockResolvedValue({
    webId: "https://alice.example/card#me",
    issuer: "https://idp.test",
  });
  webIdCounter = 0;
  for (const [k, v] of Object.entries(ENV)) {
    vi.stubEnv(k, v);
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** A minimal VercelResponse stand-in capturing status + JSON body + headers. */
function fakeRes() {
  const headers: Record<string, string> = {};
  const res = {
    statusCode: 0,
    jsonBody: undefined as unknown,
    setHeader(k: string, v: string) {
      headers[k.toLowerCase()] = v;
    },
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.jsonBody = body;
      return res;
    },
    end() {
      return res;
    },
    headers,
  };
  return res;
}

describe("api/feedback adapter — DPoP htu uses the configured public URL", () => {
  it("passes config.publicEndpointUrl (not the rewritten req.url) to the verifier", async () => {
    // Mock the GitHub create-issue call so the happy path completes.
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({ html_url: "https://github.com/jeswr/pod-mail/issues/1", number: 1 }),
          { status: 201, headers: { "content-type": "application/json" } },
        ),
      );

    const { default: handler } = await import("../api/feedback.js");

    const req = {
      method: "POST",
      // The INTERNAL rewritten path — must NOT be what the verifier sees.
      url: "/api/feedback",
      headers: {
        authorization: "DPoP token",
        dpop: "proof",
        origin: "https://app.test",
        host: "feedback.test",
        "content-type": "application/json",
      },
      body: {
        repo: "jeswr/pod-mail",
        category: "bug",
        description: "x",
        diagnostics: { appName: "Pod Mail" },
      },
      socket: { remoteAddress: "203.0.113.9" },
    };
    const res = fakeRes();

    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins for the adapter.
    await handler(req as any, res as any);

    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect(verifySpy.mock.calls[0]?.[0].url).toBe("https://feedback.test/feedback");
    expect(res.statusCode).toBe(200);
    fetchSpy.mockRestore();
  });
});

/** A POST request with valid DPoP-ish headers; override `headers`/`body` per test. */
function postReq(overrides: {
  headers?: Record<string, string>;
  body?: unknown;
}): Record<string, unknown> {
  return {
    method: "POST",
    url: "/api/feedback",
    headers: {
      authorization: "DPoP token",
      dpop: "proof",
      origin: "https://app.test",
      host: "feedback.test",
      "content-type": "application/json",
      ...overrides.headers,
    },
    body: overrides.body,
    socket: { remoteAddress: "203.0.113.9" },
  };
}

const VALID_BODY = {
  repo: "jeswr/pod-mail",
  category: "bug",
  description: "x",
  diagnostics: { appName: "Pod Mail" },
};

describe("api/feedback adapter — content-type + defensive body parsing (roborev MEDIUM)", () => {
  it("rejects a non-JSON Content-Type with 415 BEFORE any auth/token work", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { default: handler } = await import("../api/feedback.js");
    const req = postReq({ headers: { "content-type": "text/plain" }, body: "hello" });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(415);
    // The auth path + the GitHub token were NEVER reached.
    expect(verifySpy).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("rejects a MISSING Content-Type with 415 (auth/token never reached)", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { default: handler } = await import("../api/feedback.js");
    const req = postReq({ headers: { "content-type": "" }, body: undefined });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(415);
    expect(verifySpy).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("rejects a string body with MALFORMED JSON with 400 (auth/token never reached)", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { default: handler } = await import("../api/feedback.js");
    // Vercel may hand us the raw STRING when it can't parse it — must 400, not reach auth.
    const req = postReq({ body: "{ not valid json " });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(400);
    expect((res.jsonBody as { error: string }).error).toMatch(/malformed json/i);
    expect(verifySpy).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("returns 400 for a missing/non-object body (no string to parse)", async () => {
    const { default: handler } = await import("../api/feedback.js");
    const req = postReq({ body: undefined });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    // Content-type is JSON (415 not hit); the core's shape validation 400s the empty body.
    expect(res.statusCode).toBe(400);
  });

  it("parses a well-formed JSON STRING body and flows through to a 200", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({ html_url: "https://github.com/jeswr/pod-mail/issues/2", number: 2 }),
          { status: 201, headers: { "content-type": "application/json" } },
        ),
      );
    const { default: handler } = await import("../api/feedback.js");
    // The body arrives as a raw JSON string — the adapter must JSON.parse it defensively.
    const req = postReq({ body: JSON.stringify(VALID_BODY) });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(200);
    expect(verifySpy).toHaveBeenCalledTimes(1);
    fetchSpy.mockRestore();
  });

  it("still accepts an already-parsed OBJECT body (the normal Vercel path)", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(
          JSON.stringify({ html_url: "https://github.com/jeswr/pod-mail/issues/3", number: 3 }),
          { status: 201, headers: { "content-type": "application/json" } },
        ),
      );
    const { default: handler } = await import("../api/feedback.js");
    const req = postReq({ body: VALID_BODY });
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(200);
    fetchSpy.mockRestore();
  });
});

describe("api/feedback adapter — method gate + trusted client IP (roborev)", () => {
  it("returns 405 (not 415) for a non-POST method even without a JSON content type", async () => {
    const { default: handler } = await import("../api/feedback.js");
    const req = {
      method: "GET",
      url: "/api/feedback",
      headers: { origin: "https://app.test", host: "feedback.test" }, // no content-type
      socket: { remoteAddress: "203.0.113.9" },
    };
    const res = fakeRes();
    // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
    await handler(req as any, res as any);
    expect(res.statusCode).toBe(405);
    expect(res.headers.allow).toBe("POST, OPTIONS");
  });

  it("keys the rate limit on x-real-ip, IGNORING a spoofed X-Forwarded-For", async () => {
    // Build a FRESH module instance with the post-auth per-IP limit pinned to 1, so the
    // SECOND request from the same client trips the limiter — proving which header is the key.
    vi.resetModules();
    vi.stubEnv("FEEDBACK_RATE_LIMIT", "1");
    // Unique WebID per call so the per-WebID limit never trips — this isolates per-IP keying.
    verifySpy.mockImplementation(uniqueWebIdVerifier);
    // A FRESH Response per call — a Response body can be read only once, so a shared object
    // would fail (→ 502) on the second consuming call.
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(
        async () =>
          new Response(
            JSON.stringify({ html_url: "https://github.com/jeswr/pod-mail/issues/9", number: 9 }),
            { status: 201, headers: { "content-type": "application/json" } },
          ),
      );
    const { default: handler } = await import("../api/feedback.js");

    const send = async (xRealIp: string, xff: string) => {
      const req = postReq({
        headers: { "x-real-ip": xRealIp, "x-forwarded-for": xff },
        body: VALID_BODY,
      });
      const res = fakeRes();
      // biome-ignore lint/suspicious/noExplicitAny: minimal Vercel req/res stand-ins.
      await handler(req as any, res as any);
      return res.statusCode;
    };

    // 1st request from x-real-ip A (limit 1) → allowed.
    expect(await send("198.51.100.20", "1.1.1.1")).toBe(200);
    // 2nd request: SAME x-real-ip A but a DIFFERENT spoofed XFF. If XFF were the key this
    // would be a fresh bucket and pass; because x-real-ip is the key, it is rate-limited.
    expect(await send("198.51.100.20", "2.2.2.2")).toBe(429);
    // 3rd request: DIFFERENT x-real-ip B but the SAME XFF as the blocked one. If XFF were
    // the key this would be blocked; because x-real-ip is the key, it is allowed.
    expect(await send("203.0.113.55", "2.2.2.2")).toBe(200);

    fetchSpy.mockRestore();
  });
});
