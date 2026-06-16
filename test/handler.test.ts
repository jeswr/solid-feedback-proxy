// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// End-to-end pipeline tests: a real DpopTokenVerifier (inline JWKS) + a real
// RateLimiter + a mocked GitHub fetch, driven through handleFeedback. Asserts the
// full happy path returns FeedbackSubmitResult { url, number } AND every reject branch
// (401 / 405 / 415 / 403 / 429 / 400 / 502 / CORS preflight), incl. pre-auth throttle,
// WebID-spoof rejection, and the verified-WebID provenance.

import { describe, expect, it, vi } from "vitest";
import type { ProxyConfig } from "../src/config.js";
import type { FetchLike } from "../src/github.js";
import { type HandlerDeps, handleFeedback, type ProxyRequest } from "../src/handler.js";
import { RateLimiter } from "../src/rateLimit.js";
import { DpopTokenVerifier } from "../src/verify.js";
import {
  AUDIENCE,
  ENDPOINT_URL,
  ISSUER,
  inlineResolver,
  makeKeys,
  makeVerifyRequest,
  WEBID,
} from "./helpers.js";

const ORIGIN = "https://app.test";

function baseConfig(overrides: Partial<ProxyConfig> = {}): ProxyConfig {
  return {
    trustedIssuers: [ISSUER],
    allowedRepos: ["jeswr/pod-mail"],
    githubToken: "secret-token",
    allowedOrigins: [ORIGIN],
    audience: AUDIENCE,
    publicEndpointUrl: ENDPOINT_URL,
    hashSecret: "test-hash-secret",
    webidClaim: "webid",
    rateLimitPerWindow: 5,
    rateLimitWindowMs: 60_000,
    maxDescriptionLength: 8000,
    ...overrides,
  };
}

const VALID_BODY = {
  repo: "jeswr/pod-mail",
  category: "bug",
  description: "Save button does nothing",
  diagnostics: {
    appName: "Pod Mail",
    appVersion: "1.0.0",
    pageUrl: "https://x/y",
    userAgent: "UA",
  },
};

async function deps(
  overrides: {
    config?: Partial<ProxyConfig>;
    fetchImpl?: FetchLike;
    rateLimiter?: RateLimiter;
    preAuthRateLimiter?: RateLimiter;
  } = {},
) {
  const keys = await makeKeys();
  const config = baseConfig(overrides.config);
  const verifier = new DpopTokenVerifier(
    {
      trustedIssuers: config.trustedIssuers,
      webidClaim: config.webidClaim,
      audience: config.audience,
    },
    inlineResolver(keys),
  );
  const handlerDeps: HandlerDeps = {
    config,
    verifier,
    rateLimiter:
      overrides.rateLimiter ?? new RateLimiter(config.rateLimitPerWindow, config.rateLimitWindowMs),
    ...(overrides.preAuthRateLimiter ? { preAuthRateLimiter: overrides.preAuthRateLimiter } : {}),
    ...(overrides.fetchImpl ? { fetchImpl: overrides.fetchImpl } : {}),
  };
  return { keys, handlerDeps };
}

function okFetch() {
  return vi.fn<FetchLike>(
    async () =>
      new Response(
        JSON.stringify({ html_url: "https://github.com/jeswr/pod-mail/issues/7", number: 7 }),
        {
          status: 201,
          headers: { "content-type": "application/json" },
        },
      ),
  );
}

/** Read the JSON issue payload the proxy sent to the (mocked) GitHub API on its first call. */
function sentIssueBody(fetchImpl: ReturnType<typeof okFetch>): {
  title: string;
  body: string;
  labels: string[];
} {
  const call = fetchImpl.mock.calls[0];
  if (!call) {
    throw new Error("expected the handler to call the GitHub API");
  }
  return JSON.parse(call[1].body as string);
}

async function authedRequest(
  keys: Awaited<ReturnType<typeof makeKeys>>,
  body: unknown,
  extra: Partial<ProxyRequest> = {},
): Promise<ProxyRequest> {
  const vr = await makeVerifyRequest(keys, { url: ENDPOINT_URL, method: "POST" });
  return {
    method: "POST",
    headers: {
      authorization: vr.authorization,
      dpop: vr.dpop,
      origin: ORIGIN,
      contentType: "application/json",
    },
    body,
    url: ENDPOINT_URL,
    ip: "203.0.113.1",
    ...extra,
  };
}

describe("handleFeedback — happy path", () => {
  it("verifies, composes server-side, creates the issue, returns { url, number }", async () => {
    const fetchImpl = okFetch();
    const { keys, handlerDeps } = await deps({ fetchImpl });
    const req = await authedRequest(keys, VALID_BODY);
    const res = await handleFeedback(req, handlerDeps);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ url: "https://github.com/jeswr/pod-mail/issues/7", number: 7 });
    expect(res.headers["access-control-allow-origin"]).toBe(ORIGIN);
    // Server composed the title/body/labels — not the client's.
    const sent = sentIssueBody(fetchImpl);
    expect(sent.title).toBe("[Bug] Save button does nothing");
    expect(sent.labels).toEqual(["user-feedback", "bug"]);
  });

  it("attaches the WebID to the issue only when the button included it (consent)", async () => {
    const fetchImpl = okFetch();
    const { keys, handlerDeps } = await deps({ fetchImpl });
    const req = await authedRequest(keys, {
      ...VALID_BODY,
      diagnostics: { ...VALID_BODY.diagnostics, webId: WEBID },
    });
    const res = await handleFeedback(req, handlerDeps);
    expect(res.status).toBe(200);
    const sent = sentIssueBody(fetchImpl);
    expect(sent.body).toContain(`Reporter WebID: ${WEBID}`);
  });

  it("records the VERIFIED WebID, never a client-spoofed one (consent is just a flag)", async () => {
    const fetchImpl = okFetch();
    const { keys, handlerDeps } = await deps({ fetchImpl });
    // The token's verified WebID is WEBID; the client tries to attribute the report to
    // someone else. The proxy must write the VERIFIED WebID, never the spoofed one.
    const req = await authedRequest(keys, {
      ...VALID_BODY,
      diagnostics: { ...VALID_BODY.diagnostics, webId: "https://victim.example/card#me" },
    });
    const res = await handleFeedback(req, handlerDeps);
    expect(res.status).toBe(200);
    const sent = sentIssueBody(fetchImpl);
    expect(sent.body).toContain(`Reporter WebID: ${WEBID}`);
    expect(sent.body).not.toContain("victim.example");
  });

  it("does not record any WebID when the user did not consent", async () => {
    const fetchImpl = okFetch();
    const { keys, handlerDeps } = await deps({ fetchImpl });
    const req = await authedRequest(keys, VALID_BODY); // no diagnostics.webId
    const res = await handleFeedback(req, handlerDeps);
    expect(res.status).toBe(200);
    const sent = sentIssueBody(fetchImpl);
    expect(sent.body).not.toContain("Reporter WebID");
  });
});

describe("handleFeedback — preflight + method", () => {
  it("answers the CORS preflight with 204 + CORS headers", async () => {
    const { handlerDeps } = await deps();
    const res = await handleFeedback(
      {
        method: "OPTIONS",
        headers: { origin: ORIGIN },
        body: undefined,
        url: ENDPOINT_URL,
        ip: undefined,
      },
      handlerDeps,
    );
    expect(res.status).toBe(204);
    expect(res.body).toBeUndefined();
    expect(res.headers["access-control-allow-origin"]).toBe(ORIGIN);
  });

  it("rejects a non-POST method with 405", async () => {
    const { handlerDeps } = await deps();
    const res = await handleFeedback(
      {
        method: "GET",
        headers: { origin: ORIGIN },
        body: undefined,
        url: ENDPOINT_URL,
        ip: undefined,
      },
      handlerDeps,
    );
    expect(res.status).toBe(405);
  });
});

describe("handleFeedback — auth gate", () => {
  it("rejects an unauthenticated request with 401 + WWW-Authenticate", async () => {
    const { handlerDeps } = await deps();
    const res = await handleFeedback(
      {
        method: "POST",
        headers: { origin: ORIGIN, contentType: "application/json" },
        body: VALID_BODY,
        url: ENDPOINT_URL,
        ip: "1.2.3.4",
      },
      handlerDeps,
    );
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toContain("DPoP");
  });
});

describe("handleFeedback — rate limit", () => {
  it("returns 429 with Retry-After once the per-WebID limit is exceeded", async () => {
    const fetchImpl = okFetch();
    const rateLimiter = new RateLimiter(2, 60_000);
    const { keys, handlerDeps } = await deps({ fetchImpl, rateLimiter });
    // 2 allowed, 3rd blocked (same WebID; build a fresh authed request each time).
    expect((await handleFeedback(await authedRequest(keys, VALID_BODY), handlerDeps)).status).toBe(
      200,
    );
    expect((await handleFeedback(await authedRequest(keys, VALID_BODY), handlerDeps)).status).toBe(
      200,
    );
    const third = await handleFeedback(await authedRequest(keys, VALID_BODY), handlerDeps);
    expect(third.status).toBe(429);
    expect(third.headers["retry-after"]).toBeDefined();
  });

  it("pre-auth IP throttle blocks BEFORE verification (verifier never called)", async () => {
    const preAuthRateLimiter = new RateLimiter(1, 60_000);
    const { handlerDeps } = await deps({ preAuthRateLimiter });
    const verifySpy = vi.spyOn(handlerDeps.verifier, "verify");
    const req = (): ProxyRequest => ({
      method: "POST",
      // no auth — would 401 if it reached verification
      headers: { origin: ORIGIN, contentType: "application/json" },
      body: VALID_BODY,
      url: ENDPOINT_URL,
      ip: "198.51.100.7",
    });
    // 1st attempt: under the pre-auth budget → reaches the (failing) auth gate → 401.
    expect((await handleFeedback(req(), handlerDeps)).status).toBe(401);
    // 2nd attempt from the same IP: over the pre-auth budget → 429 BEFORE verification.
    const second = await handleFeedback(req(), handlerDeps);
    expect(second.status).toBe(429);
    expect(second.headers["retry-after"]).toBeDefined();
    // verify() was called exactly once (only for the first, throttle-passing attempt).
    expect(verifySpy).toHaveBeenCalledTimes(1);
  });
});

describe("handleFeedback — content-type gate (roborev MEDIUM)", () => {
  it("rejects a non-JSON Content-Type with 415 BEFORE auth (verifier never called)", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const verifySpy = vi.spyOn(handlerDeps.verifier, "verify");
    const authed = await authedRequest(keys, VALID_BODY);
    const res = await handleFeedback(
      { ...authed, headers: { ...authed.headers, contentType: "text/plain" } },
      handlerDeps,
    );
    expect(res.status).toBe(415);
    expect(verifySpy).not.toHaveBeenCalled();
  });

  it("rejects a MISSING Content-Type with 415 BEFORE auth (verifier never called)", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const verifySpy = vi.spyOn(handlerDeps.verifier, "verify");
    const authed = await authedRequest(keys, VALID_BODY);
    const res = await handleFeedback(
      {
        ...authed,
        headers: {
          authorization: authed.headers.authorization,
          dpop: authed.headers.dpop,
          origin: ORIGIN,
          // contentType omitted entirely
        },
      },
      handlerDeps,
    );
    expect(res.status).toBe(415);
    expect(verifySpy).not.toHaveBeenCalled();
  });

  it("accepts application/json with a charset suffix", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const authed = await authedRequest(keys, VALID_BODY);
    const res = await handleFeedback(
      { ...authed, headers: { ...authed.headers, contentType: "application/json; charset=utf-8" } },
      handlerDeps,
    );
    expect(res.status).toBe(200);
  });
});

describe("handleFeedback — validation + allowlist", () => {
  it("returns 400 on a malformed body", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const res = await handleFeedback(
      await authedRequest(keys, { repo: "jeswr/pod-mail" }),
      handlerDeps,
    );
    expect(res.status).toBe(400);
  });

  it("validates the body shape BEFORE auth — a malformed body 400s without verifying", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const verifySpy = vi.spyOn(handlerDeps.verifier, "verify");
    const res = await handleFeedback(
      await authedRequest(keys, { repo: "jeswr/pod-mail" }),
      handlerDeps,
    );
    expect(res.status).toBe(400);
    // Cheap reject: the bad body never reached the (expensive) verifier / GitHub-token path.
    expect(verifySpy).not.toHaveBeenCalled();
  });

  it("returns 400 on a non-object body (undefined) BEFORE auth", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const verifySpy = vi.spyOn(handlerDeps.verifier, "verify");
    const res = await handleFeedback(await authedRequest(keys, undefined), handlerDeps);
    expect(res.status).toBe(400);
    expect(verifySpy).not.toHaveBeenCalled();
  });

  it("returns 403 when the repo is not on the allowlist", async () => {
    const { keys, handlerDeps } = await deps({ fetchImpl: okFetch() });
    const res = await handleFeedback(
      await authedRequest(keys, { ...VALID_BODY, repo: "jeswr/secret-private-repo" }),
      handlerDeps,
    );
    expect(res.status).toBe(403);
  });
});

describe("handleFeedback — GitHub failure", () => {
  it("returns 502 when GitHub rejects the create-issue call", async () => {
    const fetchImpl = vi.fn<FetchLike>(
      async () => new Response(JSON.stringify({ message: "Bad credentials" }), { status: 401 }),
    );
    const { keys, handlerDeps } = await deps({ fetchImpl });
    const res = await handleFeedback(await authedRequest(keys, VALID_BODY), handlerDeps);
    expect(res.status).toBe(502);
    // The client-facing error never reveals the upstream detail or the token.
    expect(JSON.stringify(res.body)).not.toContain("secret-token");
    expect(JSON.stringify(res.body)).not.toContain("Bad credentials");
  });
});
