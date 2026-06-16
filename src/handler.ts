// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The framework-agnostic core of the feedback proxy. The Vercel function
// (`api/feedback.ts`) is a thin adapter that maps the platform's req/res onto
// {@link ProxyRequest}/{@link ProxyResponse} and calls {@link handleFeedback}. Keeping
// the logic here (no `@vercel/node` import) makes the whole pipeline unit-testable with
// plain objects and lets the same core run on any host.
//
// Pipeline (fail-fast, cheapest checks first — cheap rejects BEFORE the auth/token path):
//   1. CORS preflight (OPTIONS) → 204 with the CORS headers.
//   2. Method gate — only POST is accepted.
//   3. Content-Type gate — require `application/json` → 415 (before any auth/rate-limit/token
//      work, so a non-JSON request cannot reach the verifier or the GitHub token's budget).
//   4. Body validation (shape/types/lengths/category) → 400, AND the repo allowlist → 403.
//      Both are done BEFORE auth + rate-limiting so a malformed/oversized/off-allowlist body
//      is rejected cheaply and cannot consume the (expensive) verifier path or the shared
//      GitHub-token rate budget. The body is NOT trusted afterwards — only its shape gates here.
//   5. Pre-auth per-IP throttle → 429 (guards the verifier/JWKS path from unauth floods).
//   6. DPoP token verification → the caller's WebID (provenance + the rate-limit key).
//   7. Per-WebID + per-IP rate limit → 429 when over.
//   8. Compose the issue server-side + create it via GitHub → 200 { url, number }
//      (GitHub failure → 502).
//
// SECURITY: the token + DPoP proof are NEVER logged; only a salted hash of the WebID is
// used for the rate-limit key (the WebID itself appears in the issue ONLY with consent).

import { createHmac } from "node:crypto";
import type { ProxyConfig } from "./config.js";
import { corsHeaders } from "./cors.js";
import { createIssue, type FetchLike, GitHubApiError } from "./github.js";
import { composeIssueBody, composeIssueTitle, feedbackLabels } from "./issue.js";
import type { RateLimiter } from "./rateLimit.js";
import type { FeedbackSubmitResult } from "./types.js";
import { ValidationError, validatePayload } from "./validate.js";
import type { DpopTokenVerifier } from "./verify.js";
import { TokenVerifyError } from "./verify.js";

/** The platform-agnostic request the handler operates on. */
export interface ProxyRequest {
  readonly method: string;
  /** Lower-cased header lookups. */
  readonly headers: {
    authorization?: string | undefined;
    dpop?: string | undefined;
    origin?: string | undefined;
    /** The request `Content-Type` (the adapter forwards it; gated to `application/json`). */
    contentType?: string | undefined;
  };
  /**
   * The request body, defensively parsed by the adapter into a value: a plain object on a
   * well-formed JSON body, otherwise `undefined` (no body / non-JSON / non-object). The
   * adapter rejects malformed JSON (string body that fails `JSON.parse`) with its OWN 400
   * before calling the core, so the core never sees a raw unparsed string here. The core
   * STILL re-validates the shape (defence in depth) — it never assumes a trusted body.
   */
  readonly body: unknown;
  /** The external https URL of THIS endpoint (proxy-aware), for the DPoP `htu` check. */
  readonly url: string;
  /** The client IP (best-effort, for the secondary per-IP rate-limit key). */
  readonly ip: string | undefined;
}

/** The platform-agnostic response the adapter writes back. */
export interface ProxyResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  /** A JSON-serialisable body, or `undefined` for an empty body (e.g. 204). */
  readonly body: { error: string } | FeedbackSubmitResult | undefined;
}

/** The collaborators the handler needs — injected so tests supply fakes. */
export interface HandlerDeps {
  readonly config: ProxyConfig;
  readonly verifier: DpopTokenVerifier;
  /** Post-auth limiter: per accepted WebID + IP (the issue-creation quota). */
  readonly rateLimiter: RateLimiter;
  /**
   * Pre-auth limiter: per IP, checked BEFORE token verification so unauthenticated /
   * invalid-token traffic cannot repeatedly drive the (relatively expensive) verifier +
   * JWKS path unthrottled (a cheap DoS guard). More generous than the post-auth limit.
   * Optional — when omitted the pre-auth check is skipped.
   */
  readonly preAuthRateLimiter?: RateLimiter;
  /** The outbound GitHub `fetch` — injected so tests mock the API. */
  readonly fetchImpl?: FetchLike;
}

const JSON_HEADERS = { "content-type": "application/json" } as const;

/** Run the full pipeline. Pure with respect to its {@link HandlerDeps} (no globals read). */
export async function handleFeedback(req: ProxyRequest, deps: HandlerDeps): Promise<ProxyResponse> {
  const { config } = deps;
  const cors = corsHeaders(req.headers.origin, config.allowedOrigins);
  const respond = (
    status: number,
    body: ProxyResponse["body"],
    extra: Record<string, string> = {},
  ): ProxyResponse => ({
    status,
    headers: { ...cors, ...(body === undefined ? {} : JSON_HEADERS), ...extra },
    body,
  });

  // 1. CORS preflight.
  if (req.method === "OPTIONS") {
    return respond(204, undefined);
  }
  // 2. Method gate.
  if (req.method !== "POST") {
    return respond(405, { error: "Method not allowed; use POST." }, { allow: "POST, OPTIONS" });
  }

  // 3. Content-Type gate — require `application/json` (a charset/params suffix is fine).
  //    Done BEFORE any auth/rate-limit/token work: a request without the JSON content type
  //    is rejected with 415 up front, so it can never reach the verifier or burn the
  //    GitHub-token rate budget (roborev MEDIUM). The adapter ALSO enforces this on the raw
  //    Vercel request; the core re-checks so the gate holds on any host (defence in depth).
  if (!isJsonContentType(req.headers.contentType)) {
    return respond(415, { error: "Content-Type must be application/json." });
  }

  // 4. Body shape validation + repo allowlist — BEFORE auth + rate-limiting. A
  //    malformed/oversized/off-allowlist body is a CHEAP reject, so doing it first means a
  //    bad body cannot consume the (expensive) verifier path or the shared GitHub-token rate
  //    budget (roborev MEDIUM: fail fast, cheap rejects first). The body is NEVER trusted
  //    beyond its shape here — the issue is recomposed server-side from the validated fields,
  //    and the consented WebID is taken from the VERIFIED token below, not from this body.
  let payload: ReturnType<typeof validatePayload>;
  try {
    payload = validatePayload(req.body, config);
  } catch (error) {
    if (error instanceof ValidationError) {
      return respond(400, { error: error.message });
    }
    return respond(400, { error: "Invalid request body." });
  }
  // Repo allowlist — the token must not be usable to file on arbitrary repos.
  if (!config.allowedRepos.includes(payload.repo)) {
    return respond(403, { error: "Repository is not on the feedback allowlist." });
  }

  // 5. Pre-auth IP throttle — BEFORE verification, so unauthenticated / invalid-token
  //    floods cannot repeatedly drive the verifier + JWKS path (cheap DoS guard). Skipped
  //    when no IP is known or no pre-auth limiter is configured.
  if (deps.preAuthRateLimiter && req.ip) {
    const pre = deps.preAuthRateLimiter.take(`preauth:${hashKey(req.ip, config.hashSecret)}`);
    if (!pre.allowed) {
      return respond(
        429,
        { error: "Too many requests; please try again later." },
        { "retry-after": String(pre.retryAfterSec) },
      );
    }
  }

  // 6. Auth gate — a verified, DPoP-bound Solid token is REQUIRED.
  let caller: { webId: string };
  try {
    caller = await deps.verifier.verify({
      authorization: req.headers.authorization,
      dpop: req.headers.dpop,
      method: "POST",
      url: req.url,
    });
  } catch (error) {
    if (error instanceof TokenVerifyError) {
      return respond(
        error.statusCode,
        { error: error.message },
        {
          "www-authenticate": 'DPoP error="invalid_token"',
        },
      );
    }
    return respond(401, { error: "Authentication failed." });
  }

  // 7. Rate limit — per WebID (primary) and per IP (secondary), checked TOGETHER so a
  //    request blocked by one key does not burn the other's quota (roborev LOW). Both
  //    keys are hashed so the limiter never stores the raw identifier. `takeAll` consumes
  //    from each key only when ALL are under the limit; otherwise nothing is consumed.
  const keys = [`webid:${hashKey(caller.webId, config.hashSecret)}`];
  if (req.ip) {
    keys.push(`ip:${hashKey(req.ip, config.hashSecret)}`);
  }
  const rate = deps.rateLimiter.takeAll(keys);
  if (!rate.allowed) {
    return respond(
      429,
      { error: "Rate limit exceeded; please try again later." },
      { "retry-after": String(rate.retryAfterSec) },
    );
  }

  // 8. Compose the issue SERVER-SIDE (never trust the client's title/body/labels) +
  //    create it. The client's `diagnostics.webId` is treated ONLY as a consent FLAG:
  //    when present we attach the VERIFIED `caller.webId` (from the token), NOT the
  //    client-supplied value — otherwise an authenticated caller could attribute the
  //    report to someone else's WebID (roborev HIGH). When absent, the WebID is never
  //    written (it was only used for the hashed rate-limit key above).
  const consentedToShareWebId = payload.diagnostics.webId !== undefined;
  const diagnostics = consentedToShareWebId
    ? { ...payload.diagnostics, webId: caller.webId }
    : payload.diagnostics;
  const title = composeIssueTitle(payload.category, payload.description);
  const body = composeIssueBody(payload.description, diagnostics);
  const labels = feedbackLabels(payload.category);

  try {
    const result = await createIssue(
      { repo: payload.repo, title, body, labels },
      config.githubToken,
      deps.fetchImpl,
    );
    return respond(200, result);
  } catch (error) {
    if (error instanceof GitHubApiError) {
      // 502: the upstream (GitHub) failed; the request itself was valid + authorized.
      return respond(502, { error: "Could not create the issue upstream." });
    }
    return respond(502, { error: "Could not create the issue upstream." });
  }
}

/**
 * True iff the request `Content-Type` is `application/json` (a `; charset=…` or other
 * parameter suffix is allowed; the media type itself must match, case-insensitively).
 * A missing / non-JSON content type fails — the gate that yields 415 (roborev MEDIUM):
 * a request without it can never reach auth, rate-limiting or the GitHub token.
 */
function isJsonContentType(contentType: string | undefined): boolean {
  if (typeof contentType !== "string") {
    return false;
  }
  // Take the media type before any `;` parameters, trim + lower-case, and match exactly.
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json";
}

/**
 * A stable, non-reversible key for an identifier (WebID or IP) used ONLY for
 * rate-limiting. HMAC-SHA256 under the server-side `hashSecret` so the key is NOT
 * dictionary-reversible (a plain hash of an IPv4 / common WebID has a small keyspace) —
 * matters once limiter state is exposed or moved to a shared store. The raw value is
 * never stored in the limiter or logged.
 */
function hashKey(value: string, secret: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
}
