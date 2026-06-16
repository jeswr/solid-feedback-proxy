// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The Vercel serverless function: POST /feedback (also responds to the CORS OPTIONS
// preflight). A THIN adapter — it maps Vercel's req/res onto the framework-agnostic
// {@link ProxyRequest}/{@link ProxyResponse} and delegates ALL logic to
// {@link handleFeedback} in `src/handler.ts` (which is the unit-tested core).
//
// The verifier + rate limiter are module-level singletons so they persist across WARM
// invocations of the same function instance: the verifier caches per-issuer OIDC
// discovery + JWKS, and the in-memory rate-limit windows survive between requests on
// that instance. (See the README on why a multi-instance deploy wants a shared store.)

import type { VercelRequest, VercelResponse } from "@vercel/node";
import { loadConfig, type ProxyConfig } from "../src/config.js";
import { corsHeaders } from "../src/cors.js";
import { handleFeedback, type ProxyRequest } from "../src/handler.js";
import { RateLimiter } from "../src/rateLimit.js";
import { DpopTokenVerifier } from "../src/verify.js";

/**
 * Vercel function config: cap the JSON body the platform parses BEFORE our handler runs,
 * so an oversized payload is rejected at the platform edge rather than parsed into memory
 * (roborev LOW). 64kb comfortably exceeds a real feedback payload (the description cap is
 * 8000 chars) while bounding abuse.
 */
export const config = {
  api: {
    bodyParser: {
      sizeLimit: "64kb",
    },
  },
};

/** Multiplier: the pre-auth (per-IP, unauthenticated) attempt budget vs the post-auth quota. */
const PRE_AUTH_LIMIT_MULTIPLIER = 4;

/** Lazily-initialised singletons, built once per cold start from the environment. */
let cached:
  | {
      config: ProxyConfig;
      verifier: DpopTokenVerifier;
      rateLimiter: RateLimiter;
      preAuthRateLimiter: RateLimiter;
    }
  | undefined;

function deps() {
  if (cached === undefined) {
    const cfg = loadConfig();
    cached = {
      config: cfg,
      verifier: new DpopTokenVerifier({
        trustedIssuers: cfg.trustedIssuers,
        webidClaim: cfg.webidClaim,
        audience: cfg.audience,
      }),
      rateLimiter: new RateLimiter(cfg.rateLimitPerWindow, cfg.rateLimitWindowMs),
      // A more generous per-IP budget for auth ATTEMPTS (incl. failures), in the same
      // window — throttles unauthenticated floods without blocking legitimate retries.
      preAuthRateLimiter: new RateLimiter(
        cfg.rateLimitPerWindow * PRE_AUTH_LIMIT_MULTIPLIER,
        cfg.rateLimitWindowMs,
      ),
    };
  }
  return cached;
}

/**
 * The trusted client IP, used as a rate-limit key. We use Vercel's `x-real-ip` — the edge
 * sets it to the actual observed client address and a client CANNOT spoof it (unlike
 * `X-Forwarded-For`, whose leftmost value is attacker-controlled: a client may prepend a
 * fake hop, so taking `XFF[0]` would let an attacker pick arbitrary IP keys and bypass the
 * IP rate limits — roborev MEDIUM). We deliberately do NOT trust `X-Forwarded-For` here.
 * Falls back to the socket address (direct, non-proxied dev). `undefined` ⇒ no IP key
 * (the per-IP limit is simply skipped — the per-WebID limit still applies).
 */
function clientIp(req: VercelRequest): string | undefined {
  const realIp = firstHeader(req.headers["x-real-ip"]);
  if (typeof realIp === "string" && realIp.trim().length > 0) {
    return realIp.trim();
  }
  return req.socket?.remoteAddress ?? undefined;
}

function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

/**
 * True iff the request `Content-Type` is `application/json` (a `; charset=…` / params
 * suffix is allowed). Mirrors the core's `isJsonContentType` — enforced HERE too so a
 * non-JSON request is rejected with 415 at the EDGE, before deps()/auth/token work
 * (roborev MEDIUM: cheap rejects first; the core re-checks as defence in depth).
 */
function isJsonContentType(contentType: string | undefined): boolean {
  if (typeof contentType !== "string") {
    return false;
  }
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json";
}

/** Thrown by {@link parseBody} when a string/Buffer body is not well-formed JSON. */
class MalformedJsonError extends Error {}

function parseJsonText(text: string): unknown {
  // An empty / whitespace-only body is "no body" (→ undefined → the core's shape
  // validation 400s it), NOT malformed — only non-empty unparsable text is a 400-malformed.
  if (text.trim().length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new MalformedJsonError("Request body is not valid JSON.");
  }
}

/**
 * Defensively turn Vercel's `req.body` into a value the core can validate. Vercel parses
 * JSON onto `req.body` for an `application/json` request, but depending on platform/config
 * it may instead leave a raw STRING (or Buffer), or `undefined`. We therefore:
 *   - `string` → `JSON.parse` in try/catch ({@link MalformedJsonError} → 400 on failure),
 *   - `Buffer`/`Uint8Array` → decode to text then `JSON.parse` (same try/catch),
 *   - already an object → use as-is,
 *   - anything else (`undefined`/null/number/boolean) → returned verbatim so the core's
 *     shape validation rejects it with a 400.
 * The core re-validates the SHAPE regardless; this only ensures it never sees a raw,
 * unparsed JSON string and that malformed JSON can't reach the auth/token path (roborev
 * MEDIUM). NB: we do NOT call this for an OPTIONS preflight (no body to parse there).
 */
function parseBody(body: unknown): unknown {
  if (typeof body === "string") {
    return parseJsonText(body);
  }
  if (body instanceof Uint8Array) {
    return parseJsonText(Buffer.from(body).toString("utf8"));
  }
  return body;
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const method = req.method ?? "GET";
  const origin = firstHeader(req.headers.origin);
  const contentType = firstHeader(req.headers["content-type"]);

  // CORS preflight is delegated to the core (it answers OPTIONS with 204 + CORS) — do NOT
  // apply the content-type / body checks to it (a preflight carries no body).
  // For every other method, enforce the JSON content-type + defensively parse the body
  // BEFORE constructing deps() or touching the auth/token path (roborev MEDIUM: cheap,
  // unauthenticated rejects first). These early rejects are CORS-wrapped so the browser
  // can read them.
  let parsedBody: unknown = req.body;
  if (method !== "OPTIONS") {
    const cors = corsHeaders(origin, loadAllowedOriginsSafe());
    // Method gate FIRST — a non-POST (GET/DELETE/…) is 405, BEFORE the content-type check,
    // so the documented 405 is returned rather than a 415 for a method that has no body
    // semantics here (roborev LOW). OPTIONS is handled by the core (204 preflight) below.
    if (method !== "POST") {
      respondEarly(
        res,
        405,
        { error: "Method not allowed; use POST." },
        {
          ...cors,
          allow: "POST, OPTIONS",
        },
      );
      return;
    }
    if (!isJsonContentType(contentType)) {
      respondEarly(res, 415, { error: "Content-Type must be application/json." }, cors);
      return;
    }
    try {
      parsedBody = parseBody(req.body);
    } catch (error) {
      if (error instanceof MalformedJsonError) {
        respondEarly(res, 400, { error: "Request body is malformed JSON." }, cors);
        return;
      }
      throw error;
    }
  }

  let d: ReturnType<typeof deps>;
  try {
    d = deps();
  } catch (error) {
    // A configuration error is an OPERATOR problem (missing env). Surface a generic 500
    // — never echo the (potentially secret-revealing) config message to the client. The
    // detail is logged server-side for the operator.
    console.error("solid-feedback-proxy: misconfigured —", reason(error));
    res.status(500).json({ error: "Server is not configured." });
    return;
  }

  const proxyReq: ProxyRequest = {
    method,
    headers: {
      authorization: firstHeader(req.headers.authorization),
      dpop: firstHeader(req.headers.dpop as string | string[] | undefined),
      origin,
      contentType,
    },
    // The defensively-parsed body: a plain object on well-formed JSON, else `undefined`
    // (the core's shape validation then 400s it). Never a raw unparsed string here.
    body: parsedBody,
    // Use the CONFIGURED public endpoint URL (what the client signs into the DPoP `htu`),
    // NOT the request path — Vercel rewrites `/feedback` → `/api/feedback`, so `req.url`
    // would be the internal path and break proof verification (roborev MEDIUM).
    url: d.config.publicEndpointUrl,
    ip: clientIp(req),
  };

  const result = await handleFeedback(proxyReq, d);
  for (const [k, v] of Object.entries(result.headers)) {
    res.setHeader(k, v);
  }
  if (result.body === undefined) {
    res.status(result.status).end();
  } else {
    res.status(result.status).json(result.body);
  }
}

/** Write a CORS-wrapped JSON error for an EARLY reject (415 / 400-malformed), pre-deps(). */
function respondEarly(
  res: VercelResponse,
  status: number,
  body: { error: string },
  cors: Record<string, string>,
): void {
  for (const [k, v] of Object.entries(cors)) {
    res.setHeader(k, v);
  }
  res.status(status).json(body);
}

/**
 * Best-effort allowed-origins for the EARLY (pre-deps) CORS headers on a 415/400-malformed.
 * `loadConfig()` can throw on operator misconfiguration; an early reject must not turn that
 * into a 500, so we fall back to NO allowed origins (the browser then blocks the read — a
 * safe default; the request was being rejected anyway). Cheap; cached config makes the
 * normal path a no-op re-read.
 */
function loadAllowedOriginsSafe(): readonly string[] {
  try {
    return (cached?.config ?? loadConfig()).allowedOrigins;
  } catch {
    return [];
  }
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
