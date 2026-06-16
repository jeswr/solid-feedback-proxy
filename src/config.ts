// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Environment-driven configuration, parsed + validated once. Centralising this
// keeps the rest of the code free of `process.env` reads (testable: tests build a
// `ProxyConfig` directly) and gives one place to fail-fast on misconfiguration.

import { randomBytes } from "node:crypto";

/** Fully-resolved, validated configuration for one proxy instance. */
export interface ProxyConfig {
  /** Issuers we trust to mint access tokens (the suite broker + local dev issuer). */
  readonly trustedIssuers: readonly string[];
  /** The OWNER/REPO values a caller may file against (the suite repo allowlist). */
  readonly allowedRepos: readonly string[];
  /** The server-side GitHub token (fine-grained PAT, issues:write on the allowed repos). */
  readonly githubToken: string;
  /** Origins permitted by CORS (the suite app origins). */
  readonly allowedOrigins: readonly string[];
  /**
   * The audience this resource server expects in a token's `aud` claim (RFC 9068).
   * This is the proxy's own public URL. REQUIRED — RFC 9068 makes audience binding
   * mandatory, so a token the trusted issuer minted for another resource server is
   * rejected (closing the audience-confusion gap).
   */
  readonly audience: string;
  /**
   * The exact PUBLIC URL of the feedback endpoint the client calls and signs into its
   * DPoP proof `htu` (e.g. `https://feedback.example/feedback`). The Vercel adapter uses
   * THIS — not the possibly-rewritten internal request path (`/api/feedback`) — to build
   * the verifier's `htu`, so the `/feedback` → `/api/feedback` rewrite cannot break proof
   * verification. Defaults to `<audience>/feedback` when not set explicitly.
   */
  readonly publicEndpointUrl: string;
  /**
   * Server-side secret used to HMAC rate-limit keys (WebID / IP) so a stored key is not
   * dictionary-reversible (IPv4 + common WebIDs have small keyspaces under a plain hash).
   * Defaults to a per-instance random secret when unset — fine for the in-memory limiter,
   * but an operator backing the limiter with a SHARED store should set `FEEDBACK_HASH_SECRET`
   * to a stable value so keys are consistent across instances yet still un-reversible.
   */
  readonly hashSecret: string;
  /** The claim carrying the agent's WebID (Keycloak protocol-mapper output). */
  readonly webidClaim: string;
  /** Max issues per WebID per window. */
  readonly rateLimitPerWindow: number;
  /** The rate-limit window, in milliseconds. */
  readonly rateLimitWindowMs: number;
  /** Max characters accepted for the free-text description. */
  readonly maxDescriptionLength: number;
}

/** Defaults that are safe and do not need an operator to set them. */
const DEFAULTS = {
  webidClaim: "webid",
  rateLimitPerWindow: 5,
  rateLimitWindowMs: 60 * 60 * 1000, // 1 hour
  maxDescriptionLength: 8000,
} as const;

/** Split a comma/space/newline-separated env list into trimmed, non-empty entries. */
export function parseList(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === "") {
    return fallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    throw new ProxyConfigError(`Expected a positive integer, got "${raw}".`);
  }
  return n;
}

/** Thrown when the environment is missing/malformed — surfaces as a 500 (operator error). */
export class ProxyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProxyConfigError";
  }
}

/**
 * Build + validate the configuration from an environment-like record (defaults to
 * `process.env`). Fails fast (throwing {@link ProxyConfigError}) when a required
 * secret/allowlist is missing, so a misconfigured deploy cannot silently accept
 * traffic with, say, an empty repo allowlist.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): ProxyConfig {
  const trustedIssuers = parseList(env.FEEDBACK_TRUSTED_ISSUERS);
  if (trustedIssuers.length === 0) {
    throw new ProxyConfigError(
      "FEEDBACK_TRUSTED_ISSUERS is required (space/comma-separated Solid-OIDC issuer URLs).",
    );
  }
  const allowedRepos = parseList(env.FEEDBACK_ALLOWED_REPOS);
  if (allowedRepos.length === 0) {
    throw new ProxyConfigError(
      "FEEDBACK_ALLOWED_REPOS is required (space/comma-separated OWNER/REPO values).",
    );
  }
  for (const repo of allowedRepos) {
    if (!isValidRepoSlug(repo)) {
      throw new ProxyConfigError(
        `FEEDBACK_ALLOWED_REPOS entry is not a valid OWNER/REPO: "${repo}".`,
      );
    }
  }
  const githubToken = (env.FEEDBACK_GITHUB_TOKEN ?? "").trim();
  if (githubToken.length === 0) {
    throw new ProxyConfigError("FEEDBACK_GITHUB_TOKEN is required (a fine-grained GitHub PAT).");
  }
  const allowedOrigins = parseList(env.FEEDBACK_ALLOWED_ORIGINS);
  if (allowedOrigins.length === 0) {
    throw new ProxyConfigError(
      "FEEDBACK_ALLOWED_ORIGINS is required (space/comma-separated app origins for CORS).",
    );
  }

  const audience = (env.FEEDBACK_AUDIENCE ?? "").trim();
  if (audience.length === 0) {
    throw new ProxyConfigError(
      "FEEDBACK_AUDIENCE is required (this proxy's own public URL — the expected token aud).",
    );
  }

  // The public endpoint URL the client signs into the DPoP `htu`. Defaults to
  // `<audience>/feedback` (the route the FeedbackButton POSTs to), normalised so a
  // trailing slash / casing on the audience does not change the canonical URL.
  const publicEndpointUrl = normalizeEndpointUrl(
    (env.FEEDBACK_PUBLIC_URL ?? "").trim() || joinUrl(audience, "/feedback"),
  );

  // HMAC secret for rate-limit keys. A configured stable secret is required for a SHARED
  // store; otherwise a strong per-instance random secret (fine for the in-memory limiter).
  const hashSecret = (env.FEEDBACK_HASH_SECRET ?? "").trim() || randomBytes(32).toString("hex");

  return {
    trustedIssuers,
    allowedRepos,
    githubToken,
    allowedOrigins,
    audience,
    publicEndpointUrl,
    hashSecret,
    webidClaim: (env.FEEDBACK_WEBID_CLAIM ?? "").trim() || DEFAULTS.webidClaim,
    rateLimitPerWindow: parsePositiveInt(env.FEEDBACK_RATE_LIMIT, DEFAULTS.rateLimitPerWindow),
    rateLimitWindowMs: parsePositiveInt(env.FEEDBACK_RATE_WINDOW_MS, DEFAULTS.rateLimitWindowMs),
    maxDescriptionLength: parsePositiveInt(
      env.FEEDBACK_MAX_DESCRIPTION,
      DEFAULTS.maxDescriptionLength,
    ),
  };
}

/**
 * A GitHub OWNER/REPO slug: exactly one slash, each side made of the GitHub-legal
 * name characters (alphanumerics, `-`, `_`, `.`). This is both a config-time guard
 * and the shape the request-time allowlist check relies on; keeping it strict means
 * an allowlist entry can never be a path-traversal/injection vector into the API URL.
 */
export function isValidRepoSlug(repo: string): boolean {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    return false;
  }
  // Reject `.`/`..` segments defensively — never a real owner/repo, and they would
  // be a path-traversal smell even though the GitHub client path-encodes each segment.
  const [owner, name] = repo.split("/");
  return owner !== "." && owner !== ".." && name !== "." && name !== "..";
}

/** Join a base URL and a path, tolerating a trailing/leading slash on either side. */
function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

/**
 * Canonicalise an endpoint URL the way the DPoP `htu` comparison does: parse it, strip
 * query + fragment, and return the normalised absolute URL. Throws {@link ProxyConfigError}
 * on a malformed URL so a typo fails fast at boot rather than rejecting every request.
 */
export function normalizeEndpointUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProxyConfigError(`Invalid endpoint URL: "${value}".`);
  }
  url.search = "";
  url.hash = "";
  return url.href;
}
