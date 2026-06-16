// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Issuer-agnostic Solid-OIDC + RFC 9449 DPoP access-token verification, built on the
// SAME vetted library prod-solid-server's verifier uses — `oauth4webapi` (panva,
// RFC 6750/9068/9449) for the full token + proof orchestration. NOTHING is
// hand-rolled: we do not parse JWTs, verify signatures, or check the DPoP proof
// ourselves — `validateJwtAccessToken` does it all in one call.
//
// What that one call verifies (and what this proxy relies on):
//   - the access-token JWS signature against the issuer's JWKS, an ASYMMETRIC `alg`
//     only (HS*/none excluded — proof-of-possession is meaningless otherwise),
//     `typ=at+jwt`, the RFC 9068 required claims, the trusted `iss`, the expected
//     `aud` (this endpoint's identity), and temporal claims within tolerance;
//   - the DPoP proof (RFC 9449): `typ=dpop+jwt`, asymmetric `alg`, embedded PUBLIC
//     JWK, the proof JWS signature, `htm`==method, `htu`==this endpoint's URL, `iat`
//     freshness, `ath` binding the proof to THIS token, and `cnf.jkt` proof-of-possession.
//
// On top we keep the Solid policy the library does not cover: the trusted-issuer
// allowlist (pre-checked from the UNVERIFIED `iss` BEFORE any discovery, so an
// untrusted issuer never causes us to dereference its discovery document) and the
// `webid`-claim extraction (must be an `https:` URL without userinfo).
//
// DPoP IS REQUIRED. A bare Bearer token is rejected — abuse control + provenance
// demand proof-of-possession, exactly as the suite resource server requires.

import * as oauth from "oauth4webapi";
import { InProcessReplayStore, type ReplayStore } from "./replayStore.js";

/** Asymmetric signature algorithms accepted for BOTH the access token and the DPoP proof. */
const SIGNING_ALGS = [
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "PS384",
  "PS512",
  "RS256",
  "RS384",
  "RS512",
];

/**
 * The DPoP-proof `iat` freshness window `oauth4webapi` enforces (≈300 s). The replay
 * cache MUST remember a `jti` for at least this long: the library accepts the *same*
 * proof for up to this window, so a shorter TTL would reopen the replay gap once the
 * cache forgot the `jti` but before the library rejects it as stale.
 */
const DPOP_PROOF_MAX_AGE_SEC = 300;

/** The verified caller: the WebID (provenance) + the issuer that minted the token. */
export interface VerifiedCaller {
  readonly webId: string;
  readonly issuer: string;
  readonly clientId?: string;
}

/** Raised when a presented token/proof fails verification — surfaces as 401. */
export class TokenVerifyError extends Error {
  readonly statusCode: number;
  constructor(message: string, statusCode = 401) {
    super(message);
    this.name = "TokenVerifyError";
    this.statusCode = statusCode;
  }
}

/** The transport-agnostic inputs the verifier needs (assembled by the HTTP adapter). */
export interface VerifyRequest {
  /** The `Authorization` header value (e.g. `DPoP <token>`). */
  readonly authorization: string | undefined;
  /** The `DPoP` header value (the proof JWT). */
  readonly dpop: string | undefined;
  /** The HTTP method (upper-case) — checked against the proof's `htm`. */
  readonly method: string;
  /**
   * The exact public URL of this endpoint the client signed into the proof's `htu`
   * (scheme + host + path, query/fragment stripped). Behind Vercel's TLS-terminating
   * proxy this MUST be the external https URL the client called, not the internal one.
   */
  readonly url: string;
}

/**
 * What the issuer resolver yields: the `oauth4webapi` AuthorizationServer metadata
 * (carrying the discovered `jwks_uri`) plus an optional pre-seeded JWKS (tests inject
 * `jwks` so the verifier runs with no network I/O).
 */
export interface IssuerConfig {
  readonly as: oauth.AuthorizationServer;
  readonly jwks?: oauth.JWKS;
  readonly allowInsecureRequests?: boolean;
}

export interface VerifierOptions {
  /** Issuers we trust to mint tokens (suite broker + local dev issuer). Non-empty. */
  readonly trustedIssuers: readonly string[];
  /** The claim carrying the WebID. */
  readonly webidClaim: string;
  /**
   * The `aud` this resource server expects — its own public URL. REQUIRED (RFC 9068
   * makes audience binding mandatory): a token the trusted issuer minted for another
   * resource server is rejected, closing the audience-confusion gap.
   */
  readonly audience: string;
  /** Allowed clock skew, in seconds. */
  readonly clockToleranceSec?: number;
}

/** Whether an issuer URL is a loopback HTTP endpoint (the dev/CI IdP) — HTTPS relaxed only here. */
export function isLoopbackHttp(issuer: string): boolean {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return false;
  }
  if (url.protocol !== "http:") {
    return false;
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return (
    host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0:0:0:0:0:0:0:1"
  );
}

/**
 * Resolve an issuer's metadata via OIDC discovery, cross-checking the discovery
 * `issuer` against the configured one (a spoofed document cannot redirect key
 * resolution) and validating it carries a `jwks_uri`.
 */
async function discoverIssuer(issuer: string): Promise<IssuerConfig> {
  const issuerUrl = new URL(issuer);
  const allowInsecureRequests = isLoopbackHttp(issuer);
  const res = await oauth.discoveryRequest(issuerUrl, {
    algorithm: "oidc",
    [oauth.allowInsecureRequests]: allowInsecureRequests,
  });
  const as = await oauth.processDiscoveryResponse(issuerUrl, res);
  if (as.issuer !== issuer) {
    throw new Error(`OIDC discovery issuer mismatch for ${issuer} (got ${as.issuer}).`);
  }
  if (typeof as.jwks_uri !== "string" || as.jwks_uri.length === 0) {
    throw new Error(`OIDC discovery for ${issuer} has no jwks_uri.`);
  }
  return { as, allowInsecureRequests };
}

/** Parse an `Authorization` header into a lower-cased scheme + token. */
export function parseAuthorization(
  header: string | undefined,
): { scheme: string; token: string } | undefined {
  if (!header) {
    return undefined;
  }
  const trimmed = header.trim();
  const sp = trimmed.indexOf(" ");
  if (sp === -1) {
    return undefined;
  }
  const scheme = trimmed.slice(0, sp).toLowerCase();
  const token = trimmed.slice(sp + 1).trim();
  if (!token) {
    return undefined;
  }
  return { scheme, token };
}

/** Decode the unverified JWT payload just far enough to read a claim (pre-validation routing). */
function decodeClaims(token: string): Record<string, unknown> | undefined {
  const parts = token.split(".");
  const claimsSegment = parts.length === 3 ? parts[1] : undefined;
  if (claimsSegment === undefined) {
    return undefined;
  }
  try {
    const json = Buffer.from(claimsSegment, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Read a DPoP proof's `jti` (the proof is already validated; this only feeds the replay cache). */
function peekJti(proof: string): string | undefined {
  const jti = decodeClaims(proof)?.jti;
  return typeof jti === "string" && jti.length > 0 ? jti : undefined;
}

/** Build a WHATWG Request from the transport-agnostic inputs for `validateJwtAccessToken`. */
function toRequest(req: VerifyRequest): Request {
  const headers = new Headers();
  if (req.authorization) {
    headers.set("authorization", req.authorization);
  }
  if (req.dpop) {
    headers.set("dpop", req.dpop);
  }
  return new Request(req.url, { method: req.method, headers });
}

/**
 * The Solid-OIDC + DPoP token verifier. Constructed once per cold start; caches the
 * per-issuer discovery promise so OIDC discovery + JWKS fetch happen at most once per
 * issuer for the lifetime of the function instance.
 */
export class DpopTokenVerifier {
  private readonly options: Required<VerifierOptions>;
  private readonly issuers = new Map<string, Promise<IssuerConfig>>();
  private readonly resolveIssuer: (issuer: string) => Promise<IssuerConfig> | IssuerConfig;
  private readonly replay: ReplayStore;

  constructor(
    options: VerifierOptions,
    resolveIssuer: (issuer: string) => Promise<IssuerConfig> | IssuerConfig = discoverIssuer,
    /** Replay store for DPoP-proof `jti`. Defaults to an in-process store. */
    replay: ReplayStore = new InProcessReplayStore(),
  ) {
    if (options.trustedIssuers.length === 0) {
      throw new Error("DpopTokenVerifier requires at least one trusted issuer.");
    }
    if (!options.audience) {
      throw new Error("DpopTokenVerifier requires an audience (the resource server's identity).");
    }
    this.options = {
      trustedIssuers: options.trustedIssuers,
      webidClaim: options.webidClaim,
      audience: options.audience,
      clockToleranceSec: options.clockToleranceSec ?? 5,
    };
    this.resolveIssuer = resolveIssuer;
    this.replay = replay;
  }

  /**
   * Verify the request's DPoP-bound token. Returns the {@link VerifiedCaller} (WebID +
   * issuer). Throws {@link TokenVerifyError} (401) on ANY failure, including an absent
   * `Authorization` header — this endpoint NEVER serves anonymous callers.
   */
  async verify(req: VerifyRequest): Promise<VerifiedCaller> {
    const parsed = parseAuthorization(req.authorization);
    if (!parsed) {
      throw new TokenVerifyError("Authorization required (DPoP-bound Solid-OIDC token).");
    }
    // DPoP is mandatory — reject bare Bearer and any other scheme.
    if (parsed.scheme !== "dpop") {
      throw new TokenVerifyError("A DPoP-bound token is required; Bearer is not accepted.");
    }
    if (!req.dpop) {
      throw new TokenVerifyError("Missing DPoP proof header.");
    }

    // Trusted-issuer allowlist FIRST — from the UNVERIFIED `iss`, BEFORE discovery, so
    // an untrusted issuer never makes us dereference its (attacker-controlled) document.
    const claimedIssuer = this.peekIssuer(parsed.token);
    if (!this.options.trustedIssuers.includes(claimedIssuer)) {
      throw new TokenVerifyError("Token issuer is not trusted.");
    }

    const claims = await this.validateToken(req, claimedIssuer);
    const webId = this.extractWebId(claims);
    // Replay protection — the library validated the proof but does not remember its
    // `jti`. Consume it AFTER the cryptographic validation (so an invalid proof never
    // touches the cache) and reject a repeat within the freshness window.
    this.checkReplay(req.dpop);
    return {
      webId,
      issuer: claims.iss,
      ...(typeof claims.client_id === "string" ? { clientId: claims.client_id } : {}),
    };
  }

  /**
   * Consume the DPoP proof's `jti` against the replay store. A repeated `jti` within its
   * freshness window is a replay → reject. The TTL covers the full window the library
   * would still accept the same proof on its `iat`.
   */
  private checkReplay(proof: string): void {
    const jti = peekJti(proof);
    if (jti === undefined) {
      // The library already required a `jti`; this is belt-and-braces.
      throw new TokenVerifyError("DPoP proof is missing a jti.");
    }
    const ttlSeconds = DPOP_PROOF_MAX_AGE_SEC + this.options.clockToleranceSec;
    if (this.replay.mark(jti, ttlSeconds) === "replay") {
      throw new TokenVerifyError("DPoP proof has already been used (replay).");
    }
  }

  /** Run the certified `oauth4webapi` validation (token + DPoP proof) over a WHATWG Request. */
  private async validateToken(
    req: VerifyRequest,
    claimedIssuer: string,
  ): Promise<oauth.JWTAccessTokenClaims> {
    try {
      const { as, jwks, allowInsecureRequests } = await this.issuerConfigFor(claimedIssuer);
      const request = toRequest(req);
      return await oauth.validateJwtAccessToken(as, request, this.options.audience, {
        requireDPoP: true,
        signingAlgorithms: SIGNING_ALGS,
        [oauth.clockTolerance]: this.options.clockToleranceSec,
        ...(allowInsecureRequests ? { [oauth.allowInsecureRequests]: true } : {}),
        ...(jwks ? { [oauth.jwksCache]: { jwks, uat: Math.floor(Date.now() / 1000) } } : {}),
      });
    } catch (error: unknown) {
      if (error instanceof TokenVerifyError) {
        throw error;
      }
      throw new TokenVerifyError(`Token verification failed: ${reason(error)}`);
    }
  }

  /** The `webid` (configurable claim) — must be present and an `https:` URL without userinfo. */
  private extractWebId(claims: oauth.JWTAccessTokenClaims): string {
    const raw = claims[this.options.webidClaim];
    if (typeof raw !== "string" || raw.length === 0) {
      throw new TokenVerifyError(`Token is missing the '${this.options.webidClaim}' claim.`);
    }
    // Reject ASCII control characters (CR/LF/TAB/…) BEFORE parsing. `new URL()` silently
    // strips tab/newline and trims leading/trailing C0 controls, so a claim like
    // "https://x/y\nReporter WebID: evil" would otherwise PASS validation and then be
    // written verbatim into the issue's diagnostics block — a metadata-line injection. The
    // verified WebID is the one trusted field that reaches the body unmodified, so it must
    // be control-char-free (roborev MEDIUM). A real WebID never contains control chars.
    if (hasControlChar(raw)) {
      throw new TokenVerifyError("WebID claim must not contain control characters.");
    }
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new TokenVerifyError("WebID claim is not a valid URL.");
    }
    if (url.protocol !== "https:") {
      throw new TokenVerifyError("WebID claim must be an https: URL.");
    }
    if (url.username || url.password) {
      throw new TokenVerifyError("WebID claim must not include userinfo.");
    }
    return raw;
  }

  private peekIssuer(token: string): string {
    const claims = decodeClaims(token);
    if (!claims) {
      throw new TokenVerifyError("Malformed access token.");
    }
    const iss = claims.iss;
    if (typeof iss !== "string" || iss.length === 0) {
      throw new TokenVerifyError("Access token has no issuer.");
    }
    return iss;
  }

  /** Get (or lazily create + cache) the {@link IssuerConfig} for a trusted issuer. */
  private async issuerConfigFor(issuer: string): Promise<IssuerConfig> {
    let pending = this.issuers.get(issuer);
    if (!pending) {
      pending = Promise.resolve(this.resolveIssuer(issuer));
      this.issuers.set(issuer, pending);
    }
    try {
      return await pending;
    } catch (error: unknown) {
      this.issuers.delete(issuer);
      throw error;
    }
  }
}

/** A short, non-sensitive reason string from an unknown error. */
function reason(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

/**
 * Whether a string contains any ASCII control character (C0 range 0x00–0x1F or DEL 0x7F),
 * which includes CR/LF/TAB. Used to reject a WebID claim that could carry an injected
 * newline (the verified WebID is written into the issue body, so it must be single-line).
 * Built char-by-char to avoid a regex literal containing control characters.
 */
function hasControlChar(value: string): boolean {
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}
