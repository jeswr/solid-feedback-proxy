// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Test helpers: mint RFC 9068 DPoP-bound access tokens + RFC 9449 DPoP proofs with
// `jose` (asymmetric ES256), and an injectable issuer resolver that hands the verifier
// an inline JWKS so no network/discovery happens. Mirrors how prod-solid-server's
// verifier tests inject `IssuerConfig.jwks`.

import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import type { IssuerConfig, VerifyRequest } from "../src/verify.js";

/** The private-key half jose's `generateKeyPair` yields — used for signing in tests. */
type SigningKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

export const ISSUER = "https://idp.test.example";
export const AUDIENCE = "https://feedback.test.example";
export const WEBID = "https://alice.test.example/profile/card#me";
export const ENDPOINT_URL = "https://feedback.test.example/feedback";

export interface KeyMaterial {
  /** The issuer's signing key (signs the access token). */
  readonly issuerPrivate: SigningKey;
  /** The issuer's public JWK, with a `kid` so the JWKS resolves by key id. */
  readonly issuerPublicJwk: JWK;
  /** The kid of the issuer key (also set on `issuerPublicJwk.kid`). */
  readonly issuerKid: string;
  /** The client's DPoP key (signs the proof; its thumbprint is the token's cnf.jkt). */
  readonly dpopPrivate: SigningKey;
  readonly dpopPublicJwk: JWK;
  readonly jkt: string;
}

/** Generate a fresh issuer key + DPoP key pair for one test. */
export async function makeKeys(): Promise<KeyMaterial> {
  const issuer = await generateKeyPair("ES256", { extractable: true });
  const dpop = await generateKeyPair("ES256", { extractable: true });
  const issuerKid = "test-issuer-key";
  const issuerPublicJwk: JWK = { ...(await exportJWK(issuer.publicKey)), kid: issuerKid };
  const dpopPublicJwk = await exportJWK(dpop.publicKey);
  const jkt = await calculateJwkThumbprint(dpopPublicJwk, "sha256");
  return {
    issuerPrivate: issuer.privateKey,
    issuerPublicJwk,
    issuerKid,
    dpopPrivate: dpop.privateKey,
    dpopPublicJwk,
    jkt,
  };
}

/** An issuer resolver that returns an inline JWKS so the verifier does no network I/O. */
export function inlineResolver(keys: KeyMaterial, issuer = ISSUER): (iss: string) => IssuerConfig {
  return (iss: string): IssuerConfig => {
    if (iss !== issuer) {
      throw new Error(`unexpected issuer ${iss}`);
    }
    // jose's JWK and oauth4webapi's JWKS.keys differ only in optional-property
    // variance under exactOptionalPropertyTypes; the runtime shape is identical.
    const jwks = { keys: [keys.issuerPublicJwk] } as unknown as NonNullable<IssuerConfig["jwks"]>;
    return {
      as: { issuer, jwks_uri: `${issuer}/jwks` },
      jwks,
    };
  };
}

export interface AccessTokenOptions {
  issuer?: string;
  audience?: string;
  webId?: string;
  webidClaim?: string;
  jkt?: string | undefined;
  clientId?: string;
  /** Seconds from now for `exp` (negative = expired). */
  expiresInSec?: number;
  /** Override `iat` (epoch seconds). */
  iat?: number;
  /** Omit the webid claim entirely. */
  omitWebId?: boolean;
}

/** Mint an RFC 9068 `at+jwt` access token, DPoP-bound via `cnf.jkt` unless `jkt` is null. */
export async function makeAccessToken(
  keys: KeyMaterial,
  opts: AccessTokenOptions = {},
): Promise<string> {
  const nowSec = opts.iat ?? Math.floor(Date.now() / 1000);
  const exp = nowSec + (opts.expiresInSec ?? 300);
  const webidClaim = opts.webidClaim ?? "webid";
  const cnfJkt = opts.jkt === undefined ? keys.jkt : opts.jkt;

  const payload: Record<string, unknown> = {
    sub: "test-subject",
    client_id: opts.clientId ?? "test-client",
    jti: `at-${Math.random().toString(36).slice(2)}`,
  };
  if (!opts.omitWebId) {
    payload[webidClaim] = opts.webId ?? WEBID;
  }
  if (cnfJkt !== null) {
    payload.cnf = { jkt: cnfJkt };
  }

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid: keys.issuerKid })
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? AUDIENCE)
    .setIssuedAt(nowSec)
    .setExpirationTime(exp)
    .sign(keys.issuerPrivate);
}

export interface DpopProofOptions {
  htm?: string;
  htu?: string;
  /** Override the embedded public JWK (e.g. to break the cnf.jkt binding). */
  jwk?: JWK;
  /** Include an `ath` claim (the access-token hash). When set, pass the access token. */
  accessToken?: string;
  /** Omit `ath` (default false — a correct proof binds the token). */
  omitAth?: boolean;
  iatOffsetSec?: number;
  /** Use a fixed jti so two proofs collide (replay test). */
  jti?: string;
}

/** Compute the RFC 9449 `ath` (base64url SHA-256 of the access token). */
async function ath(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken));
  return Buffer.from(new Uint8Array(digest)).toString("base64url");
}

/** Mint an RFC 9449 `dpop+jwt` proof signed by the client's DPoP key. */
export async function makeDpopProof(
  keys: KeyMaterial,
  opts: DpopProofOptions = {},
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000) + (opts.iatOffsetSec ?? 0);
  const payload: Record<string, unknown> = {
    htm: opts.htm ?? "POST",
    htu: opts.htu ?? ENDPOINT_URL,
    jti: opts.jti ?? `proof-${Math.random().toString(36).slice(2)}`,
  };
  if (!opts.omitAth && opts.accessToken) {
    payload.ath = await ath(opts.accessToken);
  }
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: opts.jwk ?? keys.dpopPublicJwk,
    })
    .setIssuedAt(nowSec)
    .sign(keys.dpopPrivate);
}

/** Build a `VerifyRequest` with a DPoP-bound token + proof for the default endpoint. */
export async function makeVerifyRequest(
  keys: KeyMaterial,
  overrides: {
    tokenOptions?: AccessTokenOptions;
    proofOptions?: DpopProofOptions;
    method?: string;
    url?: string;
  } = {},
): Promise<VerifyRequest> {
  const token = await makeAccessToken(keys, overrides.tokenOptions);
  const proof = await makeDpopProof(keys, {
    accessToken: token,
    htu: overrides.url ?? ENDPOINT_URL,
    htm: overrides.method ?? "POST",
    ...overrides.proofOptions,
  });
  return {
    authorization: `DPoP ${token}`,
    dpop: proof,
    method: overrides.method ?? "POST",
    url: overrides.url ?? ENDPOINT_URL,
  };
}
