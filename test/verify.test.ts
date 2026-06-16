// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Exhaustive token-verification tests: accept the happy path, then reject on every
// independent failure (bad issuer, bare Bearer, missing/wrong/absent DPoP proof,
// expired token, wrong audience, wrong htu/htm, broken cnf.jkt binding, missing/non-
// https webid). Mirrors prod-solid-server's verifier test discipline.

import { describe, expect, it } from "vitest";
import { DpopTokenVerifier, TokenVerifyError } from "../src/verify.js";
import {
  AUDIENCE,
  ENDPOINT_URL,
  ISSUER,
  inlineResolver,
  type KeyMaterial,
  makeDpopProof,
  makeKeys,
  makeVerifyRequest,
  WEBID,
} from "./helpers.js";

function verifier(keys: KeyMaterial, issuer = ISSUER) {
  return new DpopTokenVerifier(
    { trustedIssuers: [ISSUER], webidClaim: "webid", audience: AUDIENCE },
    inlineResolver(keys, issuer),
  );
}

describe("DpopTokenVerifier — accept", () => {
  it("accepts a valid DPoP-bound token and returns the WebID + issuer", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys);
    const caller = await verifier(keys).verify(req);
    expect(caller.webId).toBe(WEBID);
    expect(caller.issuer).toBe(ISSUER);
    expect(caller.clientId).toBe("test-client");
  });
});

describe("DpopTokenVerifier — reject", () => {
  it("rejects when no Authorization header is present", async () => {
    const keys = await makeKeys();
    await expect(
      verifier(keys).verify({
        authorization: undefined,
        dpop: undefined,
        method: "POST",
        url: ENDPOINT_URL,
      }),
    ).rejects.toBeInstanceOf(TokenVerifyError);
  });

  it("rejects a bare Bearer token (DPoP required)", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys);
    await expect(
      verifier(keys).verify({
        ...req,
        authorization: req.authorization?.replace("DPoP", "Bearer"),
      }),
    ).rejects.toThrow(/DPoP-bound token is required/);
  });

  it("rejects when the DPoP proof header is absent", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys);
    await expect(verifier(keys).verify({ ...req, dpop: undefined })).rejects.toThrow(
      /Missing DPoP proof/,
    );
  });

  it("rejects an untrusted issuer BEFORE any discovery", async () => {
    const keys = await makeKeys();
    // Token minted by a different issuer than the verifier trusts.
    const req = await makeVerifyRequest(keys, {
      tokenOptions: { issuer: "https://evil.example" },
    });
    // The resolver would throw on the wrong issuer; but the allowlist must reject first.
    await expect(verifier(keys).verify(req)).rejects.toThrow(/issuer is not trusted/);
  });

  it("rejects an expired access token", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, { tokenOptions: { expiresInSec: -60 } });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/verification failed/i);
  });

  it("rejects a token minted for a different audience", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, { tokenOptions: { audience: "https://other.rs" } });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/verification failed/i);
  });

  it("rejects a proof whose htu does not match this endpoint", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, {
      proofOptions: { htu: "https://feedback.test.example/other" },
    });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/verification failed/i);
  });

  it("rejects a proof whose htm does not match the method", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, { proofOptions: { htm: "GET" } });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/verification failed/i);
  });

  it("rejects a proof not bound to the token (broken cnf.jkt)", async () => {
    const keys = await makeKeys();
    const other = await makeKeys();
    // Sign the proof with a DIFFERENT DPoP key than the token's cnf.jkt was computed from.
    const token = await (await import("./helpers.js")).makeAccessToken(keys);
    const proof = await makeDpopProof(other, { accessToken: token, htu: ENDPOINT_URL });
    await expect(
      verifier(keys).verify({
        authorization: `DPoP ${token}`,
        dpop: proof,
        method: "POST",
        url: ENDPOINT_URL,
      }),
    ).rejects.toThrow(/verification failed/i);
  });

  it("rejects a token missing the webid claim", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, { tokenOptions: { omitWebId: true } });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/missing the 'webid' claim/);
  });

  it("rejects a non-https webid claim", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, {
      tokenOptions: { webId: "http://alice.example/card#me" },
    });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/must be an https/);
  });

  it("rejects a webid with embedded userinfo", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, {
      tokenOptions: { webId: "https://user:pass@alice.example/card#me" },
    });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/must not include userinfo/);
  });

  it("rejects a webid claim containing a newline (metadata-line injection guard)", async () => {
    const keys = await makeKeys();
    // `new URL()` would silently strip the newline and accept this; the explicit
    // control-char check must reject it BEFORE it can reach the issue body.
    const req = await makeVerifyRequest(keys, {
      tokenOptions: { webId: "https://alice.example/card#me\nReporter WebID: https://evil/x" },
    });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/control characters/);
  });

  it("rejects a webid claim containing a tab/CR control char", async () => {
    const keys = await makeKeys();
    const req = await makeVerifyRequest(keys, {
      tokenOptions: { webId: "https://alice.example/\tcard#me" },
    });
    await expect(verifier(keys).verify(req)).rejects.toThrow(/control characters/);
  });

  it("rejects a malformed access token", async () => {
    const keys = await makeKeys();
    await expect(
      verifier(keys).verify({
        authorization: "DPoP not-a-jwt",
        dpop: "x",
        method: "POST",
        url: ENDPOINT_URL,
      }),
    ).rejects.toThrow(/Malformed access token/);
  });

  it("rejects a replayed DPoP proof (same jti used twice)", async () => {
    const keys = await makeKeys();
    const v = verifier(keys);
    // Same token + same proof (same jti) presented twice → first ok, second is a replay.
    const req = await makeVerifyRequest(keys);
    await expect(v.verify(req)).resolves.toMatchObject({ webId: WEBID });
    await expect(v.verify(req)).rejects.toThrow(/already been used \(replay\)/);
  });
});

describe("DpopTokenVerifier — construction", () => {
  it("requires at least one trusted issuer", async () => {
    const keys = await makeKeys();
    expect(
      () =>
        new DpopTokenVerifier(
          { trustedIssuers: [], webidClaim: "webid", audience: AUDIENCE },
          inlineResolver(keys),
        ),
    ).toThrow(/at least one trusted issuer/);
  });

  it("requires an audience", async () => {
    const keys = await makeKeys();
    expect(
      () =>
        new DpopTokenVerifier(
          { trustedIssuers: [ISSUER], webidClaim: "webid", audience: "" },
          inlineResolver(keys),
        ),
    ).toThrow(/requires an audience/);
  });
});
