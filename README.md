# solid-feedback-proxy

> ⚠️ **Experimental — AI-agent-generated.** Created by an AI coding agent (Claude Opus 4.8,
> @jeswr's PSS agent). Auth + secret-handling service — review before relying on it in production.

A small, Vercel-deployable serverless backend that lets **non-technical Solid pod users file GitHub
issues without a GitHub account.** It is the server-side `submit` hook behind the suite's in-app
**FeedbackButton** (`app-shell/src/components/feedback.tsx`): the button POSTs its feedback payload
here, this service authenticates the caller against their **Solid session**, then creates the issue
on the app's repo using a **server-side GitHub token** the user never sees.

```
FeedbackButton.submit(payload)
        │  POST /feedback   (Authorization: DPoP <token> + DPoP proof)
        ▼
solid-feedback-proxy  ──►  verify DPoP-bound Solid-OIDC token  (issuer-agnostic, asymmetric-only)
        │                  ──►  repo allowlist + per-WebID/IP rate limit + input validation
        │                  ──►  compose issue server-side (labels user-feedback + category)
        ▼
   POST https://api.github.com/repos/{owner}/{repo}/issues   (server-side token)
        │
        ▼
   { url, number }   ──►  back to the button as FeedbackSubmitResult
```

## Why a proxy at all?

The FeedbackButton has two mechanisms. The zero-infra default opens GitHub's prefilled new-issue
page — but that requires the reporter to have a GitHub account. This proxy is the other mechanism: a
signed-in pod user (who has **no GitHub account**) can file an issue, because the proxy holds the
GitHub credential and the user's authenticated **Solid identity** is the abuse-control + provenance
signal instead.

## The endpoint + the contract

`POST /feedback` (the CORS `OPTIONS` preflight is also handled).

**Request body** — exactly the FeedbackButton's `FeedbackPayload` (the button POSTs it verbatim):

```jsonc
{
  "repo": "jeswr/pod-mail",          // OWNER/REPO — MUST be on the allowlist
  "category": "bug",                  // "bug" | "feedback" | "help"
  "description": "Save does nothing", // the free text the user typed
  "diagnostics": {
    "appName": "Pod Mail",
    "appVersion": "1.0.0",            // optional
    "pageUrl": "https://app/…",       // optional
    "userAgent": "…",                 // optional
    "webId": "https://alice…/card#me" // PRESENT ONLY when the user consented (privacy)
  }
  // title / body / labels MAY be sent (the button composes them) but are IGNORED:
  // the proxy recomposes them server-side from the trusted fields above.
}
```

**Success response** — exactly the button's `FeedbackSubmitResult`:

```json
{ "url": "https://github.com/jeswr/pod-mail/issues/42", "number": 42 }
```

The composed issue matches the prefill flow: title `"[Bug] <first line>"`, body = the description +
a diagnostics block (the `Reporter WebID:` line appears **only** when the user consented), labels
`["user-feedback", "<category>"]`.

**Error responses** — `{ "error": "…" }` with status: `400` invalid body, `401` auth failure (with
a `WWW-Authenticate: DPoP …` challenge), `403` repo not on the allowlist, `405` wrong method, `415`
non-JSON Content-Type, `429` rate-limited (with `Retry-After`), `502` GitHub upstream failure, `500`
server misconfigured.

### Wiring the button to this proxy

```ts
import { FeedbackButton, type FeedbackPayload, type FeedbackSubmitResult } from "@jeswr/app-shell";

async function submit(payload: FeedbackPayload): Promise<FeedbackSubmitResult> {
  // `authedFetch` is the app's DPoP-bound fetch (the suite reactive-auth session) — it
  // attaches `Authorization: DPoP <token>` + the matching `DPoP` proof for THIS URL.
  const res = await authedFetch("https://feedback.solid-test.jeswr.org/feedback", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? "Feedback failed");
  return res.json();
}

<FeedbackButton repo="jeswr/pod-mail" appName="Pod Mail" webId={webId} submit={submit} />;
```

The DPoP proof's `htu` MUST be this endpoint's external URL and `htm` MUST be `POST` — the suite
DPoP fetch does this automatically.

## The auth gate (Solid-native)

Every request MUST present a **DPoP-bound Solid-OIDC access token** (`Authorization: DPoP <token>`
plus a matching `DPoP` proof header). Verification reuses the **same approach + libraries as
prod-solid-server's verifier** — `oauth4webapi` (RFC 6750 / 9068 / 9449) does the full orchestration
and `jose` resolves the issuer JWKS; **nothing is hand-rolled**:

- **Issuer-agnostic, allowlisted.** The token's `iss` must be on the trusted-issuer allowlist
  (`FEEDBACK_TRUSTED_ISSUERS` — the suite broker + the local dev issuer). The allowlist is checked
  from the *unverified* `iss` **before** any OIDC discovery, so an untrusted issuer never makes the
  proxy dereference its discovery document. The IdP is swappable.
- **Asymmetric-only.** `ES*`/`PS*`/`RS*` for both the token and the proof; `HS*`/`none` rejected.
- **DPoP proof-of-possession.** The proof must bind the token (`ath` + `cnf.jkt`), its `htm`/`htu`
  must match this request + endpoint, and `iat` must be fresh — all enforced by the library.
- **Replay-protected.** Each accepted proof's `jti` is remembered for the freshness window; a
  reused proof is rejected, so a captured request cannot be replayed to file a duplicate issue.
  (In-memory per instance — see "Production hardening" for the shared-store note.)
- **Audience-bound** (RFC 9068). The token's `aud` must equal `FEEDBACK_AUDIENCE` (this proxy's own
  URL), so a token minted for another resource server is rejected.
- **WebID extracted** from the configured claim (must be an `https:` URL without userinfo). Only a
  verified WebID may file. That WebID is the provenance. The client's `diagnostics.webId` is treated
  purely as a **consent flag**: when present, the proxy records the **verified token WebID** (never
  the client-supplied value, so a caller cannot attribute a report to someone else); when absent, no
  WebID is written — it is used solely as the (hashed) rate-limit key.

A bare Bearer token is rejected — proof-of-possession is required.

## Repo allowlist + rate limit + abuse controls

- **Repo allowlist** (`FEEDBACK_ALLOWED_REPOS`): the `repo` must be one of the configured suite
  repos, so a stolen/valid token can never file on an arbitrary repository. Each allowlist entry is
  validated to be a strict `OWNER/REPO` slug.
- **Rate limit** (`FEEDBACK_RATE_LIMIT` per `FEEDBACK_RATE_WINDOW_MS`): per-WebID **and** per-IP,
  fixed-window, checked together so a request blocked by one key never burns the other's quota.
  Over-limit → `429` + `Retry-After`. **In-memory** — see "Production hardening". The per-IP key
  comes from Vercel's trusted `x-real-ip` (the spoofable `X-Forwarded-For` is deliberately ignored,
  so a client cannot prepend a fake hop to choose an arbitrary IP key and bypass the limit).
- **Pre-auth IP throttle**: a cheaper per-IP limiter runs **before** token verification, so an
  unauthenticated / invalid-token flood cannot repeatedly drive the verifier + JWKS path (a DoS
  guard). It is more generous than the post-auth quota so legitimate retries are unaffected.
- **Content-Type gate**: a request must carry `Content-Type: application/json` (a `; charset=…`
  suffix is fine) or it is rejected with `415` **up front** — before any auth, rate-limiting or
  token work. The adapter enforces this at the edge and the core re-checks (defence in depth).
- **Defensive body parsing**: the adapter does not blindly trust `req.body`. A raw JSON **string**
  body is `JSON.parse`d in a try/catch (malformed → `400`); an already-parsed object is used as-is;
  anything else (missing / non-object) falls through to shape validation, which `400`s it. The core
  never sees an unparsed string.
- **Cheap rejects first**: content-type + body-shape validation + the repo allowlist run **before**
  authentication and rate-limiting, so a malformed / oversized / off-allowlist body cannot consume
  the (expensive) verifier path or the shared GitHub-token rate budget.
- **Request size cap**: the Vercel function limits the parsed JSON body (64 kb) so an oversized
  payload is rejected at the platform edge before it is parsed into memory.
- **Input validation**: strict shape/type/enum checks (run before auth, see above); the description
  is length-capped (`FEEDBACK_MAX_DESCRIPTION`); the client's `title`/`body`/`labels` are dropped
  and recomposed server-side.
- **CORS** (`FEEDBACK_ALLOWED_ORIGINS`): the request `Origin` is reflected **only** when allowlisted
  (never `*`); `Authorization` + `DPoP` request headers are permitted; responses `Vary: Origin`.
- **No SSRF / no secret logging**: the only outbound call is to `api.github.com` (a fixed host); the
  GitHub token and the DPoP proof are never logged.

## ⚠️ The GitHub token the maintainer must provision (`needs:user`)

This is the one human action required before deploy. Create a **fine-grained Personal Access
Token** and set it as `FEEDBACK_GITHUB_TOKEN`:

1. GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens →
   Generate new token.**
2. **Resource owner:** `jeswr`.
3. **Repository access → Only select repositories:** select **exactly** the repos you list in
   `FEEDBACK_ALLOWED_REPOS` (e.g. `pod-mail`, `pod-drive`, `solid-pod-manager`, `solid-issues`).
4. **Repository permissions → Issues → Read and write.** Grant **nothing else** (least privilege —
   this token can only create/read issues on those repos).
5. **Expiration:** pick a finite expiry and set a calendar reminder to rotate. Treat the value like
   a password — set it as a Vercel **Environment Variable** (encrypted), never commit it.

If the token is exposed, **revoke it in GitHub and generate a new one**; the proxy needs no code
change, just the new env value.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `FEEDBACK_GITHUB_TOKEN` | ✅ | The fine-grained GitHub PAT above (issues:write on the allowed repos). **Secret.** |
| `FEEDBACK_ALLOWED_REPOS` | ✅ | Space/comma-separated `OWNER/REPO` values a caller may file against. |
| `FEEDBACK_TRUSTED_ISSUERS` | ✅ | Space/comma-separated Solid-OIDC issuer URLs to trust (suite broker + dev issuer). |
| `FEEDBACK_AUDIENCE` | ✅ | This proxy's own public URL — the expected token `aud` (RFC 9068). |
| `FEEDBACK_ALLOWED_ORIGINS` | ✅ | Space/comma-separated browser origins allowed by CORS. |
| `FEEDBACK_PUBLIC_URL` | optional | The exact public endpoint URL the client calls + signs into the DPoP `htu` (default `<audience>/feedback`). Set this if your public path differs from the default — it is used for `htu` verification, immune to the Vercel `/feedback` → `/api/feedback` rewrite. |
| `FEEDBACK_HASH_SECRET` | optional | A stable secret used to HMAC the rate-limit keys (WebID / IP) so they are not dictionary-reversible. Defaults to a per-instance random value (fine for the in-memory limiter). **Set a stable value if you back the limiter with a shared store** (Upstash Redis / Vercel KV) so keys are consistent across instances. |
| `FEEDBACK_WEBID_CLAIM` | optional | The JWT claim carrying the WebID (default `webid`). |
| `FEEDBACK_RATE_LIMIT` | optional | Max issues per WebID (and per IP) per window (default `5`). |
| `FEEDBACK_RATE_WINDOW_MS` | optional | Rate-limit window in ms (default `3600000` = 1 hour). |
| `FEEDBACK_MAX_DESCRIPTION` | optional | Max description characters (default `8000`). |

See [`.env.example`](./.env.example) for a copy-paste template.

## Deploy (Vercel — the suite's free hosting preference)

1. Provision the GitHub token above.
2. Push this repo to GitHub, then **import it into Vercel** (or `vercel` CLI). It is a zero-config
   Vercel project: `api/feedback.ts` becomes the function and `vercel.json` rewrites `/feedback` →
   `/api/feedback`.
3. Set the environment variables above as **Vercel Project Environment Variables** (mark
   `FEEDBACK_GITHUB_TOKEN` as a secret).
4. Point the apps' `submit` hook at `https://<your-deployment>/feedback` and ensure
   `FEEDBACK_AUDIENCE` matches the URL the apps request a token for + call.

The function is framework-agnostic at its core (`src/handler.ts`), so it can also run on any host
that gives it an HTTP request; `api/feedback.ts` is a thin Vercel adapter.

## Production hardening

The rate limiter **and** the DPoP-proof replay cache are **in-memory** (per function instance).
Vercel scales to many warm instances, so a determined abuser hitting different instances could
exceed the per-key limit, and a replay could land on a different instance than the original. For
production-grade behaviour, back both with a **shared TTL store** (Upstash Redis / Vercel KV) behind
the same `RateLimiter.take()` / `ReplayStore.mark()` contracts — see `src/rateLimit.ts` and
`src/replayStore.ts`. The in-memory versions are the floor (they stop casual abuse, accidental
loops, and same-instance replays), not the ceiling.

## Develop & test

```sh
npm install
npm run lint        # biome
npm run typecheck   # tsc --noEmit
npm test            # vitest — token-verify (accept/reject + replay), rate limit, validation,
                    # repo allowlist, CORS, WebID-spoof rejection, GitHub (mocked), full pipeline
npm run build       # tsc --noEmit (this is a serverless function, not a published package)
```

The whole suite is hermetic: the issuer JWKS is injected (no discovery/network), and the single
outbound GitHub call is mocked. Token + DPoP-proof fixtures are minted with `jose` in
`test/helpers.ts`.

## License

MIT © Jesse Wright
