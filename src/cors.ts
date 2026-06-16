// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// CORS for the suite app origins ONLY. We reflect the request's `Origin` back in
// `Access-Control-Allow-Origin` ONLY when it is on the configured allowlist (never a
// wildcard `*`, which would expose the authenticated endpoint to any site). An origin
// not on the allowlist gets NO CORS headers — the browser then blocks the cross-origin
// read, while same-origin / non-browser callers (which do not enforce CORS) are
// unaffected. We must allow the `Authorization` and `DPoP` request headers and vary on
// `Origin` so a CDN does not cache one origin's CORS response for another.

/** The CORS response headers for a given request origin, given the allowlist. */
export function corsHeaders(
  origin: string | undefined,
  allowedOrigins: readonly string[],
): Record<string, string> {
  if (origin === undefined || !allowedOrigins.includes(origin)) {
    // Not an allowed origin: emit only `Vary` so caches key correctly; no ACAO.
    return { vary: "Origin" };
  }
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Authorization, DPoP, Content-Type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}
