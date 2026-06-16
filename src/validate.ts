// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Strict, defensive validation + normalisation of the untrusted request body into a
// canonical FeedbackPayload. Everything that reaches the issue-composer or the
// GitHub API must pass through here. We accept ONLY the fields we use, coerce
// nothing implicitly, cap lengths, and require `description` to be non-empty.

import type { ProxyConfig } from "./config.js";
import { FEEDBACK_CATEGORIES, type FeedbackCategory, type FeedbackPayload } from "./types.js";

/** Thrown on a malformed/oversized/empty request body — surfaces as 400. */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/** Caps on diagnostic strings so a malicious client cannot blow up the issue body. */
const LIMITS = {
  appName: 200,
  appVersion: 100,
  pageUrl: 2000,
  userAgent: 1000,
  webId: 2000,
} as const;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireString(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") {
    throw new ValidationError(`Field "${field}" must be a string.`);
  }
  if (value.length > max) {
    throw new ValidationError(`Field "${field}" exceeds the maximum length of ${max}.`);
  }
  return value;
}

function optionalString(value: unknown, field: string, max: number): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  const s = requireString(value, field, max);
  return s.length > 0 ? s : undefined;
}

/**
 * Collapse newlines + other control characters in a single-line diagnostic field to
 * spaces (and trim). This is the anti-injection control (roborev MEDIUM): without it a
 * caller could embed `\nReporter WebID: …` (or any forged metadata line) in `appName` /
 * `appVersion` / `pageUrl` / `userAgent` and spoof the diagnostics block — these fields
 * are single-line by nature, so stripping line breaks is both correct and load-bearing.
 */
function singleLine(value: string): string {
  // Drop ASCII control chars (incl. CR/LF/TAB, code points 0-31) and DEL (127); collapse
  // surrounding whitespace. Building char-by-char avoids a regex literal with control chars.
  let out = "";
  let lastWasSpace = false;
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    const isControl = code < 0x20 || code === 0x7f;
    if (isControl || ch === " ") {
      if (!lastWasSpace) {
        out += " ";
        lastWasSpace = true;
      }
    } else {
      out += ch;
      lastWasSpace = false;
    }
  }
  return out.trim();
}

/** As {@link optionalString}, but normalised to a single line (no injectable line breaks). */
function optionalSingleLine(value: unknown, field: string, max: number): string | undefined {
  const s = optionalString(value, field, max);
  if (s === undefined) {
    return undefined;
  }
  const collapsed = singleLine(s);
  return collapsed.length > 0 ? collapsed : undefined;
}

/** An `https:` URL with no embedded userinfo — the shape a real WebID has. */
function isHttpsUrlNoUserinfo(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && !url.username && !url.password;
}

/**
 * Validate + normalise an untrusted JSON body into a canonical {@link FeedbackPayload}.
 * The client-supplied `title`/`body`/`labels` are intentionally DROPPED here — the
 * server recomposes them (see `issue.ts`) from the trusted `description`/`category`/
 * `diagnostics`, so a caller cannot inject arbitrary labels or a mismatched body.
 *
 * `repo` allowlisting is NOT done here (that needs the config + is the auth layer's
 * concern); this only validates shape, types, lengths and the category enum.
 */
export function validatePayload(raw: unknown, config: ProxyConfig): FeedbackPayload {
  if (!isObject(raw)) {
    throw new ValidationError("Request body must be a JSON object.");
  }

  const repo = requireString(raw.repo, "repo", 200);

  if (typeof raw.category !== "string" || !isCategory(raw.category)) {
    throw new ValidationError(
      `Field "category" must be one of: ${FEEDBACK_CATEGORIES.join(", ")}.`,
    );
  }
  const category: FeedbackCategory = raw.category;

  const description = requireString(raw.description, "description", config.maxDescriptionLength);
  if (description.trim().length === 0) {
    throw new ValidationError(`Field "description" must not be empty.`);
  }

  if (!isObject(raw.diagnostics)) {
    throw new ValidationError(`Field "diagnostics" must be an object.`);
  }
  const d = raw.diagnostics;
  const appName = singleLine(requireString(d.appName, "diagnostics.appName", LIMITS.appName));
  if (appName.length === 0) {
    throw new ValidationError(`Field "diagnostics.appName" must not be empty.`);
  }

  const webId = optionalString(d.webId, "diagnostics.webId", LIMITS.webId);
  if (webId !== undefined && !isHttpsUrlNoUserinfo(webId)) {
    throw new ValidationError(`Field "diagnostics.webId" must be an https: URL without userinfo.`);
  }

  const diagnostics: FeedbackPayload["diagnostics"] = {
    appName,
    // The four single-line diagnostic fields are newline-stripped (anti-injection) so a
    // caller cannot forge extra metadata lines (e.g. a fake `Reporter WebID:`) in the body.
    ...optionalField(
      "appVersion",
      optionalSingleLine(d.appVersion, "diagnostics.appVersion", LIMITS.appVersion),
    ),
    ...optionalField(
      "pageUrl",
      optionalSingleLine(d.pageUrl, "diagnostics.pageUrl", LIMITS.pageUrl),
    ),
    ...optionalField(
      "userAgent",
      optionalSingleLine(d.userAgent, "diagnostics.userAgent", LIMITS.userAgent),
    ),
    ...optionalField("webId", webId),
  };

  return { repo, category, description, diagnostics };
}

/** Helper so we never assign `undefined` onto an exactOptionalPropertyTypes field. */
function optionalField<K extends string, V>(key: K, value: V | undefined): Record<K, V> | object {
  return value === undefined ? {} : ({ [key]: value } as Record<K, V>);
}

function isCategory(v: string): v is FeedbackCategory {
  return (FEEDBACK_CATEGORIES as readonly string[]).includes(v);
}
