// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Server-side composition of the GitHub issue title / body / labels. This MIRRORS
// the FeedbackButton's prefill helpers (composeIssueTitle / composeIssueBody /
// feedbackLabels in app-shell/src/components/feedback.tsx) so the issue a verified
// proxy submission creates is identical to the one the zero-infra prefill flow
// would have opened — but composed from the TRUSTED fields server-side, never from
// the client-supplied title/body/labels (which a malicious caller could tamper).

import { collapseToSingleLine } from "./text.js";
import type { FeedbackCategory, FeedbackDiagnostics } from "./types.js";

/** Per-category title prefix — matches the button's CATEGORIES table. */
const TITLE_PREFIX: Record<FeedbackCategory, string> = {
  bug: "[Bug]",
  feedback: "[Feedback]",
  help: "[Help]",
};

const TITLE_MAX = 80;

/** The category-prefixed title: "<prefix> <first non-empty line of description>". */
export function composeIssueTitle(category: FeedbackCategory, description: string): string {
  const prefix = TITLE_PREFIX[category];
  const firstLine =
    description
      .split("\n")
      .map((l) => l.trim())
      .find(Boolean) ?? "";
  const trimmed =
    firstLine.length > TITLE_MAX ? `${firstLine.slice(0, TITLE_MAX - 1)}…` : firstLine;
  return trimmed ? `${prefix} ${trimmed}` : prefix;
}

// Defence-in-depth: every structured diagnostics value is passed through the shared
// {@link collapseToSingleLine} (src/text.ts) before it reaches a SINGLE `key: value`
// metadata line. The diagnostics fields are already newline-stripped upstream
// (`validate.validatePayload`) and the WebID is control-char-REJECTED in the verifier
// (`verify.extractWebId`), so by the time a value reaches here it is already single-line —
// but the compose step is the last gate before the bytes hit the issue body, so applying
// the same guard here makes a metadata line structurally injection-proof regardless of any
// upstream caller (roborev MEDIUM). The implementation is shared so the control-char
// definition is reviewed once, not re-derived per call site.

/**
 * Compose the issue body: the user's description, then a diagnostics block. The
 * `Reporter WebID` line is emitted ONLY when `diagnostics.webId` is set (consent).
 * Mirrors the button's composeIssueBody. Never includes tokens/secrets.
 *
 * The description is the reporter's own free-text prose and is intentionally left
 * MULTI-LINE (it is the issue body Markdown). Every structured DIAGNOSTICS field, by
 * contrast, goes onto a single `key: value` line, so each is passed through the shared
 * {@link collapseToSingleLine} as the final-gate guarantee that no token/user-derived field
 * can carry a newline that breaks the body structure (defence in depth — upstream already
 * normalises/rejects, this is the last line of defence at the compose step).
 */
export function composeIssueBody(description: string, diagnostics: FeedbackDiagnostics): string {
  const lines: string[] = [];
  lines.push(description.trim());
  lines.push("");
  lines.push("---");
  const version = diagnostics.appVersion ? ` ${collapseToSingleLine(diagnostics.appVersion)}` : "";
  lines.push(`App: ${collapseToSingleLine(diagnostics.appName)}${version}`);
  if (diagnostics.pageUrl) {
    lines.push(`Page: ${collapseToSingleLine(diagnostics.pageUrl)}`);
  }
  if (diagnostics.userAgent) {
    lines.push(`UA: ${collapseToSingleLine(diagnostics.userAgent)}`);
  }
  // PRIVACY: only present when the reporter consented (caller sets webId only then).
  if (diagnostics.webId) {
    lines.push(`Reporter WebID: ${collapseToSingleLine(diagnostics.webId)}`);
  }
  return lines.join("\n");
}

/** The GitHub labels for a category: always `user-feedback` + the category id. */
export function feedbackLabels(category: FeedbackCategory): string[] {
  return ["user-feedback", category];
}
