// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The wire contract between the suite's in-app FeedbackButton (`submit` hook) and
// this proxy. These shapes are copied EXACTLY from
// `app-shell/src/components/feedback.tsx` (FeedbackPayload / FeedbackDiagnostics /
// FeedbackSubmitResult / FeedbackCategory) so the button can POST its payload
// verbatim and read back the result without any adaptation. If the button's shape
// changes, update both in the same change (the suite cross-app parity rule).

/** The three feedback categories. The value doubles as a GitHub label. */
export type FeedbackCategory = "bug" | "feedback" | "help";

/** The set of valid categories, used for input validation. */
export const FEEDBACK_CATEGORIES: readonly FeedbackCategory[] = ["bug", "feedback", "help"];

/**
 * The diagnostics block, structured. Mirrors FeedbackDiagnostics in the button.
 * The WebID is present ONLY when the reporter consented to share it (privacy).
 */
export interface FeedbackDiagnostics {
  appName: string;
  appVersion?: string;
  /** The page the feedback was raised from (`location.href`). */
  pageUrl?: string;
  /** The browser user-agent. */
  userAgent?: string;
  /** Present ONLY when the reporter consented to share their WebID. */
  webId?: string;
}

/**
 * The payload the FeedbackButton's `submit` hook POSTs. Mirrors FeedbackPayload in
 * the button. The proxy recomposes the title/body/labels server-side from the
 * trusted fields (`description`, `category`, `diagnostics`) rather than trusting
 * the client's `title`/`body`/`labels`, so a malicious client cannot inject
 * arbitrary labels or a body the diagnostics block does not match.
 */
export interface FeedbackPayload {
  /** "jeswr/pod-mail" — the OWNER/REPO the issue is filed against. */
  repo: string;
  /** The selected category (also a GitHub label). */
  category: FeedbackCategory;
  /** The full issue title the button composed (informational; the proxy recomposes). */
  title?: string;
  /** The full issue body the button composed (informational; the proxy recomposes). */
  body?: string;
  /** The GitHub labels the button composed (informational; the proxy recomposes). */
  labels?: string[];
  /** The raw description the user typed (without the diagnostics block). */
  description: string;
  /** Diagnostics appended to the body. */
  diagnostics: FeedbackDiagnostics;
}

/**
 * The result the `submit` hook resolves with: the created issue's URL + number.
 * Mirrors FeedbackSubmitResult in the button.
 */
export interface FeedbackSubmitResult {
  url: string;
  number: number;
}
