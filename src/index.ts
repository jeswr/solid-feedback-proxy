// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Public barrel for the feedback-proxy core. The Vercel function imports from here;
// consumers that embed the core on another host can too.

export {
  isValidRepoSlug,
  loadConfig,
  type ProxyConfig,
  ProxyConfigError,
  parseList,
} from "./config.js";
export { corsHeaders } from "./cors.js";
export { type CreateIssueInput, createIssue, type FetchLike, GitHubApiError } from "./github.js";
export {
  type HandlerDeps,
  handleFeedback,
  type ProxyRequest,
  type ProxyResponse,
} from "./handler.js";
export { composeIssueBody, composeIssueTitle, feedbackLabels } from "./issue.js";
export { RateLimiter, type RateLimitResult } from "./rateLimit.js";
export { InProcessReplayStore, type ReplayStore } from "./replayStore.js";
export { collapseToSingleLine, hasControlChar, isControlCodePoint } from "./text.js";
export {
  FEEDBACK_CATEGORIES,
  type FeedbackCategory,
  type FeedbackDiagnostics,
  type FeedbackPayload,
  type FeedbackSubmitResult,
} from "./types.js";
export { ValidationError, validatePayload } from "./validate.js";
export {
  DpopTokenVerifier,
  type IssuerConfig,
  isLoopbackHttp,
  parseAuthorization,
  TokenVerifyError,
  type VerifiedCaller,
  type VerifierOptions,
  type VerifyRequest,
} from "./verify.js";
