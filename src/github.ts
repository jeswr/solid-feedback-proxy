// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The single outbound call this service makes: create a GitHub issue via the REST API
// (`POST /repos/{owner}/{repo}/issues`) using the server-side token. There is NO other
// network egress — no SSRF surface, because the URL is built ONLY from an
// allowlist-validated repo slug + a fixed api.github.com host. The token is sent in the
// Authorization header and NEVER logged.

import type { FeedbackSubmitResult } from "./types.js";

/** The GitHub API host. Hard-coded — the only host this service ever contacts. */
const GITHUB_API = "https://api.github.com";

/** Thrown when GitHub rejects the create-issue call — surfaces as 502 (upstream failure). */
export class GitHubApiError extends Error {
  /** The HTTP status GitHub returned (or 0 if the call never completed). */
  readonly upstreamStatus: number;
  constructor(message: string, upstreamStatus: number) {
    super(message);
    this.name = "GitHubApiError";
    this.upstreamStatus = upstreamStatus;
  }
}

/** The fields a created issue needs. */
export interface CreateIssueInput {
  /** OWNER/REPO — MUST already be allowlist-validated by the caller. */
  readonly repo: string;
  readonly title: string;
  readonly body: string;
  readonly labels: string[];
}

/** The `fetch` shape we depend on — injectable so tests mock the outbound call. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/**
 * Create a GitHub issue. Returns {@link FeedbackSubmitResult} (`{ url, number }`) on
 * success; throws {@link GitHubApiError} (→ 502) on any non-2xx / network failure.
 *
 * The repo slug is path-encoded defensively even though it is already allowlist-
 * validated, so the URL can never be anything but `…/repos/<owner>/<repo>/issues`.
 */
export async function createIssue(
  input: CreateIssueInput,
  token: string,
  fetchImpl: FetchLike = (i, init) => fetch(i, init),
): Promise<FeedbackSubmitResult> {
  const [owner, repo] = input.repo.split("/");
  if (!owner || !repo) {
    // Defensive: the caller validates the slug, so this is unreachable in practice.
    throw new GitHubApiError(`Invalid repo slug: ${input.repo}`, 0);
  }
  const url = `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`;

  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: {
        // GitHub's documented bearer form; never logged.
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "user-agent": "solid-feedback-proxy",
        "x-github-api-version": "2022-11-28",
      },
      body: JSON.stringify({ title: input.title, body: input.body, labels: input.labels }),
    });
  } catch (error) {
    throw new GitHubApiError(
      `GitHub request failed: ${error instanceof Error ? error.message : "network error"}`,
      0,
    );
  }

  if (!res.ok) {
    // Read a short, non-sensitive reason; do not echo arbitrary GitHub response bodies
    // to the client (they could contain rate-limit/repo details we'd rather not leak).
    throw new GitHubApiError(`GitHub returned ${res.status}.`, res.status);
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch {
    throw new GitHubApiError("GitHub returned a non-JSON success response.", res.status);
  }
  if (!isIssueResponse(json)) {
    throw new GitHubApiError("GitHub response missing html_url/number.", res.status);
  }
  return { url: json.html_url, number: json.number };
}

function isIssueResponse(v: unknown): v is { html_url: string; number: number } {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { html_url?: unknown }).html_url === "string" &&
    typeof (v as { number?: unknown }).number === "number"
  );
}
