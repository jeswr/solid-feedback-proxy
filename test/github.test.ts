// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it, vi } from "vitest";
import { createIssue, type FetchLike, GitHubApiError } from "../src/github.js";

const input = {
  repo: "jeswr/pod-mail",
  title: "[Bug] x",
  body: "b",
  labels: ["user-feedback", "bug"],
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createIssue", () => {
  it("posts to the correct URL with the token and returns { url, number }", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(201, { html_url: "https://github.com/jeswr/pod-mail/issues/42", number: 42 }),
    );
    const result = await createIssue(input, "secret-token", fetchImpl);
    expect(result).toEqual({ url: "https://github.com/jeswr/pod-mail/issues/42", number: 42 });
    const call = fetchImpl.mock.calls[0];
    if (!call) {
      throw new Error("expected createIssue to call fetch");
    }
    const [url, init] = call;
    expect(url).toBe("https://api.github.com/repos/jeswr/pod-mail/issues");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer secret-token");
    expect(JSON.parse(init.body as string)).toEqual({
      title: input.title,
      body: input.body,
      labels: input.labels,
    });
  });

  it("throws GitHubApiError (→ 502) on a non-2xx response", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(422, { message: "Validation Failed" }),
    );
    await expect(createIssue(input, "t", fetchImpl)).rejects.toBeInstanceOf(GitHubApiError);
    await expect(createIssue(input, "t", fetchImpl)).rejects.toMatchObject({ upstreamStatus: 422 });
  });

  it("throws GitHubApiError on a network failure", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => {
      throw new Error("ECONNREFUSED");
    });
    await expect(createIssue(input, "t", fetchImpl)).rejects.toThrow(/GitHub request failed/);
  });

  it("throws when the success response is missing html_url/number", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(201, { foo: "bar" }));
    await expect(createIssue(input, "t", fetchImpl)).rejects.toThrow(/missing html_url/);
  });

  it("never includes the token in the error message", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(500, {}));
    try {
      await createIssue(input, "super-secret-token", fetchImpl);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as Error).message).not.toContain("super-secret-token");
    }
  });
});
