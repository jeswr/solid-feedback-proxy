// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Pins that the server-side composition matches the FeedbackButton's prefill helpers
// (composeIssueTitle / composeIssueBody / feedbackLabels in app-shell).

import { describe, expect, it } from "vitest";
import { composeIssueBody, composeIssueTitle, feedbackLabels } from "../src/issue.js";

describe("composeIssueTitle", () => {
  it("prefixes with the category and the first non-empty line", () => {
    expect(composeIssueTitle("bug", "\n  Save button broken\nmore")).toBe(
      "[Bug] Save button broken",
    );
    expect(composeIssueTitle("feedback", "Idea")).toBe("[Feedback] Idea");
    expect(composeIssueTitle("help", "How do I…")).toBe("[Help] How do I…");
  });
  it("falls back to just the prefix for an empty description", () => {
    expect(composeIssueTitle("bug", "   ")).toBe("[Bug]");
  });
  it("truncates a very long first line", () => {
    const title = composeIssueTitle("bug", "x".repeat(200));
    expect(title.length).toBeLessThanOrEqual("[Bug] ".length + 80);
    expect(title.endsWith("…")).toBe(true);
  });
});

describe("composeIssueBody", () => {
  it("includes the description + diagnostics block, WebID only with consent", () => {
    const withConsent = composeIssueBody("desc", {
      appName: "Pod Mail",
      appVersion: "1.2.3",
      pageUrl: "https://x/y",
      userAgent: "UA",
      webId: "https://alice.example/card#me",
    });
    expect(withConsent).toContain("desc");
    expect(withConsent).toContain("App: Pod Mail 1.2.3");
    expect(withConsent).toContain("Page: https://x/y");
    expect(withConsent).toContain("UA: UA");
    expect(withConsent).toContain("Reporter WebID: https://alice.example/card#me");
  });

  it("omits the WebID line when not consented", () => {
    const body = composeIssueBody("desc", { appName: "Pod Mail" });
    expect(body).not.toContain("Reporter WebID");
    expect(body).toContain("App: Pod Mail");
  });

  it("strips injected newlines/control chars from every diagnostics line (defence in depth)", () => {
    // Even if an un-normalised value reaches the compose step, a metadata line must not be
    // splittable: a forged `\nReporter WebID:` (or any C0 control) is collapsed to a space so
    // the `key: value` body structure cannot be broken (the verifier rejects such a WebID and
    // validate.singleLine normalises the diagnostics upstream; this is the last gate).
    const body = composeIssueBody("desc", {
      appName: "Pod\nMail",
      appVersion: "1.0\r\nReporter WebID: https://victim.example/card#me",
      pageUrl: "https://x/y\nfake: line",
      userAgent: "UA\twith\ttabs",
      webId: "https://alice.example/card#me\nReporter WebID: https://evil/x",
    });
    // Exactly the structured metadata lines we emit — no extra forged line.
    const metaLines = body.split("\n").filter((l) => /^(App|Page|UA|Reporter WebID): /.test(l));
    expect(metaLines).toEqual([
      "App: Pod Mail 1.0 Reporter WebID: https://victim.example/card#me",
      "Page: https://x/y fake: line",
      "UA: UA with tabs",
      "Reporter WebID: https://alice.example/card#me Reporter WebID: https://evil/x",
    ]);
    // The injected second `Reporter WebID:` did NOT become its own line.
    expect(metaLines.filter((l) => l.startsWith("Reporter WebID: "))).toHaveLength(1);
  });
});

describe("feedbackLabels", () => {
  it("is always user-feedback + the category", () => {
    expect(feedbackLabels("bug")).toEqual(["user-feedback", "bug"]);
    expect(feedbackLabels("feedback")).toEqual(["user-feedback", "feedback"]);
    expect(feedbackLabels("help")).toEqual(["user-feedback", "help"]);
  });
});
