// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate

import { describe, expect, it } from "vitest";
import type { ProxyConfig } from "../src/config.js";
import { ValidationError, validatePayload } from "../src/validate.js";

const config = { maxDescriptionLength: 100 } as ProxyConfig;

const valid = {
  repo: "jeswr/pod-mail",
  category: "bug",
  description: "It crashed when I clicked save",
  diagnostics: {
    appName: "Pod Mail",
    appVersion: "1.0.0",
    pageUrl: "https://x/y",
    userAgent: "UA",
  },
};

describe("validatePayload — accept", () => {
  it("returns a canonical payload and drops client title/body/labels", () => {
    const p = validatePayload({ ...valid, title: "EVIL", body: "EVIL", labels: ["evil"] }, config);
    expect(p.repo).toBe("jeswr/pod-mail");
    expect(p.category).toBe("bug");
    expect(p.description).toBe(valid.description);
    expect(p.diagnostics.appName).toBe("Pod Mail");
    // The dropped fields are not present on the canonical payload.
    expect(Object.hasOwn(p, "labels")).toBe(false);
    expect(Object.hasOwn(p, "body")).toBe(false);
    expect(Object.hasOwn(p, "title")).toBe(false);
  });

  it("accepts an https webid in diagnostics (consent path)", () => {
    const p = validatePayload(
      { ...valid, diagnostics: { ...valid.diagnostics, webId: "https://alice.example/card#me" } },
      config,
    );
    expect(p.diagnostics.webId).toBe("https://alice.example/card#me");
  });

  it("strips newlines/control chars from single-line diagnostic fields (anti-injection)", () => {
    const p = validatePayload(
      {
        ...valid,
        diagnostics: {
          appName: "Pod\nMail",
          appVersion: "1.0\r\nReporter WebID: https://victim.example/card#me",
          pageUrl: "https://x/y\nfake: line",
          userAgent: "UA\twith\ttabs",
        },
      },
      config,
    );
    expect(p.diagnostics.appName).toBe("Pod Mail");
    // A forged "Reporter WebID:" line cannot survive — it is collapsed to one line.
    expect(p.diagnostics.appVersion).not.toContain("\n");
    expect(p.diagnostics.appVersion).toBe("1.0 Reporter WebID: https://victim.example/card#me");
    expect(p.diagnostics.pageUrl).not.toContain("\n");
    expect(p.diagnostics.userAgent).toBe("UA with tabs");
  });

  it("treats empty optional diagnostics as absent", () => {
    const p = validatePayload(
      { ...valid, diagnostics: { appName: "App", appVersion: "", pageUrl: "" } },
      config,
    );
    expect(p.diagnostics.appVersion).toBeUndefined();
    expect(p.diagnostics.pageUrl).toBeUndefined();
  });
});

describe("validatePayload — reject", () => {
  it("rejects a non-object body", () => {
    expect(() => validatePayload("x", config)).toThrow(ValidationError);
    expect(() => validatePayload(null, config)).toThrow(/must be a JSON object/);
    expect(() => validatePayload([], config)).toThrow(/must be a JSON object/);
  });

  it("rejects an unknown category", () => {
    expect(() => validatePayload({ ...valid, category: "spam" }, config)).toThrow(/category/);
  });

  it("rejects a missing/empty description", () => {
    expect(() => validatePayload({ ...valid, description: "   " }, config)).toThrow(
      /must not be empty/,
    );
    const noDesc = { ...valid } as Record<string, unknown>;
    delete noDesc.description;
    expect(() => validatePayload(noDesc, config)).toThrow(/must be a string/);
  });

  it("rejects an over-length description (cap enforced)", () => {
    expect(() => validatePayload({ ...valid, description: "x".repeat(101) }, config)).toThrow(
      /maximum length/,
    );
  });

  it("rejects a missing diagnostics object or empty appName", () => {
    const noDiag = { ...valid } as Record<string, unknown>;
    delete noDiag.diagnostics;
    expect(() => validatePayload(noDiag, config)).toThrow(/diagnostics.*must be an object/);
    expect(() => validatePayload({ ...valid, diagnostics: { appName: " " } }, config)).toThrow(
      /appName.*must not be empty/,
    );
  });

  it("rejects a non-https or userinfo-bearing webid", () => {
    expect(() =>
      validatePayload({ ...valid, diagnostics: { appName: "A", webId: "http://x/y" } }, config),
    ).toThrow(/https/);
    expect(() =>
      validatePayload(
        { ...valid, diagnostics: { appName: "A", webId: "https://u:p@x/y" } },
        config,
      ),
    ).toThrow(/https/);
  });

  it("rejects an over-length diagnostic string", () => {
    expect(() =>
      validatePayload(
        { ...valid, diagnostics: { appName: "A", userAgent: "x".repeat(1001) } },
        config,
      ),
    ).toThrow(/maximum length/);
  });
});
