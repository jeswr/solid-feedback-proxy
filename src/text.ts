// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The ONE reviewed home for the control-character safety primitive used across the
// metadata-line-injection defence (roborev MEDIUM). The whole pipeline is layered:
//   - `verify.extractWebId` REJECTS a token WebID that contains a control char,
//   - `validate.validatePayload` COLLAPSES control chars in single-line diagnostics,
//   - `issue.composeIssueBody` COLLAPSES again at the last gate (defence in depth).
// Each layer used to carry its OWN copy of the "what is a control char" definition and
// the char-by-char collapse loop. Consolidating them here means the security-critical
// definition (`isControlCodePoint`) is reviewed in exactly one place, and the three
// call sites delegate to it — the duplication a reviewer would otherwise have to diff
// for drift is gone, while the layered defence-in-depth is unchanged (each site still
// applies the guard; only the implementation is shared).
//
// "Control character" here is the ASCII C0 range (0x00–0x1F, which includes CR/LF/TAB)
// plus DEL (0x7F) — the bytes that could break a single-line `key: value` metadata line
// or inject a forged line (e.g. a second `Reporter WebID:`). A real WebID / diagnostic
// value never contains them, so rejecting/collapsing them is both correct and safe.
//
// Built char-by-char (no regex literal) deliberately: a regex matching control chars
// would itself have to embed those control characters in source.

/** True iff a Unicode code point is an ASCII control character (C0 0x00–0x1F or DEL 0x7F). */
export function isControlCodePoint(code: number): boolean {
  return code < 0x20 || code === 0x7f;
}

/**
 * Whether a string contains ANY ASCII control character (C0 0x00–0x1F incl. CR/LF/TAB, or
 * DEL 0x7F). Used to REJECT a value (e.g. the verified WebID) that must reach the issue body
 * verbatim and so must be single-line — a control char there would be a metadata-line
 * injection vector (roborev MEDIUM).
 */
export function hasControlChar(value: string): boolean {
  for (const ch of value) {
    if (isControlCodePoint(ch.codePointAt(0) ?? 0)) {
      return true;
    }
  }
  return false;
}

/**
 * Collapse every ASCII control character (incl. CR/LF/TAB and DEL) AND every run of
 * whitespace down to a single space, then trim. Turns an arbitrary value into a safe,
 * single-line `key: value` fragment: a caller cannot embed a newline to forge an extra
 * metadata line (e.g. a fake `Reporter WebID:`) in the composed issue body. The
 * anti-injection NORMALISER counterpart to {@link hasControlChar}'s REJECT.
 */
export function collapseToSingleLine(value: string): string {
  let out = "";
  let lastWasSpace = false;
  for (const ch of value) {
    const isControl = isControlCodePoint(ch.codePointAt(0) ?? 0);
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
