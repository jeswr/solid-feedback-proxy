import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Pure unit tests — no network, no ports. The single outbound call (GitHub)
    // and the Solid issuer JWKS are both injected/mocked, so the suite is fast,
    // hermetic and parallel-safe.
    include: ["test/**/*.test.ts"],
    exclude: ["**/node_modules/**"],
    testTimeout: 20_000,
  },
});
