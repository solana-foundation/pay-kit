import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Must be >= ADAPTER_OUTPUT_TIMEOUT_MS in src/process.ts (120s) so the
    // adapter's own timeout fires first and produces its richer "last
    // stderr" diagnostic. If vitest times out earlier, the failure is the
    // generic vitest timeout and the adapter stderr tail is lost.
    testTimeout: 130_000,
    hookTimeout: 130_000,
    fileParallelism: false,
    maxWorkers: 1,
  },
});
