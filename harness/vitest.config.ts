import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The on-chain suite imports @solana/pay-kit (a file: dep built separately)
    // and needs a forked validator — importing it where pay-kit isn't built
    // would error. It runs via its own config (`pnpm test:onchain`), so keep it
    // out of the default cross-language run.
    exclude: [...configDefaults.exclude, "test/onchain.e2e.test.ts"],
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
