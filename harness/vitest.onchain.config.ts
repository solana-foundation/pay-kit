import { defineConfig } from "vitest/config";

// Dedicated config for the on-chain settlement suite. Runs only the on-chain
// test (which imports @solana/pay-kit and forks a validator), via
// `pnpm test:onchain`. Kept separate from the default cross-language run.
export default defineConfig({
  test: {
    include: ["test/onchain.e2e.test.ts"],
    // Hard-fails when this config runs under CI without HARNESS_ONCHAIN=1, so a
    // green on-chain job cannot mean "every settlement assertion was skipped".
    setupFiles: ["test/onchain.setup.ts"],
    testTimeout: 130_000,
    hookTimeout: 130_000,
    fileParallelism: false,
    maxWorkers: 1,
    // The settlement suite is entirely under describe.skipIf(!RUN); a config run
    // that skips everything must not exit green on its own.
    passWithNoTests: false,
  },
});
