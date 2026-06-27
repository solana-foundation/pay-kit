import { defineConfig } from "vitest/config";

// Dedicated config for the on-chain settlement suite. Runs only the on-chain
// test (which imports @solana/pay-kit and forks a validator), via
// `pnpm test:onchain`. Kept separate from the default cross-language run.
export default defineConfig({
  test: {
    include: ["test/onchain.e2e.test.ts"],
    testTimeout: 130_000,
    hookTimeout: 130_000,
    fileParallelism: false,
    maxWorkers: 1,
  },
});
