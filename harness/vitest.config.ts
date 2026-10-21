import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The on-chain suite imports @solana/pay-kit (a file: dep built separately)
    // and needs a forked validator — importing it where pay-kit isn't built
    // would error. It runs via its own config (`pnpm test:onchain`), so keep it
    // out of the default cross-language run.
    exclude: [...configDefaults.exclude, "test/onchain.e2e.test.ts"],
    // The protocol and flow suites spawn language runners; leave them room.
    testTimeout: 130_000,
    hookTimeout: 130_000,
    fileParallelism: false,
    maxWorkers: 1,
  },
});
