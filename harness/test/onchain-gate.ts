// Pure on-chain gate logic for the settlement suite. Side-effect free so it can
// be unit-tested directly; the vitest setup file (onchain.setup.ts) is the only
// caller that runs it against the live process env.
//
// The on-chain settlement assertions live under `describe.skipIf(!RUN)` keyed on
// HARNESS_ONCHAIN. Running the on-chain config WITHOUT that flag skipped every
// settlement assertion yet exited green, so a green "on-chain" job did not prove
// settlement was asserted. Under CI the on-chain config is only ever invoked to
// run the real settlement suite, so a missing flag there is a misconfiguration,
// not a legitimate skip: fail loud instead of green-skipping. Locally (no CI)
// the flag stays optional so a developer can typecheck / dry the config without
// a mainnet fork.

export const ONCHAIN_FLAG_MISSING_CI_MESSAGE =
  "vitest.onchain.config.ts ran under CI without HARNESS_ONCHAIN=1, which would " +
  "skip every on-chain settlement assertion and still exit green. The on-chain " +
  "job must set HARNESS_ONCHAIN=1 (via `pnpm test:onchain`) so settlement is " +
  "actually asserted. Set CI=0 to opt into the local skip behaviour.";

// True when CI is set to a meaningful (truthy) value. Matches src/guards.ts.
function isCi(env: NodeJS.ProcessEnv): boolean {
  const value = env.CI;
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    value !== "0" &&
    value !== "false"
  );
}

// Throw when the on-chain config is run under CI without the settlement flag.
export function assertOnchainGate(env: NodeJS.ProcessEnv): void {
  if (isCi(env) && env.HARNESS_ONCHAIN !== "1") {
    throw new Error(ONCHAIN_FLAG_MISSING_CI_MESSAGE);
  }
}
