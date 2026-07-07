// vitest setupFiles target for vitest.onchain.config.ts. Runs the on-chain gate
// against the live process env so the on-chain config hard-fails when it is run
// under CI without HARNESS_ONCHAIN=1 (which would skip every settlement
// assertion and still exit green). The gate logic lives in ./onchain-gate.ts so
// it stays side-effect free and unit-testable.

import { assertOnchainGate } from "./onchain-gate.js";

assertOnchainGate(process.env);
