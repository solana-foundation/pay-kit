import type { CanonicalErrorCode } from "./canonical-codes";
import { chargeScenarios } from "./intents/charge";
import { sessionScenarios } from "./intents/session";
import { x402ExactScenarios } from "./intents/x402-exact";

export type { CanonicalErrorCode };

export type AdapterKind = "client" | "server";

export type HarnessIntent = "charge" | "x402-exact" | "session";

export type HarnessScenarioSplit = {
  recipientKey: string;
  amount: string;
  ataCreationRequired?: boolean;
  memo?: string;
};

export type TokenProgramVariant = "TOKEN_PROGRAM" | "TOKEN_2022_PROGRAM";

export type CurrencyMode = "pubkey" | "symbol";

export type HarnessScenario = {
  id: string;
  intent: HarnessIntent;
  // Settlement mode. Defaults to "pull" (server broadcasts the client's
  // signed transaction). "push" exercises the client-broadcast path: the
  // client builds, signs, broadcasts, and awaits confirmation locally,
  // then sends only the resulting transaction signature to the server as
  // a `type=signature` credential. The server re-fetches the on-chain
  // transaction and re-runs the structural verifier against it.
  paymentMode?: "pull" | "push";
  network: string;
  price: string;
  amount: string;
  // The literal value the harness sends to each adapter as
  // `MPP_HARNESS_MINT`. In `pubkey` mode (default) this is a 32+ char
  // base58 mint pubkey. In `symbol` mode this is a stablecoin symbol
  // (e.g. "USDC") and the harness deploys the mint at the pubkey each
  // SDK's `Mints.resolve(symbol, network)` returns.
  asset: string;
  resourcePath: string;
  settlementHeader: string;
  splits?: HarnessScenarioSplit[];
  replaySource?: {
    resourcePath: string;
    price: string;
    amount: string;
  };
  expectedStatus: 200 | 402;
  clientIds?: string[];
  serverIds?: string[];
  // Optional. Defaults to "TOKEN_PROGRAM" (legacy SPL). Set to
  // "TOKEN_2022_PROGRAM" for scenarios that exercise Token-2022. The harness
  // uses this to deploy the scenario mint under the right program owner.
  tokenProgram?: TokenProgramVariant;
  // Optional. Defaults to "pubkey". Set to "symbol" to exercise the
  // SDK-side `Mints.resolve(currency, network)` path that the manual DX
  // path (pay sandbox + example servers) actually hits. The harness uses
  // `expectedMint` below to know which on-chain mint to deploy and to
  // assert balances against.
  currencyMode?: CurrencyMode;
  // Required when `currencyMode === "symbol"`. The pubkey the symbol
  // is expected to resolve to under `network`. Harness deploys the mint
  // here and asserts settled transferChecked uses this mint.
  expectedMint?: string;
  // Optional. Defaults to 6. Drives both the mint account `data[44]`
  // byte at deploy time and the assertion `decimals` byte at `data[9]`
  // of every transferChecked instruction. Adapters that accept a
  // configurable decimals value read `MPP_HARNESS_DECIMALS` from env.
  decimals?: number;
  // Optional. When set the harness pre-creates the platform recipient's
  // ATA for the scenario mint with a zero balance before the test
  // starts, so the idempotent ATA-create instruction in the settled
  // transaction is exercised against an already-existing account.
  preCreatePlatformAta?: boolean;
  // Optional. When set the TypeScript client passes the override to
  // `solana.charge({ computeUnitLimit, computeUnitPrice })`. Used by
  // G14 (compute budget over-cap) to force the server-side allowlist
  // cap to reject. Ignored by clients other than `typescript`.
  clientComputeUnitLimit?: number;
  clientComputeUnitPrice?: string;
  // Optional. When set to `"SOL"` the scenario exercises the native
  // SOL transfer path (System Program transfer, lamports, decimals 9,
  // no SPL token program). The harness funds the client wallet with
  // lamports via `surfnet.fundSol`, skips the SPL mint deploy, and the
  // assertion helpers expect a System Program transfer instruction
  // (discriminator 2) instead of an SPL transferChecked.
  assetKind?: "spl" | "sol";
  // Optional. When set the harness asserts `result.responseBody.code`
  // matches the canonical L6 / P1 structured error code on a 402 result.
  // Only meaningful for `expectedStatus: 402`. Each server adapter is
  // expected to emit the same canonical snake_case code for the same
  // failure class. Adapters that have not yet shipped L6 emission can be
  // excluded via `serverIds` per scenario; once their L6 work lands, the
  // serverIds gate is dropped.
  expectedCode?: CanonicalErrorCode;
  // Cross-server / idempotent-resubmit support. Default `standard`
  // exercises the single-server pay-once flow. `cross-server-portability`
  // spawns two servers (A and B) with different MPP secret keys; the
  // client pays A, then re-submits the same Authorization to B. B must
  // reject with `challenge_verification_failed` because B's HMAC
  // secret differs. `idempotent-resubmit` spawns one server, client
  // pays, then re-submits the same Authorization to the same server.
  // The server must respond with `signature_consumed`.
  kind?: "standard" | "cross-server-portability" | "idempotent-resubmit";
  // For `cross-server-portability`. Pairs to iterate over. Each entry is
  // [serverA, serverB]. The runner spawns server A and server B with
  // distinct MPP secret keys, the client pays A, then re-submits the
  // same Authorization to B. B MUST reject with the canonical
  // `challenge_verification_failed` code. crossServerPairs is REQUIRED
  // for `cross-server-portability` scenarios; a scenario that omits it
  // will be skipped (the runner does not silently pair against an
  // arbitrary fallback server).
  crossServerPairs?: Array<[string, string]>;
};

export type ReadyMessage = {
  type: "ready";
  implementation: string;
  role: AdapterKind;
  port?: number;
  capabilities?: string[];
};

export type ClientRunResult = {
  type: "result";
  implementation: string;
  role: "client";
  ok: boolean;
  status: number;
  responseHeaders: Record<string, string>;
  responseBody: unknown;
  settlement?: unknown;
};

export type AdapterMessage = ReadyMessage | ClientRunResult;

// P0: header-key normalization. Resubmit / cross-server assertions read
// exact lower-case header keys (e.g. `payment-signature-sent`). An
// adapter that emits `Payment-Signature` would otherwise silently fall
// through to a different key and mask a replay-vector bug. Lower-case
// every key once, at the harness boundary, before any assertion runs.
// On a duplicate key after lower-casing, the last value wins (matches
// how a single-valued header map collapses).
export function normalizeResponseHeaders(
  headers: Record<string, string> | undefined | null,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  if (!headers) {
    return normalized;
  }
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

export { chargeCanonicalJsonVectors } from "./intents/charge";

export const harnessScenarios: readonly HarnessScenario[] = [
  ...chargeScenarios,
  ...x402ExactScenarios,
  ...sessionScenarios,
];

export const harnessScenario: HarnessScenario = {
  ...(harnessScenarios[0] as HarnessScenario),
};

export const supportedHarnessIntents: readonly HarnessIntent[] = Array.from(
  new Set(harnessScenarios.map((scenario) => scenario.intent)),
);

export function selectHarnessScenarios(
  rawIntentSelection: string | undefined,
  rawScenarioSelection: string | undefined,
): HarnessScenario[] {
  const selectedIntents = selectHarnessIntents(rawIntentSelection);
  const selectedScenarioIds = selectScenarioIds(rawScenarioSelection);
  const selectedScenarios = harnessScenarios.filter(
    (scenario) =>
      selectedIntents.includes(scenario.intent) &&
      selectedScenarioIds.includes(scenario.id),
  );

  if (selectedScenarios.length === 0) {
    throw new Error(
      `No harness scenarios matched MPP_HARNESS_INTENTS=${rawIntentSelection ?? "<default>"} ` +
        `and MPP_HARNESS_SCENARIOS=${rawScenarioSelection ?? "<default>"}.`,
    );
  }

  return [...selectedScenarios];
}

function selectScenarioIds(rawSelection: string | undefined): string[] {
  const supported = harnessScenarios.map((scenario) => scenario.id);
  if (!rawSelection || rawSelection.trim() === "") {
    return supported;
  }

  const selected = rawSelection
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const unsupported = selected.filter((value) => !supported.includes(value));

  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported MPP_HARNESS_SCENARIOS value(s): ${unsupported.join(", ")}. ` +
        `Supported scenarios: ${supported.join(", ")}.`,
    );
  }

  return selected;
}

// The legacy MPP charge runner predates the x402-exact intent. To keep
// the existing CI matrix's default behaviour (charge-only) stable while
// still surfacing the new intent through `selectHarnessIntents("x402-exact")`,
// the empty-selection default is restricted to "charge". Callers that
// want the full intent set should pass the explicit list.
const DEFAULT_INTENTS: readonly HarnessIntent[] = ["charge"];

export function selectHarnessIntents(
  rawSelection: string | undefined,
): HarnessIntent[] {
  if (!rawSelection || rawSelection.trim() === "") {
    return [...DEFAULT_INTENTS];
  }

  const selected = rawSelection
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const unsupported = selected.filter(
    (value) => !supportedHarnessIntents.includes(value as never),
  );

  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported MPP_HARNESS_INTENTS value(s): ${unsupported.join(", ")}. ` +
        `Supported intents: ${supportedHarnessIntents.join(", ")}.`,
    );
  }

  return selected as HarnessIntent[];
}
