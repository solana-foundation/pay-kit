import { harnessScenario } from "../../contracts";

export type HarnessEnvironment = {
  rpcUrl: string;
  network: string;
  mint: string;
  amount: string;
  paymentMode: "pull" | "push";
  resourcePath: string;
  replaySource?: {
    amount: string;
    price: string;
    resourcePath: string;
  };
  settlementHeader: string;
  payTo: string;
  secretKey: string;
  splits: Array<{
    recipient: string;
    amount: string;
    ataCreationRequired?: boolean;
    memo?: string;
  }>;
  clientSecretKey: Uint8Array;
  feePayerSecretKey: Uint8Array;
  decimals: number;
  // SOL-native scenarios pass `MPP_HARNESS_ASSET_KIND=sol` and the
  // server fixture must build the charge with `currency: "sol"` and
  // skip the SPL token-program path. SPL scenarios pass the literal
  // `MPP_HARNESS_MINT` through to the SDK so the resolver is
  // exercised.
  assetKind: "spl" | "sol";
  computeUnitLimit?: number;
  computeUnitPrice?: bigint;
};

function readRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`${name} is required`);
  }

  return value;
}

function parseSecretKey(name: string): Uint8Array {
  const raw = readRequiredEnv(name);
  const parsed = JSON.parse(raw) as number[];
  return new Uint8Array(parsed);
}

export function readHarnessEnvironment(): HarnessEnvironment {
  return {
    rpcUrl: readRequiredEnv("MPP_HARNESS_RPC_URL"),
    network: process.env.MPP_HARNESS_NETWORK ?? harnessScenario.network,
    mint: process.env.MPP_HARNESS_MINT ?? harnessScenario.asset,
    amount: process.env.MPP_HARNESS_AMOUNT ?? harnessScenario.amount,
    paymentMode:
      process.env.MPP_HARNESS_PAYMENT_MODE === "push" ? "push" : "pull",
    resourcePath:
      process.env.MPP_HARNESS_RESOURCE_PATH ?? harnessScenario.resourcePath,
    replaySource:
      process.env.MPP_HARNESS_REPLAY_SOURCE_PATH &&
      process.env.MPP_HARNESS_REPLAY_SOURCE_AMOUNT &&
      process.env.MPP_HARNESS_REPLAY_SOURCE_PRICE
        ? {
            amount: process.env.MPP_HARNESS_REPLAY_SOURCE_AMOUNT,
            price: process.env.MPP_HARNESS_REPLAY_SOURCE_PRICE,
            resourcePath: process.env.MPP_HARNESS_REPLAY_SOURCE_PATH,
          }
        : undefined,
    settlementHeader:
      process.env.MPP_HARNESS_SETTLEMENT_HEADER ??
      harnessScenario.settlementHeader,
    payTo: readRequiredEnv("MPP_HARNESS_PAY_TO"),
    secretKey: process.env.MPP_HARNESS_SECRET_KEY ?? "mpp-harness-secret-key",
    splits: JSON.parse(
      process.env.MPP_HARNESS_SPLITS ?? "[]",
    ) as HarnessEnvironment["splits"],
    clientSecretKey: parseSecretKey("MPP_HARNESS_CLIENT_SECRET_KEY"),
    feePayerSecretKey: parseSecretKey("MPP_HARNESS_FEE_PAYER_SECRET_KEY"),
    decimals: parseDecimals(process.env.MPP_HARNESS_DECIMALS),
    assetKind:
      (process.env.MPP_HARNESS_ASSET_KIND ?? "spl").toLowerCase() === "sol"
        ? "sol"
        : "spl",
    computeUnitLimit:
      process.env.MPP_HARNESS_COMPUTE_UNIT_LIMIT &&
      process.env.MPP_HARNESS_COMPUTE_UNIT_LIMIT.trim() !== ""
        ? Number(process.env.MPP_HARNESS_COMPUTE_UNIT_LIMIT)
        : undefined,
    computeUnitPrice:
      process.env.MPP_HARNESS_COMPUTE_UNIT_PRICE &&
      process.env.MPP_HARNESS_COMPUTE_UNIT_PRICE.trim() !== ""
        ? BigInt(process.env.MPP_HARNESS_COMPUTE_UNIT_PRICE)
        : undefined,
  };
}

function parseDecimals(raw: string | undefined): number {
  if (!raw || raw.trim() === "") {
    return 6;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0 || value > 9) {
    throw new Error(`Invalid MPP_HARNESS_DECIMALS: ${raw}`);
  }
  return value;
}

export const fixtureSettlementHeader = harnessScenario.settlementHeader;
