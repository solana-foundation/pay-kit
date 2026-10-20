// Env contract for the TypeScript x402 `exact` adapters (ts-x402). They read
// the same X402_HARNESS_* variables as the Rust adapters
// (rust/crates/harness-bins/src/bin/x402_harness_{client,server}.rs) and
// drive @solana/pay-kit: the server is a pay-kit gate, the client is
// `createPayKitClient`.

import type { NetworkSlug } from "@solana/pay-kit";

export type X402HarnessEnvironment = {
  rpcUrl: string;
  // pay-kit network slug for X402_HARNESS_NETWORK (CAIP-2 or slug).
  network: NetworkSlug;
  mint: string;
  payTo: string;
  price: string;
  // Base-unit amount the scenario expects on the wire, when the harness
  // provides it (X402_HARNESS_AMOUNT).
  amount: string | undefined;
  resourcePath: string;
  settlementHeader: string;
  facilitatorSecretKey: Uint8Array;
  // Cross-route replay: a second, cheaper route on the same server.
  replaySource: { resourcePath: string; price: string } | undefined;
};

export type X402ClientEnvironment = X402HarnessEnvironment & {
  targetUrl: string;
  clientSecretKey: Uint8Array;
  resubmitUrl: string | undefined;
};

const DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_RESOURCE_PATH = "/protected";
const DEFAULT_PRICE = "0.001";
const DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement";

// CAIP-2 ids pay-kit emits (pay-kit `caip2`), mapped back to its slugs.
const CAIP2_TO_SLUG: Record<string, NetworkSlug> = {
  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "mainnet",
  "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": "devnet",
};
const SLUGS: readonly NetworkSlug[] = ["devnet", "localnet", "mainnet", "mainnet-beta"];

function readRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function parseSecretKey(name: string): Uint8Array {
  return new Uint8Array(JSON.parse(readRequiredEnv(name)) as number[]);
}

function parseNetwork(raw: string): NetworkSlug {
  const slug = CAIP2_TO_SLUG[raw] ?? (SLUGS.includes(raw as NetworkSlug) ? (raw as NetworkSlug) : undefined);
  if (!slug) throw new Error(`X402_HARNESS_NETWORK ${raw} is not a network pay-kit supports`);
  return slug;
}

// Strip the harness money shape ("$0.001", "0.001 USDC") to the decimal
// string pay-kit's `usd()` takes.
export function normalizePrice(price: string): string {
  return price.trim().replace(/^\$/, "").split(/\s+/)[0] ?? "";
}

// Convert a human-readable price ("0.001", "$0.001", "0.001 USDC") into the
// atomic base-unit integer string the x402 wire `amount` carries, scaled by
// `decimals`. Kept for test/x402-amount-base-units.test.ts.
export function toBaseUnits(price: string, decimals: number): string {
  const token = normalizePrice(price);
  if (
    token === "" ||
    (token.match(/\./g)?.length ?? 0) > 1 ||
    !/^[0-9.]+$/.test(token)
  ) {
    throw new Error(`invalid price: ${price}`);
  }
  const [whole, frac = ""] = token.split(".");
  // Reject more fractional digits than the mint supports rather than
  // truncating, which would silently under-advertise the price.
  if (frac.length > decimals) {
    throw new Error(
      `price ${price} has more than ${decimals} decimal places`,
    );
  }
  const fracScaled = frac.padEnd(decimals, "0");
  const combined = `${whole}${fracScaled}`.replace(/^0+(?=\d)/, "");
  return combined === "" ? "0" : combined;
}

function readBase(): X402HarnessEnvironment {
  const replayPath = process.env.MPP_HARNESS_REPLAY_SOURCE_PATH;
  const replayPrice = process.env.MPP_HARNESS_REPLAY_SOURCE_PRICE;
  return {
    rpcUrl: readRequiredEnv("X402_HARNESS_RPC_URL"),
    network: parseNetwork(process.env.X402_HARNESS_NETWORK ?? DEFAULT_NETWORK),
    mint: readRequiredEnv("X402_HARNESS_MINT"),
    payTo: readRequiredEnv("X402_HARNESS_PAY_TO"),
    price: normalizePrice(process.env.X402_HARNESS_PRICE ?? DEFAULT_PRICE),
    amount: process.env.X402_HARNESS_AMOUNT,
    resourcePath: process.env.X402_HARNESS_RESOURCE_PATH ?? DEFAULT_RESOURCE_PATH,
    settlementHeader:
      process.env.X402_HARNESS_SETTLEMENT_HEADER ?? DEFAULT_SETTLEMENT_HEADER,
    facilitatorSecretKey: parseSecretKey("X402_HARNESS_FACILITATOR_SECRET_KEY"),
    replaySource:
      replayPath && replayPrice
        ? { resourcePath: replayPath, price: normalizePrice(replayPrice) }
        : undefined,
  };
}

export function readX402ServerEnvironment(): X402HarnessEnvironment {
  return readBase();
}

export function readX402ClientEnvironment(): X402ClientEnvironment {
  return {
    ...readBase(),
    targetUrl: readRequiredEnv("X402_HARNESS_TARGET_URL"),
    clientSecretKey: parseSecretKey("X402_HARNESS_CLIENT_SECRET_KEY"),
    resubmitUrl: process.env.MPP_HARNESS_RESUBMIT_URL,
  };
}

export const PAYMENT_SIGNATURE_HEADER = "payment-signature";
