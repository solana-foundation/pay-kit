// Env contract for the TypeScript x402 `exact` fixture adapters. The
// wire shape mirrors the Rust spine (`rust/crates/x402/src/bin/
// interop_{client,server}.rs`) verbatim so any language adapter that
// targets this contract can pair against either TS or Rust.

export type X402InteropEnvironment = {
  rpcUrl: string;
  network: string;
  mint: string;
  payTo: string;
  price: string;
  resourcePath: string;
  settlementHeader: string;
  facilitatorSecretKey: Uint8Array;
  // Server-only. Comma-separated mint addresses advertised alongside the
  // primary currency. Read from `X402_INTEROP_EXTRA_OFFERED_MINTS`.
  extraOfferedMints: string[];
};

export type X402ClientEnvironment = X402InteropEnvironment & {
  targetUrl: string;
  clientSecretKey: Uint8Array;
  // Comma-separated currency preference list (symbols or mints) read
  // from `X402_INTEROP_PREFER_CURRENCIES`. Empty when unset.
  preferredCurrencies: string[];
};

const DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_RESOURCE_PATH = "/protected";
const DEFAULT_PRICE = "0.001";
const DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement";

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

function parseCsv(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);
}

function readBase(): X402InteropEnvironment {
  return {
    rpcUrl: readRequiredEnv("X402_INTEROP_RPC_URL"),
    network: process.env.X402_INTEROP_NETWORK ?? DEFAULT_NETWORK,
    mint: readRequiredEnv("X402_INTEROP_MINT"),
    payTo: readRequiredEnv("X402_INTEROP_PAY_TO"),
    price: process.env.X402_INTEROP_PRICE ?? DEFAULT_PRICE,
    resourcePath: process.env.X402_INTEROP_RESOURCE_PATH ?? DEFAULT_RESOURCE_PATH,
    settlementHeader:
      process.env.X402_INTEROP_SETTLEMENT_HEADER ?? DEFAULT_SETTLEMENT_HEADER,
    facilitatorSecretKey: parseSecretKey("X402_INTEROP_FACILITATOR_SECRET_KEY"),
    extraOfferedMints: parseCsv(process.env.X402_INTEROP_EXTRA_OFFERED_MINTS),
  };
}

export function readX402ServerEnvironment(): X402InteropEnvironment {
  return readBase();
}

export function readX402ClientEnvironment(): X402ClientEnvironment {
  const base = readBase();
  return {
    ...base,
    targetUrl: readRequiredEnv("X402_INTEROP_TARGET_URL"),
    clientSecretKey: parseSecretKey("X402_INTEROP_CLIENT_SECRET_KEY"),
    preferredCurrencies: parseCsv(process.env.X402_INTEROP_PREFER_CURRENCIES),
  };
}

export const PAYMENT_REQUIRED_HEADER = "payment-required";
export const PAYMENT_SIGNATURE_HEADER = "payment-signature";
export const PAYMENT_RESPONSE_HEADER = "payment-response";
export const X402_VERSION_V2 = 2;
