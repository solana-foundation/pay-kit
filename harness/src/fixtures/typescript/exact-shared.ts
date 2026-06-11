// Env contract for the TypeScript x402 `exact` fixture adapters. The
// wire shape mirrors the Rust spine (`rust/crates/x402/src/bin/
// harness_{client,server}.rs`) verbatim so any language adapter that
// targets this contract can pair against either TS or Rust.

export type X402HarnessEnvironment = {
  rpcUrl: string;
  network: string;
  mint: string;
  payTo: string;
  price: string;
  resourcePath: string;
  settlementHeader: string;
  facilitatorSecretKey: Uint8Array;
  // Server-only. Comma-separated mint addresses advertised alongside the
  // primary currency. Read from `X402_HARNESS_EXTRA_OFFERED_MINTS`.
  extraOfferedMints: string[];
};

export type X402ClientEnvironment = X402HarnessEnvironment & {
  targetUrl: string;
  clientSecretKey: Uint8Array;
  // Comma-separated currency preference list (symbols or mints) read
  // from `X402_HARNESS_PREFER_CURRENCIES`. Empty when unset.
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

// Convert a human-readable price ("0.001", "$0.001", "0.001 USDC") into the
// atomic base-unit integer string the x402 wire `amount`/`maxAmountRequired`
// field carries. Mirrors the Rust spine: conformant clients (Rust/Swift/
// Kotlin) parse `amount` as a u64 of base units, so the offer MUST advertise
// base units scaled by `decimals`, never the decimal price itself.
export function toBaseUnits(price: string, decimals: number): string {
  const token = price.trim().replace(/^\$/, "").split(/\s+/)[0] ?? "";
  if (
    token === "" ||
    (token.match(/\./g)?.length ?? 0) > 1 ||
    !/^[0-9.]+$/.test(token)
  ) {
    throw new Error(`invalid price: ${price}`);
  }
  const [whole, frac = ""] = token.split(".");
  // Reject more fractional digits than the mint supports rather than
  // truncating, which would silently under-advertise the price (the Rust
  // spine rejects the same input as too many decimal places).
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
  return {
    rpcUrl: readRequiredEnv("X402_HARNESS_RPC_URL"),
    network: process.env.X402_HARNESS_NETWORK ?? DEFAULT_NETWORK,
    mint: readRequiredEnv("X402_HARNESS_MINT"),
    payTo: readRequiredEnv("X402_HARNESS_PAY_TO"),
    price: process.env.X402_HARNESS_PRICE ?? DEFAULT_PRICE,
    resourcePath: process.env.X402_HARNESS_RESOURCE_PATH ?? DEFAULT_RESOURCE_PATH,
    settlementHeader:
      process.env.X402_HARNESS_SETTLEMENT_HEADER ?? DEFAULT_SETTLEMENT_HEADER,
    facilitatorSecretKey: parseSecretKey("X402_HARNESS_FACILITATOR_SECRET_KEY"),
    extraOfferedMints: parseCsv(process.env.X402_HARNESS_EXTRA_OFFERED_MINTS),
  };
}

export function readX402ServerEnvironment(): X402HarnessEnvironment {
  return readBase();
}

export function readX402ClientEnvironment(): X402ClientEnvironment {
  const base = readBase();
  return {
    ...base,
    targetUrl: readRequiredEnv("X402_HARNESS_TARGET_URL"),
    clientSecretKey: parseSecretKey("X402_HARNESS_CLIENT_SECRET_KEY"),
    preferredCurrencies: parseCsv(process.env.X402_HARNESS_PREFER_CURRENCIES),
  };
}

export const PAYMENT_REQUIRED_HEADER = "payment-required";
export const PAYMENT_SIGNATURE_HEADER = "payment-signature";
export const PAYMENT_RESPONSE_HEADER = "payment-response";
export const X402_VERSION_V2 = 2;
