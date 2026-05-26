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
  // Optional in the TS reference fixture because the stub credential
  // path does not actually sign anything. Real-signing language
  // adapters read their own keypair env. Kept on the type so any future
  // wire-through (settlement signing on the facilitator side) remains
  // backwards-compatible.
  facilitatorSecretKey: Uint8Array | null;
  // Server-only. Comma-separated mint addresses advertised alongside the
  // primary currency. Read from `X402_INTEROP_EXTRA_OFFERED_MINTS`.
  extraOfferedMints: string[];
};

export type X402ClientEnvironment = X402InteropEnvironment & {
  targetUrl: string;
  // Optional in the TS reference fixture (stub credential, no signing).
  // Real-signing adapters require their own keypair env.
  clientSecretKey: Uint8Array | null;
  // Comma-separated currency preference list (symbols or mints) read
  // from `X402_INTEROP_PREFER_CURRENCIES`. Empty when unset.
  preferredCurrencies: string[];
};

const DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_RESOURCE_PATH = "/protected";
const DEFAULT_PRICE = "0.001";
const DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement";
// TS reference fixture defaults: the negative-scenario suite runs the
// verifier surface without a live RPC or funded keypair. The live
// matrix overrides every one of these via env. Constants chosen to
// match harness/fixtures/x402-exact/canonical-challenge.json so
// hand-crafted credentials in the negative suite are wire-compatible.
const DEFAULT_RPC_URL = "http://127.0.0.1:8899";
const DEFAULT_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const DEFAULT_PAY_TO = "5xYbHvVQfTUyzCzKx5KjVxyqXqQ4Ujm5SbqQXJ5w8nVA";

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

function parseOptionalSecretKey(name: string): Uint8Array | null {
  const raw = process.env[name];
  if (!raw || raw.trim() === "") return null;
  try {
    const parsed = JSON.parse(raw) as number[];
    return new Uint8Array(parsed);
  } catch {
    return null;
  }
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
    rpcUrl: process.env.X402_INTEROP_RPC_URL ?? DEFAULT_RPC_URL,
    network: process.env.X402_INTEROP_NETWORK ?? DEFAULT_NETWORK,
    mint: process.env.X402_INTEROP_MINT ?? DEFAULT_MINT,
    payTo: process.env.X402_INTEROP_PAY_TO ?? DEFAULT_PAY_TO,
    price: process.env.X402_INTEROP_PRICE ?? DEFAULT_PRICE,
    resourcePath: process.env.X402_INTEROP_RESOURCE_PATH ?? DEFAULT_RESOURCE_PATH,
    settlementHeader:
      process.env.X402_INTEROP_SETTLEMENT_HEADER ?? DEFAULT_SETTLEMENT_HEADER,
    // TS reference fixture: credential is a stub blob, no on-chain
    // signing. Real-signing adapters parse this env themselves via
    // parseSecretKey. Keeping the parse optional unblocks the
    // negative-scenario suite, which exercises the verifier surface
    // without standing up a Surfpool RPC or a funded keypair.
    facilitatorSecretKey: parseOptionalSecretKey("X402_INTEROP_FACILITATOR_SECRET_KEY"),
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
    // Same rationale as `facilitatorSecretKey`: TS reference client
    // emits a stub credential and never signs. Real-signing adapters
    // read this env via their own parser.
    clientSecretKey: parseOptionalSecretKey("X402_INTEROP_CLIENT_SECRET_KEY"),
    preferredCurrencies: parseCsv(process.env.X402_INTEROP_PREFER_CURRENCIES),
  };
}

export const PAYMENT_REQUIRED_HEADER = "payment-required";
export const PAYMENT_SIGNATURE_HEADER = "payment-signature";
export const PAYMENT_RESPONSE_HEADER = "payment-response";
export const X402_VERSION_V2 = 2;
