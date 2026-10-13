// TypeScript x402 `upto` harness client.
//
// Mirrors the Python/Rust/Go upto harness clients: GET the target, parse the
// `upto` 402 challenge, build a real PAYMENT-SIGNATURE (payment-channel open
// via the TS pay-kit client), GET again with it, then print exactly one result
// JSON line to stdout. Diagnostics go to stderr.
//
// Unlike the `exact` fixture (`exact-client.ts`), this is NOT a wire-level
// stub: the TS SDK already registers `UptoSvmScheme` on the x402 client, so
// the harness exercises that real path against the Rust/Go/Python upto
// servers in the matrix (see `test/x402-upto.e2e.test.ts`).
//
// Env contract (shared with the rust/go/python upto clients):
//
// * `X402_HARNESS_TARGET_URL`        - required, the gated resource URL.
// * `X402_HARNESS_RPC_URL`           - required, used to build the channel open.
// * `X402_HARNESS_CLIENT_SECRET_KEY` - required, JSON int array (secret-key bytes).
// * `X402_HARNESS_SETTLEMENT_HEADER` - optional; default `x-fixture-settlement`.
// * `X402_HARNESS_ACTUAL_AMOUNT`     - optional; forwarded as
//   `X402-HARNESS-ACTUAL-AMOUNT` on the paid request (server metering hint).

import { createKeyPairSignerFromBytes } from "@solana/kit";
import { createPayKitClient } from "@solana/pay-kit/client";

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

async function readResponseBody(response: Response): Promise<unknown> {
  const raw = await response.text();
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

async function main() {
  const targetUrl = readRequiredEnv("X402_HARNESS_TARGET_URL");
  const rpcUrl = readRequiredEnv("X402_HARNESS_RPC_URL");
  const clientSecretKey = parseSecretKey("X402_HARNESS_CLIENT_SECRET_KEY");
  const settlementHeader =
    process.env.X402_HARNESS_SETTLEMENT_HEADER ?? DEFAULT_SETTLEMENT_HEADER;
  const actualAmount = process.env.X402_HARNESS_ACTUAL_AMOUNT ?? "0";

  const signer = await createKeyPairSignerFromBytes(clientSecretKey);
  // x402 only: the matrix servers offer `upto`, and forcing the rail avoids
  // the MPP-preferred path in createPayKitClient when both headers exist.
  const client = await createPayKitClient({
    accept: ["x402"],
    rpcUrl,
    signer,
  });

  const paidResponse = await client.fetch(
    targetUrl,
    {
      headers: {
        // Forwarded so harness servers that meter from the paid request (Rust
        // spine, Go client pair) see the scenario's actualAmount. Harmless if
        // the server reads actualAmount only from its own env.
        "X402-HARNESS-ACTUAL-AMOUNT": actualAmount,
      },
    },
    "x402",
  );

  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: paidResponse.ok,
      status: paidResponse.status,
      responseHeaders: Object.fromEntries(paidResponse.headers.entries()),
      responseBody: await readResponseBody(paidResponse),
      settlement: paidResponse.headers.get(settlementHeader),
    }),
  );
}

void main().catch(error => {
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: false,
      status: 0,
      responseHeaders: {},
      responseBody: null,
      settlement: null,
      error: error instanceof Error ? error.message : String(error),
    }),
  );
});
