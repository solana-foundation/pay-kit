import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  classifyMessageToCanonicalCode,
  injectCanonicalCode,
} from "../src/canonical-codes";

// Includes the actual PHP/Python/Lua replay RPC response, not just store hits.
const cases = [
  ["Transaction signature already consumed: signature", "signature_consumed"],
  ["pay_kit: signature_consumed", "signature_consumed"],
  [
    "Transaction simulation failed: This transaction has already been processed",
    "signature_consumed",
  ],
  [
    'Transaction verification failed for transaction Internal error: "Transaction error: This transaction has already been processed"',
    "signature_consumed",
  ],
  [
    "JSON-RPC error for method 'sendTransaction': Transaction already processed",
    "signature_consumed",
  ],
  ["sendTransaction: TRANSACTION ALREADY PROCESSED", "signature_consumed"],
  [
    "sendTransaction: Transaction simulation failed: Blockhash not found",
    "payment_invalid",
  ],
  [
    "sendTransaction: Transaction signature verification failure",
    "payment_invalid",
  ],
  [
    "sendTransaction: Transaction simulation failed: insufficient funds",
    "payment_invalid",
  ],
  ["sendTransaction: node is unhealthy", "payment_invalid"],
  ["Timed out waiting for transaction signature", "payment_invalid"],
  ["", "payment_invalid"],
] as const;

describe("canonical replay error classification", () => {
  it.each(cases)("%s → %s", (message, code) => {
    expect(classifyMessageToCanonicalCode(message)).toBe(code);
    expect(
      JSON.parse(injectCanonicalCode(JSON.stringify({ detail: message }))),
    ).toEqual({
      detail: message,
      code,
    });
  });
});

const harnessRoot = fileURLToPath(new URL("../", import.meta.url));
const adapters = [
  {
    command: "php",
    args: [
      "-r",
      'require "php-server/canonical-codes.php"; $message = stream_get_contents(STDIN); echo is_signature_consumed($message) ? "signature_consumed" : "payment_invalid";',
    ],
  },
  {
    command: "luajit",
    args: [
      "-e",
      'local codes = dofile("lua-server/canonical-codes.lua"); io.write(codes.is_signature_consumed(io.read("*a")) and "signature_consumed" or "payment_invalid")',
    ],
  },
];

for (const { command, args } of adapters) {
  // Language tools are optional in TS-only jobs; their matrix jobs install them.
  const available = !spawnSync(command, ["-v"]).error;
  describe.skipIf(!available)(
    `${command} fixture replay classifier parity`,
    () => {
      it.each(cases)("%s → %s", (message, code) => {
        const result = spawnSync(command, args, {
          cwd: harnessRoot,
          input: message,
          encoding: "utf8",
        });
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toBe(code);
      });
    },
  );
}
