import { afterEach, describe, expect, it } from "vitest";
import type { ImplementationDefinition } from "../src/implementations";
import { startServer, stopServer } from "../src/process";

const KEYPAIR_BYTES = [
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50,
  51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 35, 188, 84, 145, 44,
  30, 110, 146, 196, 168, 104, 37, 200, 103, 226, 127, 253, 197, 85, 191, 251,
  212, 36, 79, 23, 162, 106, 191, 255, 238, 150, 93,
];
const KEYPAIR_PUBKEY = "3QVq8D876hmq5C5L6J3CKpWXPhvbHASz8qFsddSXFDP2";

const phpX402Server: ImplementationDefinition = {
  id: "php-x402-startup",
  label: "PHP x402 harness startup",
  role: "server",
  command: ["php", "php-server/server.php"],
  enabled: true,
  reportsAs: "php",
};

let running: Awaited<ReturnType<typeof startServer>> | undefined;

afterEach(async () => {
  if (running) {
    await stopServer(running);
    running = undefined;
  }
});

describe("PHP x402 harness fixture", () => {
  it("boots on the non-localnet x402 network with its explicit replay capability", async () => {
    running = await startServer(phpX402Server, {
      PAY_KIT_HARNESS_PROTOCOL: "x402",
      X402_HARNESS_RPC_URL: "http://127.0.0.1:1",
      X402_HARNESS_NETWORK: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
      X402_HARNESS_MINT: "USDC",
      X402_HARNESS_AMOUNT: "1000",
      X402_HARNESS_PAY_TO: KEYPAIR_PUBKEY,
      X402_HARNESS_FACILITATOR_SECRET_KEY: JSON.stringify(KEYPAIR_BYTES),
      // startServer owns this reserved path and must ignore per-child attempts
      // to replace it with an unshared or unmanaged directory.
      PAY_KIT_HARNESS_REPLAY_STORE_DIR: "",
    });

    expect(running.ready).toMatchObject({
      type: "ready",
      role: "server",
      implementation: "php",
    });
    expect(running.ready.port).toBeGreaterThan(0);
  });
});
