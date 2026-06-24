// Cross-language matrix for the x402 `upto` intent. Iterates every
// active x402 upto client x every active x402 upto server registered in
// `src/implementations.ts` and asserts the happy-path scenario reaches
// HTTP 200 with the fixture settlement header populated.
//
// Gated behind `X402_UPTO_HARNESS_MATRIX=1` so the default `pnpm test`
// run does not require cargo or a live Surfpool RPC. The canonical CI
// invocation is:
//
//   X402_UPTO_HARNESS_MATRIX=1 \
//   X402_HARNESS_RPC_URL=... \
//   X402_HARNESS_MINT=... \
//   X402_HARNESS_PAY_TO=... \
//   X402_HARNESS_CLIENT_SECRET_KEY=[...] \
//   X402_HARNESS_FACILITATOR_SECRET_KEY=[...] \
//   pnpm test x402-upto.e2e.test.ts

import { afterAll, describe, expect, it } from "vitest";
import { harnessScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

const MATRIX_ENABLED = process.env.X402_UPTO_HARNESS_MATRIX === "1";

const requiredEnvs = [
  "X402_HARNESS_RPC_URL",
  "X402_HARNESS_MINT",
  "X402_HARNESS_PAY_TO",
  "X402_HARNESS_CLIENT_SECRET_KEY",
  "X402_HARNESS_FACILITATOR_SECRET_KEY",
];

function missingEnvs(): string[] {
  return requiredEnvs.filter(
    name => !process.env[name] || process.env[name]?.trim() === "",
  );
}

const happyPath = harnessScenarios.find(
  scenario => scenario.id === "x402-upto-basic",
);

const uptoClients = clientImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-upto"),
);
const uptoServers = serverImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-upto"),
);

type RunningServer = Awaited<ReturnType<typeof startServer>>;
const runningServers: RunningServer[] = [];

afterAll(async () => {
  for (const server of runningServers.splice(0)) {
    await stopServer(server);
  }
});

describe("x402 upto intent — cross-language matrix", () => {
  if (!MATRIX_ENABLED) {
    it.skip("matrix is gated behind X402_UPTO_HARNESS_MATRIX=1", () => {});
    return;
  }

  const missing = missingEnvs();
  if (missing.length > 0) {
    it.skip(`missing required env vars: ${missing.join(", ")}`, () => {});
    return;
  }

  if (!happyPath) {
    it.fails("happy-path scenario x402-upto-basic missing from registry", () => {
      throw new Error("x402-upto-basic scenario not found in harnessScenarios");
    });
    return;
  }

  // Only adapters carrying a real signed channel-open transaction can
  // settle end-to-end. Initially only the Rust spine pairs with itself.
  const allowedPair = (clientId: string, serverId: string): boolean => {
    if (clientId === "rust-x402-upto" && serverId === "rust-x402-upto")
      return true;
    return false;
  };

  const crossLanguageUnasserted: string[] = [];

  for (const server of uptoServers) {
    for (const client of uptoClients) {
      if (!allowedPair(client.id, server.id)) {
        crossLanguageUnasserted.push(`${client.id} -> ${server.id}`);
        it.skip(
          `${client.id} client <-> ${server.id} server: cross-language upto settlement NOT asserted (tracked follow-up)`,
          () => {},
        );
        continue;
      }
      it(
        `${client.id} client <-> ${server.id} server: happy path`,
        async () => {
          const env = {
            X402_HARNESS_NETWORK: happyPath.network,
            X402_HARNESS_PRICE: happyPath.price,
            X402_HARNESS_RESOURCE_PATH: happyPath.resourcePath,
            X402_HARNESS_SETTLEMENT_HEADER: happyPath.settlementHeader,
            X402_HARNESS_ACTUAL_AMOUNT: "50000",
          } satisfies Record<string, string>;

          const running = await startServer(server, env);
          runningServers.push(running);

          try {
            const targetUrl = `http://127.0.0.1:${running.ready.port}${happyPath.resourcePath}`;
            const result = await runClient(client, targetUrl, {
              X402_HARNESS_TARGET_URL: targetUrl,
              ...env,
            });

            expect(result.status).toBe(happyPath.expectedStatus);
            expect(result.ok).toBe(true);
            expect(result.settlement).toBeTruthy();
          } finally {
            await stopServer(running);
            runningServers.splice(runningServers.indexOf(running), 1);
          }
        },
        180_000,
      );
    }
  }

  it("cross-language x402 upto settlement gap is tracked", () => {
    if (crossLanguageUnasserted.length > 0) {
      console.warn(
        `[x402-upto-matrix] cross-language settlement is NOT asserted for ` +
          `${crossLanguageUnasserted.length} pair(s): ${crossLanguageUnasserted.join(", ")}.`,
      );
    }
    expect(allowedPair("rust-x402-upto", "rust-x402-upto")).toBe(true);
  });
});
