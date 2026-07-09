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
//   X402_HARNESS_FEE_PAYER_SECRET_KEY=[...] \
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
];

function missingEnvs(): string[] {
  const missing = requiredEnvs.filter(
    (name) => !process.env[name] || process.env[name]?.trim() === "",
  );
  if (!process.env.X402_HARNESS_FEE_PAYER_SECRET_KEY?.trim()) {
    missing.push("X402_HARNESS_FEE_PAYER_SECRET_KEY");
  }
  return missing;
}

const uptoScenarios = harnessScenarios.filter(
  (scenario) => scenario.intent === "x402-upto",
);

const uptoClients = clientImplementations.filter(
  (impl) => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-upto"),
);
const uptoServers = serverImplementations.filter(
  (impl) => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-upto"),
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
    it(`has required env vars: ${missing.join(", ")}`, () => {
      throw new Error(`missing required env vars: ${missing.join(", ")}`);
    });
    return;
  }

  if (uptoScenarios.length === 0) {
    it("has x402-upto scenarios in registry", () => {
      throw new Error("x402-upto scenarios not found in harnessScenarios");
    });
    return;
  }

  it("has selected x402 upto clients and servers", () => {
    expect(uptoClients.map((client) => client.id)).not.toHaveLength(0);
    expect(uptoServers.map((server) => server.id)).not.toHaveLength(0);
  });

  for (const scenario of uptoScenarios) {
    const scenarioServers = uptoServers.filter(
      (server) => !scenario.serverIds || scenario.serverIds.includes(server.id),
    );
    const scenarioClients = uptoClients.filter(
      (client) => !scenario.clientIds || scenario.clientIds.includes(client.id),
    );

    for (const server of scenarioServers) {
      for (const client of scenarioClients) {
        it(`${client.id} client <-> ${server.id} server: ${scenario.id}`, async () => {
          const feePayerSecret = process.env.X402_HARNESS_FEE_PAYER_SECRET_KEY!;
          const env = {
            X402_HARNESS_NETWORK: scenario.network,
            X402_HARNESS_PRICE: scenario.price,
            X402_HARNESS_RESOURCE_PATH: scenario.resourcePath,
            X402_HARNESS_SETTLEMENT_HEADER: scenario.settlementHeader,
            X402_HARNESS_ACTUAL_AMOUNT: scenario.actualAmount ?? "0",
            X402_HARNESS_FEE_PAYER_SECRET_KEY: feePayerSecret,
            X402_HARNESS_RECEIVER_AUTHORIZER_SECRET_KEY:
              process.env.X402_HARNESS_RECEIVER_AUTHORIZER_SECRET_KEY ??
              feePayerSecret,
            PAY_KIT_HARNESS_PROTOCOL: "x402-upto",
          } satisfies Record<string, string>;

          const running = await startServer(server, env);
          runningServers.push(running);

          try {
            const targetUrl = `http://127.0.0.1:${running.ready.port}${scenario.resourcePath}`;
            const result = await runClient(client, targetUrl, {
              X402_HARNESS_TARGET_URL: targetUrl,
              ...env,
            });

            expect(result.status).toBe(scenario.expectedStatus);
            expect(result.ok).toBe(true);
            expect(result.settlement).toBeTruthy();
          } finally {
            await stopServer(running);
            runningServers.splice(runningServers.indexOf(running), 1);
          }
        }, 180_000);
      }
    }
  }
});
