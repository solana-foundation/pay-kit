// Cross-server portability + idempotent-resubmit scenarios for the x402
// `exact` intent. Mirrors MPP §19.6:
//
// - Cross-server portability: the client pays server A and re-submits the
//   same payment-signature header to server B. B must reject with the
//   canonical `challenge_verification_failed` code because B's verifier
//   does not accept A's challenge.
//
// - Idempotent resubmit: the client pays server A, then re-submits the
//   same payment-signature header to server A. A must reject with
//   `signature_consumed`.
//
// Gated behind `X402_HARNESS_CROSS_SERVER=1` because the matrix needs
// two long-lived servers and live RPC credentials, neither of which the
// default `pnpm test` run wires up.

import { afterAll, describe, expect, it } from "vitest";
import { harnessScenarios } from "../src/contracts";
import { classifyMessageToCanonicalCode } from "../src/canonical-codes";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

const CROSS_SERVER_ENABLED = process.env.X402_HARNESS_CROSS_SERVER === "1";

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

const portabilityScenario = harnessScenarios.find(
  scenario => scenario.id === "x402-exact-cross-server-portability",
);
const resubmitScenario = harnessScenarios.find(
  scenario => scenario.id === "x402-exact-idempotent-resubmit",
);

const serversById = new Map(serverImplementations.map(s => [s.id, s]));
const clientsById = new Map(clientImplementations.map(c => [c.id, c]));

type RunningServer = Awaited<ReturnType<typeof startServer>>;
const runningServers: RunningServer[] = [];

afterAll(async () => {
  for (const server of runningServers.splice(0)) {
    await stopServer(server);
  }
});

function extractCanonicalCode(body: unknown): string | undefined {
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const record = body as Record<string, unknown>;
    if (typeof record.code === "string") return record.code;
    const source =
      (typeof record.error === "string" && record.error) ||
      (typeof record.message === "string" && record.message) ||
      undefined;
    if (source) return classifyMessageToCanonicalCode(source);
  }
  if (typeof body === "string") {
    return classifyMessageToCanonicalCode(body);
  }
  return undefined;
}

describe("x402 exact — cross-server portability + idempotent resubmit", () => {
  if (!CROSS_SERVER_ENABLED) {
    it.skip("cross-server suite is gated behind X402_HARNESS_CROSS_SERVER=1", () => {});
    return;
  }

  const missing = missingEnvs();
  if (missing.length > 0) {
    it.skip(`missing required env vars: ${missing.join(", ")}`, () => {});
    return;
  }

  // Pick a client adapter that can drive server A: if A is the wire-only
  // TS reference server, use the TS reference client (stub payload).
  // Otherwise use the rust-x402 client which emits a real Solana tx and
  // (since solana-foundation/pay-kit#1XX) echoes the sent credential
  // under `payment-signature-sent` so the runner can replay it to B.
  const pickClientForServer = (serverId: string): string =>
    serverId === "ts-x402" ? "ts-x402" : "rust-x402";

  if (portabilityScenario && portabilityScenario.crossServerPairs) {
    for (const [serverAId, serverBId] of portabilityScenario.crossServerPairs) {
      const serverA = serversById.get(serverAId);
      const serverB = serversById.get(serverBId);
      const clientId = pickClientForServer(serverAId);
      const client = clientsById.get(clientId);
      if (!serverA?.enabled || !serverB?.enabled || !client?.enabled) {
        it.skip(`portability ${serverAId} -> ${serverBId}: adapter not enabled`, () => {});
        continue;
      }

      it(`portability: pay ${serverAId} then resubmit credential to ${serverBId}`, async () => {
        const env = {
          X402_HARNESS_NETWORK: portabilityScenario.network,
          X402_HARNESS_PRICE: portabilityScenario.price,
          X402_HARNESS_RESOURCE_PATH: portabilityScenario.resourcePath,
          X402_HARNESS_SETTLEMENT_HEADER: portabilityScenario.settlementHeader,
        };

        const runningA = await startServer(serverA, env);
        runningServers.push(runningA);
        const runningB = await startServer(serverB, env);
        runningServers.push(runningB);

        try {
          const urlA = `http://127.0.0.1:${runningA.ready.port}${portabilityScenario.resourcePath}`;
          const payA = await runClient(client, urlA, {
            X402_HARNESS_TARGET_URL: urlA,
            ...env,
          });
          expect(payA.status).toBe(200);

          // Re-submit the captured payment-signature header to server B.
          // Adapters echo the credential they sent under `*-sent` so the
          // harness can replay it. Falls back to the live payment-signature
          // header for adapters that don't echo (rust spine).
          const headers = payA.responseHeaders as Record<string, string>;
          const credential =
            headers["payment-signature-sent"] ?? headers["payment-signature"];
          const urlB = `http://127.0.0.1:${runningB.ready.port}${portabilityScenario.resourcePath}`;
          const replay = await fetch(urlB, {
            headers: credential
              ? { "payment-signature": String(credential) }
              : {},
          });
          const body = await replay.json().catch(() => null);

          expect(replay.status).toBe(portabilityScenario.expectedStatus);
          if (portabilityScenario.expectedCode) {
            expect(extractCanonicalCode(body)).toBe(portabilityScenario.expectedCode);
          }
        } finally {
          await stopServer(runningA);
          await stopServer(runningB);
          runningServers.splice(runningServers.indexOf(runningA), 1);
          runningServers.splice(runningServers.indexOf(runningB), 1);
        }
      }, 180_000);
    }
  } else {
    it.skip("portability scenario missing crossServerPairs", () => {});
  }

  if (resubmitScenario) {
    const serverIds = resubmitScenario.serverIds ?? ["ts-x402"];
    for (const sid of serverIds) {
      const server = serversById.get(sid);
      const client = clientsById.get(pickClientForServer(sid));
      if (!server?.enabled || !client?.enabled) {
        it.skip(`idempotent-resubmit on ${sid}: adapter not enabled`, () => {});
        continue;
      }

      it(`idempotent resubmit against ${sid}`, async () => {
        const env = {
          X402_HARNESS_NETWORK: resubmitScenario.network,
          X402_HARNESS_PRICE: resubmitScenario.price,
          X402_HARNESS_RESOURCE_PATH: resubmitScenario.resourcePath,
          X402_HARNESS_SETTLEMENT_HEADER: resubmitScenario.settlementHeader,
        };

        const running = await startServer(server, env);
        runningServers.push(running);

        try {
          const url = `http://127.0.0.1:${running.ready.port}${resubmitScenario.resourcePath}`;
          const first = await runClient(client, url, {
            X402_HARNESS_TARGET_URL: url,
            ...env,
          });
          expect(first.status).toBe(200);

          const headers = first.responseHeaders as Record<string, string>;
          const credential =
            headers["payment-signature-sent"] ?? headers["payment-signature"];
          const replay = await fetch(url, {
            headers: credential
              ? { "payment-signature": String(credential) }
              : {},
          });
          const body = await replay.json().catch(() => null);

          expect(replay.status).toBe(resubmitScenario.expectedStatus);
          if (resubmitScenario.expectedCode) {
            expect(extractCanonicalCode(body)).toBe(resubmitScenario.expectedCode);
          }
        } finally {
          await stopServer(running);
          runningServers.splice(runningServers.indexOf(running), 1);
        }
      }, 180_000);
    }
  } else {
    it.skip("idempotent-resubmit scenario missing", () => {});
  }
});
