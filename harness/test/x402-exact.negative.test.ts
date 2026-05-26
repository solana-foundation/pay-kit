// Negative-scenario coverage for the x402 `exact` intent.
//
// The cross-language matrix in `x402-exact.e2e.test.ts` exercises the
// happy path and is gated behind `X402_INTEROP_MATRIX=1` plus a live
// Surfpool RPC and funded keypair. The verifier surface (network
// mismatch, cross-route replay) is independent of any of that: the
// rejection happens at the wire layer before the server would touch
// the chain. This file exercises the TS reference server's verifier
// directly with hand-crafted credentials so the negative scenarios
// registered in `src/intents/x402-exact.ts` are actually run on every
// default `pnpm test` invocation, not merely declared.
//
// Network-mismatch coverage uses two distinct `X402_INTEROP_NETWORK`
// values: the server advertises offers for network A, the credential
// claims `accepted.network = B`. The TS reference verifier returns the
// canonical `wrong_network` token.

import { afterEach, describe, expect, it } from "vitest";
import { interopScenarios } from "../src/contracts";
import {
  serverImplementations,
} from "../src/implementations";
import { startServer, stopServer } from "../src/process";

const PAYMENT_SIGNATURE_HEADER = "payment-signature";
const TS_NETWORK_A = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const TS_NETWORK_B = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

const tsServer = serverImplementations.find(s => s.id === "ts-x402");

const networkMismatch = interopScenarios.find(
  scenario => scenario.id === "x402-exact-network-mismatch",
);
const crossRouteReplay = interopScenarios.find(
  scenario => scenario.id === "x402-exact-cross-route-replay",
);

type RunningServer = Awaited<ReturnType<typeof startServer>>;
let currentServer: RunningServer | null = null;

afterEach(async () => {
  if (currentServer) {
    await stopServer(currentServer);
    currentServer = null;
  }
});

function encodeCredential(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

async function bootstrapChallengeId(port: number, resourcePath: string): Promise<string> {
  // The TS reference server issues a fresh challenge id on each 402.
  // Cross-route replay must pass server-side challenge verification,
  // so we acquire a valid id by hitting the resource without a
  // credential. The id is bound to the issuing route only at the
  // payload.resource layer; resource-mismatch fires before the
  // signature-consumed check, so reusing the id across routes is fine.
  const response = await fetch(`http://127.0.0.1:${port}${resourcePath}`);
  const challengeId = response.headers.get("x-challenge-id");
  if (!challengeId) {
    throw new Error("TS reference server did not issue an x-challenge-id");
  }
  return challengeId;
}

describe("x402 exact — verifier negative scenarios (TS reference)", () => {
  if (!tsServer || !tsServer.enabled) {
    it.skip("ts-x402 server adapter not enabled", () => {});
    return;
  }

  if (networkMismatch) {
    it("network-mismatch credential is rejected with canonical `wrong_network`", async () => {
      // Distinct networks: server advertises offers on network A;
      // client tampers credential to claim network B. This is the
      // failure shape the codex r8 negative-scenario item asks for
      // (the previous declaration used the same scenario.network for
      // both sides, which could never trigger the verifier branch).
      const serverEnv = {
        X402_INTEROP_NETWORK: TS_NETWORK_A,
        X402_INTEROP_RESOURCE_PATH: networkMismatch.resourcePath,
        X402_INTEROP_PRICE: networkMismatch.price,
      };
      currentServer = await startServer(tsServer, serverEnv);
      const port = currentServer.ready.port;
      if (!port) throw new Error("server did not report a port");
      const url = `http://127.0.0.1:${port}${networkMismatch.resourcePath}`;

      const challengeId = await bootstrapChallengeId(port, networkMismatch.resourcePath);

      const credential = encodeCredential({
        x402Version: 2,
        accepted: {
          scheme: "exact",
          // Network B: distinct from what the server advertises.
          network: TS_NETWORK_B,
          asset: networkMismatch.asset,
          payTo: "5xYbHvVQfTUyzCzKx5KjVxyqXqQ4Ujm5SbqQXJ5w8nVA",
          amount: networkMismatch.amount,
          extra: null,
        },
        payload: {
          challengeId,
          resource: networkMismatch.resourcePath,
        },
        resource: networkMismatch.resourcePath,
      });

      const response = await fetch(url, {
        headers: { [PAYMENT_SIGNATURE_HEADER]: credential },
      });
      const body = (await response.json()) as Record<string, unknown>;

      expect(response.status).toBe(networkMismatch.expectedStatus);
      expect(body.code).toBe(networkMismatch.expectedCode);
    }, 30_000);
  } else {
    it.skip("x402-exact-network-mismatch scenario missing", () => {});
  }

  if (crossRouteReplay) {
    it("cross-route replay credential is rejected with canonical `charge_request_mismatch`", async () => {
      // The credential's payload.resource pins it to the issuing route
      // (the cheap source). Replaying against the expensive route must
      // surface `charge_request_mismatch` at the verifier, not settle
      // and not surface `signature_consumed` (the signature has not
      // been consumed yet on the target route).
      const serverEnv = {
        X402_INTEROP_NETWORK: TS_NETWORK_A,
        // Server resource path = the expensive (target) route. The
        // server only knows one route at a time in this fixture;
        // cross-route replay is asserted by sending a credential whose
        // payload.resource diverges from the server's advertised
        // route.
        X402_INTEROP_RESOURCE_PATH: crossRouteReplay.resourcePath,
        X402_INTEROP_PRICE: crossRouteReplay.price,
      };
      currentServer = await startServer(tsServer, serverEnv);
      const port = currentServer.ready.port;
      if (!port) throw new Error("server did not report a port");
      const url = `http://127.0.0.1:${port}${crossRouteReplay.resourcePath}`;

      const challengeId = await bootstrapChallengeId(port, crossRouteReplay.resourcePath);

      const sourcePath = crossRouteReplay.replaySource?.resourcePath ?? "/protected/cheap";
      const credential = encodeCredential({
        x402Version: 2,
        accepted: {
          scheme: "exact",
          network: TS_NETWORK_A,
          asset: crossRouteReplay.asset,
          payTo: "5xYbHvVQfTUyzCzKx5KjVxyqXqQ4Ujm5SbqQXJ5w8nVA",
          amount: crossRouteReplay.amount,
          extra: null,
        },
        payload: {
          challengeId,
          // Pinned to the cheap source route; the server is serving
          // the expensive route — mismatch.
          resource: sourcePath,
        },
        resource: sourcePath,
      });

      const response = await fetch(url, {
        headers: { [PAYMENT_SIGNATURE_HEADER]: credential },
      });
      const body = (await response.json()) as Record<string, unknown>;

      expect(response.status).toBe(crossRouteReplay.expectedStatus);
      expect(body.code).toBe(crossRouteReplay.expectedCode);
    }, 30_000);
  } else {
    it.skip("x402-exact-cross-route-replay scenario missing", () => {});
  }
});
