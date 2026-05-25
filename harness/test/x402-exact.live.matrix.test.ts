// Live on-chain x402 `exact` cross-language matrix.
//
// Env-gated. Required:
//   X402_INTEROP_MATRIX=1
//   X402_INTEROP_RPC_URL=...        (running surfpool / devnet RPC)
//   X402_INTEROP_MINT=...
//   X402_INTEROP_PAY_TO=...
//   X402_INTEROP_CLIENT_SECRET_KEY=[...]
//   X402_INTEROP_FACILITATOR_SECRET_KEY=[...]
//
// When all required env is set, this test enumerates every `allowedPair`
// (client × server) from the x402-exact intent registration and runs
// each pair against the happy-path scenario. When env is missing, the
// suite skips with a single explanatory test so CI is loud about why
// the live matrix is not running.
//
// This file is intentionally separate from `x402-exact.e2e.test.ts`:
//   - `x402-exact.e2e.test.ts` is the canonical entrypoint and
//     enumerates same-language self-pairs + spine cross-pairs.
//   - `x402-exact.live.matrix.test.ts` is the explicit "every active
//     pair, including newly-landed language adapters" enumeration.
//     Designed to widen automatically as new x402-exact adapters
//     register; no test-edit required to pick them up.

import { afterAll, describe, expect, it } from "vitest";
import { interopScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";
import { allowedX402Pair } from "../src/x402-pair-policy";

const MATRIX_ENABLED = process.env.X402_INTEROP_MATRIX === "1";

const REQUIRED_ENVS = [
  "X402_INTEROP_RPC_URL",
  "X402_INTEROP_MINT",
  "X402_INTEROP_PAY_TO",
  "X402_INTEROP_CLIENT_SECRET_KEY",
  "X402_INTEROP_FACILITATOR_SECRET_KEY",
];

function missingEnvs(): string[] {
  return REQUIRED_ENVS.filter(
    name => !process.env[name] || process.env[name]?.trim() === "",
  );
}

const x402Clients = clientImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-exact"),
);
const x402Servers = serverImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-exact"),
);

function enumeratePairs(): Array<{ clientId: string; serverId: string }> {
  const out: Array<{ clientId: string; serverId: string }> = [];
  for (const server of x402Servers) {
    for (const client of x402Clients) {
      if (allowedX402Pair(client.id, server.id)) {
        out.push({ clientId: client.id, serverId: server.id });
      }
    }
  }
  return out;
}

const happyPath = interopScenarios.find(
  scenario => scenario.id === "x402-exact-basic",
);

type RunningServer = Awaited<ReturnType<typeof startServer>>;
const runningServers: RunningServer[] = [];

afterAll(async () => {
  for (const server of runningServers.splice(0)) {
    await stopServer(server);
  }
});

describe("x402-exact live matrix (env-gated)", () => {
  if (!MATRIX_ENABLED) {
    it.skip("matrix is gated behind X402_INTEROP_MATRIX=1", () => {});
    return;
  }
  const missing = missingEnvs();
  if (missing.length > 0) {
    // Loud stderr so CI matrix misconfiguration is visible in the
    // job log even though vitest only renders skip in green. Per spec
    // this is `skip` not `fail` (the matrix is opt-in by env), but
    // the warning surfaces the missing envs without silencing them.
    // eslint-disable-next-line no-console
    console.warn(
      `\n[x402-live-matrix] SKIP: X402_INTEROP_MATRIX=1 set but required env vars are missing: ${missing.join(", ")}\n`,
    );
    it.skip(
      `live matrix skipped: missing required env vars: ${missing.join(", ")}`,
      () => {},
    );
    return;
  }
  if (!happyPath) {
    it("happy-path scenario x402-exact-basic must be in the registry", () => {
      throw new Error("x402-exact-basic scenario not found in interopScenarios");
    });
    return;
  }

  const pairs = enumeratePairs();
  it(`enumerates ${pairs.length} allowed x402-exact pair(s)`, () => {
    expect(pairs.length).toBeGreaterThan(0);
  });

  for (const { clientId, serverId } of pairs) {
    const client = x402Clients.find(impl => impl.id === clientId);
    const server = x402Servers.find(impl => impl.id === serverId);
    if (!client || !server) continue;
    it(`${clientId} client ↔ ${serverId} server: live happy path`, async () => {
      const env = {
        X402_INTEROP_NETWORK: happyPath.network,
        X402_INTEROP_PRICE: happyPath.price,
        X402_INTEROP_RESOURCE_PATH: happyPath.resourcePath,
        X402_INTEROP_SETTLEMENT_HEADER: happyPath.settlementHeader,
      } satisfies Record<string, string>;

      const running = await startServer(server, env);
      runningServers.push(running);
      try {
        const targetUrl = `http://127.0.0.1:${running.ready.port}${happyPath.resourcePath}`;
        const result = await runClient(client, targetUrl, {
          X402_INTEROP_TARGET_URL: targetUrl,
          ...env,
        });
        expect(result.status).toBe(happyPath.expectedStatus);
        expect(result.ok).toBe(true);
        expect(result.settlement).toBeTruthy();
      } finally {
        await stopServer(running);
        runningServers.splice(runningServers.indexOf(running), 1);
      }
    }, 120_000);
  }
});
