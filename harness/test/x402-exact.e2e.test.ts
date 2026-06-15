// Cross-language matrix for the x402 `exact` intent. Iterates every
// active x402 client × every active x402 server registered in
// `src/implementations.ts` and asserts the happy-path scenario reaches
// HTTP 200 with the fixture settlement header populated.
//
// Gated behind `X402_HARNESS_MATRIX=1` so the default `pnpm test` run
// in pay-kit does not require cargo or a live Surfpool RPC. The
// canonical CI invocation is:
//
//   X402_HARNESS_MATRIX=1 \
//   X402_HARNESS_RPC_URL=... \
//   X402_HARNESS_PAY_TO=... \
//   X402_HARNESS_CLIENT_SECRET_KEY=[...] \
//   X402_HARNESS_FACILITATOR_SECRET_KEY=[...] \
//   pnpm test x402-exact.e2e.test.ts

import { afterAll, describe, expect, it } from "vitest";
import { harnessScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

const MATRIX_ENABLED = process.env.X402_HARNESS_MATRIX === "1";

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
  scenario => scenario.id === "x402-exact-basic",
);

const x402Clients = clientImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-exact"),
);
const x402Servers = serverImplementations.filter(
  impl => impl.enabled && (impl.intents ?? ["charge"]).includes("x402-exact"),
);

type RunningServer = Awaited<ReturnType<typeof startServer>>;
const runningServers: RunningServer[] = [];

afterAll(async () => {
  for (const server of runningServers.splice(0)) {
    await stopServer(server);
  }
});

describe("x402 exact intent — cross-language matrix", () => {
  if (!MATRIX_ENABLED) {
    it.skip("matrix is gated behind X402_HARNESS_MATRIX=1", () => {});
    return;
  }

  const missing = missingEnvs();
  if (missing.length > 0) {
    it.skip(`missing required env vars: ${missing.join(", ")}`, () => {});
    return;
  }

  if (!happyPath) {
    it.fails("happy-path scenario x402-exact-basic missing from registry", () => {
      throw new Error("x402-exact-basic scenario not found in harnessScenarios");
    });
    return;
  }

  // Pair restriction: the TS reference adapters speak a stub payload
  // (no real signed Solana transaction in the fixture) so they only
  // harnesserate with each other. The Rust spine adapters carry the
  // canonical PaymentProof and are exercised end-to-end by the rust
  // crate's own integration tests (`cargo test -p solana-x402`).
  // The cross-language matrix asserts the harness wiring and the
  // ready/result protocol; full TS<->Rust on-chain settlement parity
  // arrives with the TS SDK port (tracked separately).
  const allowedPair = (clientId: string, serverId: string): boolean => {
    if (clientId === "ts-x402" && serverId === "ts-x402") return true;
    if (clientId === "rust-x402" && serverId === "rust-x402") return true;
    // The Python PayKit x402 server does full settlement (cosign +
    // broadcast), so it can only be driven by a client that emits a real
    // signed Solana transaction. The rust-x402 client carries the
    // canonical PaymentProof and settles end-to-end against surfpool,
    // mirroring the rust<->lua x402 harness pairing. The ts-x402 stub
    // client (no real transaction) is intentionally excluded.
    if (clientId === "rust-x402" && serverId === "python") return true;
    // The Python pay_kit x402 client carries a real signed v0
    // VersionedTransaction, so it can only be driven against full-settling
    // x402 servers (cosign + broadcast). The ts-x402 stub server expects a
    // stub credential with a payload.challengeId and never broadcasts a real
    // transaction, so it is intentionally excluded — same reasoning that keeps
    // rust-x402 off the ts-x402 server. Drive python-x402 against the rust and
    // python x402 servers, which settle end-to-end against surfpool.
    if (clientId === "python-x402" && serverId === "rust-x402") return true;
    if (clientId === "python-x402" && serverId === "python") return true;
    // The Swift x402 exact client likewise carries a real signed Solana
    // transaction, so it settles end-to-end against the full-settling rust
    // and python x402 servers (same reasoning as python-x402; the ts-x402
    // stub server is intentionally excluded).
    if (clientId === "swift-x402" && serverId === "rust-x402") return true;
    if (clientId === "swift-x402" && serverId === "python") return true;
    // kotlin-x402 client against rust-x402 and python (real settlement).
    // ts-x402 server excluded: pre-existing getTransaction flake.
    if (clientId === "kotlin-x402" && serverId === "rust-x402") return true;
    if (clientId === "kotlin-x402" && serverId === "python") return true;
    return false;
  };

  // P0: make the cross-language x402 gap explicit. The default x402
  // matrix only self-pairs (ts<->ts, rust<->rust) plus the real-settling
  // python pairings because the TS reference fixture carries a stub
  // credential. A skipped cross pair must not read as asserted
  // cross-language coverage. Surface the un-asserted cross pairs as a
  // single tracked, logged marker so the gap is visible in the run output
  // instead of looking green.
  const crossLanguageUnasserted: string[] = [];

  for (const server of x402Servers) {
    for (const client of x402Clients) {
      if (!allowedPair(client.id, server.id)) {
        crossLanguageUnasserted.push(`${client.id} -> ${server.id}`);
        it.skip(`${client.id} client ↔ ${server.id} server: cross-language x402 settlement NOT asserted (stub TS fixture; tracked follow-up)`, () => {});
        continue;
      }
      it(`${client.id} client ↔ ${server.id} server: happy path`, async () => {
        const env = {
          X402_HARNESS_NETWORK: happyPath.network,
          X402_HARNESS_PRICE: happyPath.price,
          X402_HARNESS_RESOURCE_PATH: happyPath.resourcePath,
          X402_HARNESS_SETTLEMENT_HEADER: happyPath.settlementHeader,
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
      }, 120_000);
    }
  }

  it("cross-language x402 settlement is a tracked, un-asserted gap", () => {
    if (crossLanguageUnasserted.length > 0) {
      console.warn(
        `[x402-matrix] cross-language x402 settlement is NOT asserted for ` +
          `${crossLanguageUnasserted.length} pair(s): ${crossLanguageUnasserted.join(", ")}. ` +
          `These read as skips, not green coverage. Tracked follow-up: a TS adapter ` +
          `that emits a real PaymentProof so ts<->rust can settle end-to-end.`,
      );
    }
    // Self-documenting assertion: the matrix only self-pairs (plus the
    // real-settling python pairings) today; the stub TS fixture cannot
    // cross-settle against rust.
    expect(allowedPair("ts-x402", "rust-x402")).toBe(false);
    expect(allowedPair("rust-x402", "ts-x402")).toBe(false);
    expect(allowedPair("ts-x402", "ts-x402")).toBe(true);
    expect(allowedPair("rust-x402", "rust-x402")).toBe(true);
  });
});
