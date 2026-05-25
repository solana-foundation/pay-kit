// Cross-language matrix for the x402 `exact` intent. Iterates every
// active x402 client × every active x402 server registered in
// `src/implementations.ts` and asserts the happy-path scenario reaches
// HTTP 200 with the fixture settlement header populated.
//
// Gated behind `X402_INTEROP_MATRIX=1` so the default `pnpm test` run
// in pay-kit does not require cargo or a live Surfpool RPC. The
// canonical CI invocation is:
//
//   X402_INTEROP_MATRIX=1 \
//   X402_INTEROP_RPC_URL=... \
//   X402_INTEROP_PAY_TO=... \
//   X402_INTEROP_CLIENT_SECRET_KEY=[...] \
//   X402_INTEROP_FACILITATOR_SECRET_KEY=[...] \
//   pnpm test x402-exact.e2e.test.ts

import { afterAll, describe, expect, it } from "vitest";
import { interopScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";
import {
  allowedX402Pair,
  baseLang,
} from "../src/x402-pair-policy";

const MATRIX_ENABLED = process.env.X402_INTEROP_MATRIX === "1";

const requiredEnvs = [
  "X402_INTEROP_RPC_URL",
  "X402_INTEROP_MINT",
  "X402_INTEROP_PAY_TO",
  "X402_INTEROP_CLIENT_SECRET_KEY",
  "X402_INTEROP_FACILITATOR_SECRET_KEY",
];

function missingEnvs(): string[] {
  return requiredEnvs.filter(
    name => !process.env[name] || process.env[name]?.trim() === "",
  );
}

const happyPath = interopScenarios.find(
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
    it.skip("matrix is gated behind X402_INTEROP_MATRIX=1", () => {});
    return;
  }

  const missing = missingEnvs();
  if (missing.length > 0) {
    it.skip(`missing required env vars: ${missing.join(", ")}`, () => {});
    return;
  }

  if (!happyPath) {
    it.fails("happy-path scenario x402-exact-basic missing from registry", () => {
      throw new Error("x402-exact-basic scenario not found in interopScenarios");
    });
    return;
  }

  // Pair restriction: the TS reference adapters speak a stub payload
  // (no real signed Solana transaction in the fixture) so they only
  // interoperate with each other and never with a real-signing language
  // adapter. Every other `x402-exact` adapter (Rust spine plus any
  // language port registered in `implementations.ts`) carries the
  // canonical PaymentProof and can interop with the Rust spine on
  // either side, plus its own same-language self-pair. Pure
  // language-to-language pairings without the spine on one side are
  // out of scope for this matrix — they are exercised in each
  // language's own integration suite.
  //
  // The pair selector is data-driven so that as new language adapters
  // land (rebased onto this PR), the matrix widens automatically
  // without further test edits.
  // Pair policy lives in src/x402-pair-policy.ts so the e2e and live
  // matrix tests cannot drift apart silently.
  const allowedPair = allowedX402Pair;

  // Explicit per-language self-pair group: each registered x402-exact
  // language adapter (client + server of the same baseLang) gets a
  // documented self-pair test. The `allowedPair` filter below already
  // covers same-baseLang via the generic loop, but enumerating
  // self-pairs explicitly makes regressions easier to spot in the
  // vitest output ("`ts-x402 self-pair` failed" reads more clearly
  // than "client ts-x402 ↔ server ts-x402 failed" buried in the
  // full cross-product log).
  const selfPairLangs = Array.from(
    new Set(x402Clients.map(impl => baseLang(impl.id))),
  ).filter(lang =>
    x402Servers.some(impl => baseLang(impl.id) === lang),
  );

  describe("self-pair (each language ↔ itself)", () => {
    if (selfPairLangs.length === 0) {
      it.skip("no x402-exact adapters registered", () => {});
      return;
    }
    for (const lang of selfPairLangs) {
      it(`${lang} self-pair is enumerated`, () => {
        const client = x402Clients.find(impl => baseLang(impl.id) === lang);
        const server = x402Servers.find(impl => baseLang(impl.id) === lang);
        expect(client).toBeTruthy();
        expect(server).toBeTruthy();
        expect(allowedPair(client!.id, server!.id)).toBe(true);
      });
    }
  });

  for (const server of x402Servers) {
    for (const client of x402Clients) {
      if (!allowedPair(client.id, server.id)) {
        it.skip(`${client.id} client ↔ ${server.id} server: pair not in default matrix`, () => {});
        continue;
      }
      it(`${client.id} client ↔ ${server.id} server: happy path`, async () => {
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
  }
});
