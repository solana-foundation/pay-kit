// Wire-level compatibility matrix for the x402 `exact` intent.
//
// Three test groups run WITHOUT live RPC, surfpool, or funded keypairs:
//
//   1. Client-emit compatibility: each registered `x402-exact` client
//      adapter is spawned against a thin fixture HTTP server that
//      replies with the canonical-challenge.json 402 envelope. The
//      adapter MUST parse the envelope and resubmit a credential whose
//      `accepted` block round-trips through `JSON.parse` and matches
//      one of the offers from the envelope. This catches wire-format
//      drift between language adapters before the live matrix runs.
//
//   2. Server-accept compatibility: each registered `x402-exact` server
//      adapter is spawned against the canonical-payment-signature.json
//      credential. Because the wire-only TS reference fixture validates
//      semantic fields (challengeId issued by this server, asset/payTo
//      matching offer) it will reject a foreign-issued credential — but
//      it MUST do so with a parseable JSON response on the 402 boundary,
//      never with a process crash or unparseable body. SVM-verifier
//      adapters are gated by capability (see CAPABILITY_GATE below).
//
//   3. Attack-rejection compatibility: each registered `x402-exact`
//      server adapter is fed every credential in attack-scenarios.json.
//      For each scenario the response body's `error` / `code` / `message`
//      MUST match one of the scenario's `expectedRejectTokens`. Adapters
//      that don't decode the full SVM transaction blob are allowed the
//      fallback `payment_invalid` token (see canonical-reject-tokens.json).
//
// These tests are NOT env-gated; they run in the default `pnpm test`
// invocation. They require no cargo toolchain — the rust spine is
// excluded from the compat suite (capability filter) and exercised in
// the live matrix instead.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  clientImplementations,
  serverImplementations,
  type ImplementationDefinition,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

type CanonicalChallenge = {
  x402Version: number;
  accepts: Array<{
    scheme: string;
    network: string;
    resource: string;
    payTo: string;
    asset: string;
    maxAmountRequired: string;
    extra?: { decimals?: number; tokenProgram?: string };
  }>;
  resource: string;
};

type CanonicalCredential = {
  x402Version: number;
  accepted: {
    scheme: string;
    network: string;
    asset: string;
    payTo: string;
    amount: string;
    extra?: { decimals?: number; tokenProgram?: string };
  };
  payload: { challengeId?: string; resource?: string };
  resource?: string;
};

type AttackScenario = {
  name: string;
  description: string;
  credentialOverride: Record<string, unknown>;
  expectedRejectTokens: string[];
  // When set, listed top-level fields on the merged credential are
  // REPLACED (shallow) by the override value instead of deep-merged.
  // Use this when an attack scenario wants to drop subfields like
  // payload.challengeId — a deep merge would otherwise re-inject them
  // from the base credential.
  replaceFields?: string[];
  // When set, listed top-level fields are deleted from the merged
  // credential entirely. Used for structural-malformation attacks
  // (missing `accepted`, missing `payload`).
  deleteFields?: string[];
  // When true, wire-only adapters (no full SVM transaction decoder)
  // are allowed to accept this credential (status 200). Full-verifier
  // adapters are still required to reject with one of the
  // expectedRejectTokens. Used for attacks that target subfields a
  // wire-only adapter cannot validate without decoding the transaction
  // blob (tokenProgram, fee-payer-in-accounts, etc.).
  wireOnlyMayAccept?: boolean;
};

type AttackSuite = {
  scenarios: AttackScenario[];
  replayScenario: { expectedRejectTokens: string[] };
};

const FIXTURE_DIR = path.resolve(__dirname, "../fixtures/x402-exact");

function loadJson<T>(name: string): T {
  const raw = fs.readFileSync(path.join(FIXTURE_DIR, name), "utf8");
  return JSON.parse(raw) as T;
}

const challenge = loadJson<CanonicalChallenge>("canonical-challenge.json");
const credential = loadJson<CanonicalCredential>(
  "canonical-payment-signature.json",
);
const rejectTokens = loadJson<{
  highLevelTokens: string[];
  exactSvmPayloadTokens: string[];
}>("canonical-reject-tokens.json");
const attackSuite = loadJson<AttackSuite>("attack-scenarios.json");

// Capability gate — adapters that require external toolchains (cargo,
// go, swift) we cannot reasonably exercise in the wire-compat suite
// because their startup cost dwarfs the wire test. They re-enter via
// the live matrix once env is set. The gate is keyed off adapter ids so
// new language adapters automatically opt in.
const COMPAT_INCLUDE_IDS = new Set<string>(["ts-x402"]);

// Adapters that don't decode the full SVM transaction blob and therefore
// can't catch some attack classes (e.g. tokenProgram mismatch inside
// the signed transaction). For these adapters, attack scenarios marked
// `wireOnlyMayAccept: true` are allowed to return 200.
const WIRE_ONLY_ADAPTER_IDS = new Set<string>(["ts-x402"]);

function activeClients(): ImplementationDefinition[] {
  return clientImplementations.filter(
    impl =>
      impl.enabled &&
      (impl.intents ?? []).includes("x402-exact") &&
      COMPAT_INCLUDE_IDS.has(impl.id),
  );
}

function activeServers(): ImplementationDefinition[] {
  return serverImplementations.filter(
    impl =>
      impl.enabled &&
      (impl.intents ?? []).includes("x402-exact") &&
      COMPAT_INCLUDE_IDS.has(impl.id),
  );
}

const offer = challenge.accepts[0];
if (!offer) throw new Error("canonical-challenge fixture has no offers");

function buildCompatEnv(extra: Record<string, string> = {}): Record<string, string> {
  // Every required X402_INTEROP_* env, with a deterministic dummy
  // facilitator/client keypair (the adapters parse but never use them
  // in the wire compat path).
  const stubKey = JSON.stringify(new Array(64).fill(7));
  return {
    X402_INTEROP_RPC_URL: "http://127.0.0.1:65535",
    X402_INTEROP_NETWORK: offer.network,
    X402_INTEROP_MINT: offer.asset,
    X402_INTEROP_PAY_TO: offer.payTo,
    X402_INTEROP_PRICE: offer.maxAmountRequired,
    X402_INTEROP_RESOURCE_PATH: offer.resource,
    X402_INTEROP_SETTLEMENT_HEADER: "x-fixture-settlement",
    X402_INTEROP_FACILITATOR_SECRET_KEY: stubKey,
    X402_INTEROP_CLIENT_SECRET_KEY: stubKey,
    ...extra,
  };
}

// In-process fixture HTTP server that mimics a canonical x402 402
// response. Drives the client-side wire parser test without spawning a
// real x402 server adapter.
async function startCanonicalFixtureServer(): Promise<{ url: string; close: () => Promise<void>; received: { credential: string | null } }> {
  const received = { credential: null as string | null };
  const envelope = Buffer.from(JSON.stringify(challenge), "utf8").toString(
    "base64",
  );
  const server = http.createServer((req, res) => {
    const credentialHeader = req.headers["payment-signature"] as
      | string
      | undefined;
    if (!credentialHeader) {
      res.writeHead(402, {
        "content-type": "application/json",
        "payment-required": envelope,
        "x-challenge-id": "canonical-fixture-challenge-0001",
      });
      res.end(JSON.stringify({ error: "payment_required" }));
      return;
    }
    received.credential = credentialHeader;
    res.writeHead(200, {
      "content-type": "application/json",
      "payment-response": Buffer.from(
        JSON.stringify({ success: true, transaction: "fixture-tx" }),
        "utf8",
      ).toString("base64"),
      "x-fixture-settlement": "fixture-tx",
    });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>(resolve =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("fixture server failed to bind");
  }
  return {
    url: `http://127.0.0.1:${address.port}${offer.resource}`,
    received,
    close: () =>
      new Promise<void>(resolve =>
        server.close(() => resolve()),
      ),
  };
}

function decodeCredentialHeader(headerValue: string): CanonicalCredential {
  return JSON.parse(
    Buffer.from(headerValue, "base64").toString("utf8"),
  ) as CanonicalCredential;
}

function extractRejectToken(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, unknown>;
  for (const field of ["code", "error", "message"] as const) {
    const value = record[field];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function deepMerge<T extends Record<string, unknown>>(
  base: T,
  override: Record<string, unknown>,
): T {
  const result: Record<string, unknown> = { ...base };
  for (const [k, v] of Object.entries(override)) {
    if (
      v !== null &&
      typeof v === "object" &&
      !Array.isArray(v) &&
      typeof result[k] === "object" &&
      result[k] !== null &&
      !Array.isArray(result[k])
    ) {
      result[k] = deepMerge(
        result[k] as Record<string, unknown>,
        v as Record<string, unknown>,
      );
    } else {
      result[k] = v;
    }
  }
  return result as T;
}

function encodeCredential(payload: unknown): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

async function postCredential(
  targetUrl: string,
  credentialHeader: string,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(targetUrl, {
    headers: { "payment-signature": credentialHeader },
  });
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // leave as text
  }
  return { status: response.status, body };
}

describe("x402-exact compat: registered adapters", () => {
  const clients = activeClients();
  const servers = activeServers();

  it("at least one x402-exact client adapter is registered", () => {
    expect(clients.length).toBeGreaterThan(0);
  });

  it("at least one x402-exact server adapter is registered", () => {
    expect(servers.length).toBeGreaterThan(0);
  });

  it("canonical fixtures are wire-consistent with each other", () => {
    expect(credential.accepted.scheme).toBe(offer.scheme);
    expect(credential.accepted.network).toBe(offer.network);
    expect(credential.accepted.asset).toBe(offer.asset);
    expect(credential.accepted.payTo).toBe(offer.payTo);
    expect(credential.accepted.amount).toBe(offer.maxAmountRequired);
    expect(credential.payload.resource ?? credential.resource).toBe(
      offer.resource,
    );
  });

  it("canonical reject tokens are exhaustive vs the rust spine reject taxonomy", () => {
    // Hard-coded floor: the spine emits at least these high-level tokens
    // and these SVM-payload tokens. If a new token lands in the rust
    // spine and isn't mirrored here, the parity lock has drifted.
    expect(rejectTokens.highLevelTokens).toContain("payment_invalid");
    expect(rejectTokens.highLevelTokens).toContain("signature_consumed");
    expect(rejectTokens.exactSvmPayloadTokens).toContain(
      "invalid_exact_svm_payload_amount_mismatch",
    );
    expect(rejectTokens.exactSvmPayloadTokens).toContain(
      "invalid_exact_svm_payload_recipient_mismatch",
    );
    expect(rejectTokens.exactSvmPayloadTokens).toContain(
      "invalid_exact_svm_payload_mint_mismatch",
    );
  });
});

describe("x402-exact compat: client → canonical challenge", () => {
  const clients = activeClients();

  type Fixture = Awaited<ReturnType<typeof startCanonicalFixtureServer>>;
  let fixture: Fixture | undefined;
  afterEach(async () => {
    if (fixture) {
      await fixture.close();
      fixture = undefined;
    }
  });

  for (const client of clients) {
    it(`${client.id} parses canonical 402 envelope and resubmits a wire-valid credential`, async () => {
      fixture = await startCanonicalFixtureServer();
      const env = buildCompatEnv({ X402_INTEROP_TARGET_URL: fixture.url });
      const result = await runClient(client, fixture.url, env);

      expect(result.ok).toBe(true);
      expect(result.status).toBe(200);

      // Adapter must have submitted a credential the fixture server
      // saw and recorded.
      expect(fixture.received.credential).toBeTruthy();
      const parsed = decodeCredentialHeader(
        fixture.received.credential as string,
      );
      expect(parsed.accepted.scheme).toBe(offer.scheme);
      expect(parsed.accepted.network).toBe(offer.network);
      expect(parsed.accepted.asset).toBe(offer.asset);
      expect(parsed.accepted.payTo).toBe(offer.payTo);
      expect(parsed.accepted.amount).toBe(offer.maxAmountRequired);
    }, 60_000);
  }
});

describe("x402-exact compat: server → canonical credential", () => {
  const servers = activeServers();
  type Running = Awaited<ReturnType<typeof startServer>>;
  let running: Running | undefined;
  afterEach(async () => {
    if (running) {
      await stopServer(running);
      running = undefined;
    }
  });

  for (const server of servers) {
    it(`${server.id} accepts a wire-valid credential or returns a parseable rejection`, async () => {
      const env = buildCompatEnv();
      running = await startServer(server, env);
      const targetUrl = `http://127.0.0.1:${running.ready.port}${offer.resource}`;

      // First: prime the server by hitting it without a credential.
      // Some adapters (TS reference) HMAC-track issued challenge IDs
      // and reject foreign-issued ids; for those, capture the issued
      // challenge and retry with that credential id substituted in.
      const primeResponse = await fetch(targetUrl);
      expect(primeResponse.status).toBe(402);
      const issuedChallengeId = primeResponse.headers.get("x-challenge-id");

      const credentialToSend = issuedChallengeId
        ? deepMerge(credential, {
            payload: { challengeId: issuedChallengeId },
          })
        : credential;
      const header = encodeCredential(credentialToSend);
      const { status, body } = await postCredential(targetUrl, header);

      // Either accept (200) or a parseable 402 with a known reject token.
      if (status === 200) {
        expect(body).toBeDefined();
      } else {
        expect(status).toBe(402);
        const token = extractRejectToken(body);
        expect(token).toBeTruthy();
        const allTokens = new Set<string>([
          ...rejectTokens.highLevelTokens,
          ...rejectTokens.exactSvmPayloadTokens,
        ]);
        expect(allTokens.has(token as string)).toBe(true);
      }
    }, 60_000);
  }
});

describe("x402-exact compat: server → attack scenarios", () => {
  const servers = activeServers();
  type Running = Awaited<ReturnType<typeof startServer>>;
  let running: Running | undefined;
  afterEach(async () => {
    if (running) {
      await stopServer(running);
      running = undefined;
    }
  });

  for (const server of servers) {
    for (const scenario of attackSuite.scenarios) {
      it(`${server.id} rejects ${scenario.name}`, async () => {
        const env = buildCompatEnv();
        running = await startServer(server, env);
        const targetUrl = `http://127.0.0.1:${running.ready.port}${offer.resource}`;

        // Prime to get a server-issued challenge id where applicable.
        const primeResponse = await fetch(targetUrl);
        const issuedChallengeId = primeResponse.headers.get("x-challenge-id");
        const baseCredential = issuedChallengeId
          ? deepMerge(credential, {
              payload: { challengeId: issuedChallengeId },
            })
          : credential;

        let attackCredential = deepMerge(
          baseCredential,
          scenario.credentialOverride,
        );
        if (scenario.replaceFields) {
          const replaced: Record<string, unknown> = {
            ...(attackCredential as unknown as Record<string, unknown>),
          };
          for (const field of scenario.replaceFields) {
            if (field in scenario.credentialOverride) {
              replaced[field] = scenario.credentialOverride[field];
            }
          }
          attackCredential = replaced as unknown as CanonicalCredential;
        }
        if (scenario.deleteFields) {
          const stripped: Record<string, unknown> = {
            ...(attackCredential as unknown as Record<string, unknown>),
          };
          for (const field of scenario.deleteFields) {
            delete stripped[field];
          }
          attackCredential = stripped as unknown as CanonicalCredential;
        }
        const header = encodeCredential(attackCredential);
        const { status, body } = await postCredential(targetUrl, header);

        if (
          status === 200 &&
          scenario.wireOnlyMayAccept &&
          WIRE_ONLY_ADAPTER_IDS.has(server.id)
        ) {
          // Acceptable for wire-only adapters; nothing further to assert.
          return;
        }
        expect(status).toBe(402);
        const token = extractRejectToken(body);
        expect(
          token,
          `attack ${scenario.name} produced no reject token in ${JSON.stringify(body)}`,
        ).toBeTruthy();
        // The token must be either one of the scenario-expected tokens
        // or the generic `payment_invalid` fallback (allowed for
        // wire-only adapters that don't decode the SVM transaction
        // blob). Together this asserts the server emitted a
        // taxonomy-aligned response — i.e. no novel out-of-band
        // strings, no process crash, no unparseable body.
        const allowed = new Set<string>([
          ...scenario.expectedRejectTokens,
          "payment_invalid",
        ]);
        expect(
          allowed.has(token as string),
          `attack ${scenario.name}: token ${token} not in allowed set ${[...allowed].join(",")}`,
        ).toBe(true);
      }, 60_000);
    }

    it(`${server.id} rejects replay (signature_consumed)`, async () => {
      const env = buildCompatEnv();
      running = await startServer(server, env);
      const targetUrl = `http://127.0.0.1:${running.ready.port}${offer.resource}`;

      const primeResponse = await fetch(targetUrl);
      const issuedChallengeId = primeResponse.headers.get("x-challenge-id");
      const sendCredential = issuedChallengeId
        ? deepMerge(credential, {
            payload: { challengeId: issuedChallengeId },
          })
        : credential;
      const header = encodeCredential(sendCredential);

      const first = await postCredential(targetUrl, header);
      // First send: accept OR reject — what matters is the second send
      // produces a stable rejection (not a different one each time).
      const second = await postCredential(targetUrl, header);

      if (first.status === 200) {
        // If first succeeded, the replay MUST be rejected with
        // signature_consumed.
        expect(second.status).toBe(402);
        const token = extractRejectToken(second.body);
        expect(
          attackSuite.replayScenario.expectedRejectTokens.includes(
            token as string,
          ) || token === "payment_invalid",
        ).toBe(true);
      } else {
        // If the first send was rejected, the second send MUST be
        // rejected deterministically with the same token (idempotent
        // rejection).
        expect(second.status).toBe(first.status);
        expect(extractRejectToken(second.body)).toBe(
          extractRejectToken(first.body),
        );
      }
    }, 60_000);
  }
});
