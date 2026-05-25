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
type RustCredential = {
  x402Version: number;
  scheme: string;
  network: string;
  accepted: Record<string, unknown>;
  payload: { transaction?: string; signature?: string };
};
const rustCredential = loadJson<RustCredential>(
  "canonical-payment-signature-rust.json",
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
// Default compat suite covers fast in-process adapters only — adding
// cargo-built adapters (rust-x402) to the default run multiplies CI
// wall time by an order of magnitude per test. Opt in to rust-x402
// compat coverage via X402_COMPAT_INCLUDE_RUST=1 (CI matrix sets this
// on the rust toolchain job). The live matrix (env-gated) covers the
// rust spine on every happy-path pair regardless of this flag.
const COMPAT_INCLUDE_IDS = new Set<string>(["ts-x402"]);
if (process.env.X402_COMPAT_INCLUDE_RUST === "1") {
  COMPAT_INCLUDE_IDS.add("rust-x402");
}

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
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
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

// Pull a reject token from a 402 response body. The Rust spine wraps
// verifier failures as `{ error: "payment_invalid", message: "<verifier-token>: ..." }`
// (rust/crates/x402/src/bin/interop_server.rs ~L246) so the most-specific
// token is in `message`, not `error`. We search every field for a known
// reject token before falling back to the high-level `error` field. Order
// of preference: `code` (canonical), then any field with a substring match
// against the known reject taxonomy, then `error`.
function extractRejectToken(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, unknown>;
  // Canonical structured code wins outright.
  if (typeof record.code === "string" && record.code.length > 0) {
    return record.code;
  }
  // Then look in every string field for the most-specific token from
  // the known taxonomy. `invalid_exact_svm_payload_*` and the
  // high-level set are checked; first match wins by specificity
  // (svm-payload tokens before high-level fallbacks).
  const candidates: string[] = [];
  for (const field of ["message", "error", "detail"] as const) {
    const value = record[field];
    if (typeof value === "string") candidates.push(value);
  }
  // Sort longest-first so suffixed tokens (e.g.
  // `..._compute_price_instruction_too_high`) match before their
  // shorter prefix (`..._compute_price_instruction`) — otherwise the
  // shorter token would greedily credit the wrong reject class.
  const taxonomy = [
    ...rejectTokens.exactSvmPayloadTokens,
    ...rejectTokens.highLevelTokens,
  ].sort((a, b) => b.length - a.length);
  for (const token of taxonomy) {
    for (const candidate of candidates) {
      if (candidate.includes(token)) return token;
    }
  }
  // No taxonomy match — return whatever `error` or `message` says so
  // the assertion can show the unrecognised string.
  for (const field of ["error", "message"] as const) {
    const value = record[field];
    if (typeof value === "string" && value.length > 0) return value;
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

  it("rust-canonical fixture matches the rust spine PaymentSignatureEnvelope shape", () => {
    // Wire shape lock: every field the rust spine's
    // PaymentSignatureEnvelope (rust/crates/x402/src/protocol/schemes/exact/types.rs)
    // requires must be present. `payload` must deserialize as
    // PaymentProof::Transaction OR PaymentProof::Signature — i.e. exactly
    // one of `transaction` / `signature` keys, both base-encoded strings.
    expect(rustCredential.x402Version).toBe(2);
    expect(typeof rustCredential.scheme).toBe("string");
    expect(typeof rustCredential.network).toBe("string");
    expect(rustCredential.accepted).toBeDefined();
    const proofKeys = Object.keys(rustCredential.payload);
    expect(proofKeys).toHaveLength(1);
    const proofKey = proofKeys[0];
    expect(["transaction", "signature"]).toContain(proofKey);
    const proofValue = (rustCredential.payload as Record<string, unknown>)[
      proofKey
    ];
    expect(typeof proofValue).toBe("string");
    expect((proofValue as string).length).toBeGreaterThan(0);
    if (proofKey === "transaction") {
      // base64 round-trip — the spine's first step.
      const decoded = Buffer.from(proofValue as string, "base64");
      const reEncoded = decoded.toString("base64");
      expect(reEncoded).toBe(proofValue);
    }
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

  it("canonical reject tokens are exactly the rust spine reject taxonomy", () => {
    // Strict parity lock: grep the rust spine for every
    // `"invalid_exact_svm_payload_*"` literal and assert the fixture
    // lists EXACTLY those tokens (no missing, no stale). When the rust
    // spine adds, removes, or renames a token, this test fails and
    // points at the divergence — no silent drift.
    const verifyPath = path.resolve(
      __dirname,
      "../../rust/crates/x402/src/protocol/schemes/exact/verify.rs",
    );
    if (!fs.existsSync(verifyPath)) {
      // Rust source not vendored in this checkout (e.g. minimal CI image
      // without the rust workspace). Fall back to a non-empty floor.
      expect(rejectTokens.exactSvmPayloadTokens.length).toBeGreaterThan(0);
      return;
    }
    const verifySource = fs.readFileSync(verifyPath, "utf8");
    const spineTokens = new Set<string>();
    for (const match of verifySource.matchAll(
      /"(invalid_exact_svm_payload_[a-z_]+)"/g,
    )) {
      spineTokens.add(match[1]);
    }
    const fixtureSet = new Set(rejectTokens.exactSvmPayloadTokens);
    const missing = [...spineTokens].filter(t => !fixtureSet.has(t));
    const stale = [...fixtureSet].filter(t => !spineTokens.has(t));
    expect(
      missing,
      `tokens in rust spine but missing from canonical-reject-tokens.json: ${missing.join(", ")}`,
    ).toEqual([]);
    expect(
      stale,
      `tokens in canonical-reject-tokens.json but no longer in rust spine: ${stale.join(", ")}`,
    ).toEqual([]);
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

      // Wire-only adapters may accept the stub credential (200). Full
      // verifiers MUST reject — the canonical credential carries a
      // `payload.challengeId/resource` shape, not a real
      // PaymentProof::Transaction, so accepting it would be a verifier
      // bypass. Adapters opting in via X402_COMPAT_STUB_ACCEPT (CSV of
      // ids) declare their verifier accepts the stub on purpose.
      const stubAcceptAllowed =
        WIRE_ONLY_ADAPTER_IDS.has(server.id) ||
        (process.env.X402_COMPAT_STUB_ACCEPT ?? "")
          .split(",")
          .map(s => s.trim())
          .includes(server.id);
      if (status === 200) {
        expect(
          stubAcceptAllowed,
          `full verifier ${server.id} accepted the TS-wire stub credential (verifier bypass risk)`,
        ).toBe(true);
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
        // The token must be one of the scenario-expected tokens.
        // Wire-only adapters (no SVM transaction decoder) may also emit
        // the generic `payment_invalid` fallback — full verifiers must
        // emit a specific token. This prevents a full verifier from
        // silently regressing to a generic error and still passing the
        // parity lock.
        const allowed = new Set<string>(scenario.expectedRejectTokens);
        if (WIRE_ONLY_ADAPTER_IDS.has(server.id)) {
          allowed.add("payment_invalid");
        }
        expect(
          allowed.has(token as string),
          `attack ${scenario.name}: token ${token} not in allowed set ${[...allowed].join(",")}`,
        ).toBe(true);
      }, 60_000);
    }

    // Replay assertion requires the canonical credential to be accepted
    // on first submission. Adapters whose verifier needs a real signed
    // transaction blob (rust spine) reject the stub canonical credential
    // at bincode-deserialization, so replay against them is covered by
    // the live matrix where a real PaymentProof::Transaction is built.
    const replayCapable =
      WIRE_ONLY_ADAPTER_IDS.has(server.id) ||
      process.env.X402_COMPAT_REPLAY_TRUST?.split(",").includes(server.id);
    if (!replayCapable) {
      it.skip(`${server.id} replay test requires a real signed transaction (covered by live matrix)`, () => {});
      continue;
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
      // Replay semantics REQUIRE the first submission to be accepted —
      // otherwise the "second submit must produce signature_consumed"
      // assertion is vacuous (a server that rejects every credential
      // would trivially pass). Wire-only adapters that semantically
      // reject the canonical credential (because the challenge id
      // wasn't issued by this process, etc.) are not the right vehicle
      // for the replay assertion; they exercise the
      // `challenge_verification_failed` path under canonical credential
      // test above. The replay test therefore fails if the first
      // submission was rejected — that's a wiring bug, not a feature.
      expect(
        first.status,
        `replay test requires first submit to be accepted; got ${first.status}: ${JSON.stringify(first.body)}`,
      ).toBe(200);

      const second = await postCredential(targetUrl, header);
      expect(second.status).toBe(402);
      const token = extractRejectToken(second.body);
      const replayAllowed = new Set<string>(
        attackSuite.replayScenario.expectedRejectTokens,
      );
      // No payment_invalid fallback for replay: once the first
      // submission was accepted (asserted above), the second MUST be
      // classified as signature_consumed by every adapter. A generic
      // rejection here would be a real replay-detection regression.
      expect(
        replayAllowed.has(token as string),
        `replay token ${token} not in allowed ${[...replayAllowed].join(",")}`,
      ).toBe(true);
    }, 60_000);
  }
});
