// Cross-SDK conformance-vector driver.
//
// Loads every vector under harness/vectors/, spawns each SDK's runner once
// per vector over stdin/stdout, and asserts the runner output against the
// vector's `expect` block. The oracle is the DECODED SEMANTIC SHAPE for
// build/verify vectors and EXACT BYTES for canonical-bytes vectors.
//
// What each SDK must pass is declared in harness/expectations/<lang>.toml
// and reconciled exactly (src/expectations.ts): unlisted failures fail,
// listed failures that pass fail, and unsupported entries are executed and
// must still report unsupported. Nothing is skipped.
//
// HARNESS_EXPECTATIONS_DISCOVER=1 runs every vector for every SDK
// regardless of claims and only records outcomes to harness/results/, which
// is how expectations files are seeded and audited.

import { spawn } from "node:child_process";
import { address } from "@solana/kit";
import { findAssociatedTokenPda } from "@solana-program/token";
import { afterAll, describe, expect, it } from "vitest";
import { assertRunnerResult } from "../src/conformance/contract-schema";
import { loadVectors } from "../src/conformance/load";
import { discoverRunners } from "../src/conformance/runners";
import { parseLanguageAllowlist } from "../src/conformance/select";
import {
  type CaseRef,
  danglingEntries,
  decide,
  loadAllExpectations,
} from "../src/expectations";
import { CaseRecorder, discoveryMode, observe, requireMode } from "../src/expectations-run";
import type {
  ConformanceVector,
  RunnerResult,
  TransactionShape,
  X402EnvelopeShape,
} from "../src/conformance/schema";

// One CLI per SDK over stdin/stdout, discovered from per-language manifest
// files under harness/runners/ rather than a hardcoded table: adding a
// language is a manifest drop with no edit here. Each runner declares its
// own command + cwd (its SDK tree, so the toolchain resolves the project),
// so the suite needs no separate build step beyond the per-language caches.
//
// CI can narrow the set to the languages a PR actually touches via
// MPP_CONFORMANCE_LANGUAGES (a comma-separated allowlist; see
// scripts/select-conformance-runners.mjs). Unset = run every runner.
const allowlist = parseLanguageAllowlist(process.env.MPP_CONFORMANCE_LANGUAGES);
const RUNNERS = discoverRunners().filter(
  (runner) => !allowlist || allowlist.has(runner.language),
);

function runVector(
  command: string[],
  vector: ConformanceVector,
  cwd: string,
): Promise<RunnerResult> {
  const [bin, ...args] = command;
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(
          new Error(
            `runner exited with code ${code} for vector ${vector.id}; stderr: ${stderr}`,
          ),
        );
        return;
      }
      const line = stdout.trim().split("\n").filter(Boolean).pop();
      if (!line) {
        reject(new Error(`runner produced no output for vector ${vector.id}`));
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (error) {
        reject(
          new Error(
            `failed to parse runner output for ${vector.id}: ${line}\n${String(error)}`,
          ),
        );
        return;
      }
      // Validate the runner's stdout against the ABI before the driver
      // trusts it. A runner that emits a malformed/over-typed shape fails
      // loudly and attributably here instead of silently passing TS types
      // that vanish at runtime or tripping a confusing downstream assertion.
      try {
        assertRunnerResult(parsed, vector.id);
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      resolve(parsed as RunnerResult);
    });
    child.stdin.write(JSON.stringify(vector));
    child.stdin.end();
  });
}

async function assertShape(
  expected: TransactionShape,
  actual: TransactionShape | undefined,
): Promise<void> {
  expect(actual, "runner did not emit a transactionShape").toBeDefined();
  if (!actual) return;

  if (expected.feePayer !== undefined) {
    expect(actual.feePayer).toBe(expected.feePayer);
  }

  if (expected.maxComputeUnitLimit !== undefined) {
    expect(actual.maxComputeUnitLimit).toBeLessThanOrEqual(
      expected.maxComputeUnitLimit,
    );
  }
  if (expected.maxComputeUnitPrice !== undefined) {
    expect(BigInt(actual.maxComputeUnitPrice ?? "0")).toBeLessThanOrEqual(
      BigInt(expected.maxComputeUnitPrice),
    );
  }

  for (const forbidden of expected.forbiddenPrograms ?? []) {
    for (const transfer of actual.transfers ?? []) {
      expect(
        transfer.tokenProgram,
        `forbidden program ${forbidden} appeared in a transfer`,
      ).not.toBe(forbidden);
    }
  }

  if (expected.memo !== undefined) {
    expect(new Set(actual.memo ?? [])).toEqual(new Set(expected.memo));
  }

  if (expected.transfers !== undefined) {
    expect(actual.transfers, "transfer count mismatch").toHaveLength(
      expected.transfers.length,
    );
    for (const wanted of expected.transfers) {
      // Resolve the expected on-chain destination: SPL transfers land in
      // the recipient's ATA, so derive it from destinationOwner + mint +
      // tokenProgram. SOL transfers go straight to the destination.
      let wantedDestination = wanted.destination;
      if (
        wanted.kind === "spl" &&
        wanted.destinationOwner &&
        wanted.mint &&
        wanted.tokenProgram
      ) {
        const [ata] = await findAssociatedTokenPda({
          mint: address(wanted.mint),
          owner: address(wanted.destinationOwner),
          tokenProgram: address(wanted.tokenProgram),
        });
        wantedDestination = ata;
      }
      const match = (actual.transfers ?? []).find(
        (t) =>
          t.kind === wanted.kind &&
          t.amount === wanted.amount &&
          (wantedDestination === undefined || t.destination === wantedDestination) &&
          (wanted.mint === undefined || t.mint === wanted.mint) &&
          (wanted.decimals === undefined || t.decimals === wanted.decimals) &&
          (wanted.tokenProgram === undefined ||
            t.tokenProgram === wanted.tokenProgram),
      );
      expect(
        match,
        `no transfer matched ${JSON.stringify(wanted)} (dest ${wantedDestination}); got ${JSON.stringify(actual.transfers)}`,
      ).toBeDefined();
    }
  }
}

// Assert the decoded x402 envelope shape. Only the fields the vector
// pins are checked; presence/absence of scheme/network/accepted is part
// of the contract (v1 carries scheme+network and no accepted; v2 carries
// accepted and no top-level scheme/network).
function assertEnvelopeShape(
  expected: X402EnvelopeShape,
  actual: X402EnvelopeShape | undefined,
): void {
  expect(actual, "runner did not emit an x402EnvelopeShape").toBeDefined();
  if (!actual) return;

  expect(actual.x402Version).toBe(expected.x402Version);
  expect(actual.hasAccepted).toBe(expected.hasAccepted);
  expect(actual.payloadHasTransaction).toBe(expected.payloadHasTransaction);

  // scheme/network are pinned by presence: a vector that sets them
  // requires the exact value; a vector that omits them requires the
  // runner to have omitted them too (v2 must not leak a top-level
  // scheme/network).
  expect(actual.scheme).toBe(expected.scheme);
  expect(actual.network).toBe(expected.network);

  if (expected.acceptedScheme !== undefined) {
    expect(actual.acceptedScheme).toBe(expected.acceptedScheme);
  }
  if (expected.acceptedNetwork !== undefined) {
    expect(actual.acceptedNetwork).toBe(expected.acceptedNetwork);
  }
  if (expected.acceptedAsset !== undefined) {
    expect(actual.acceptedAsset).toBe(expected.acceptedAsset);
  }
  if (expected.acceptedPayTo !== undefined) {
    expect(actual.acceptedPayTo).toBe(expected.acceptedPayTo);
  }
  if (expected.acceptedAmount !== undefined) {
    expect(actual.acceptedAmount).toBe(expected.acceptedAmount);
  }

  // ── v2 extensions echo assertions ──
  if (expected.hasExtensions !== undefined) {
    expect(actual.hasExtensions).toBe(expected.hasExtensions);
  }
  if (expected.hasPaymentIdentifier !== undefined) {
    expect(actual.hasPaymentIdentifier).toBe(expected.hasPaymentIdentifier);
  }
  if (expected.paymentIdentifierRequired !== undefined) {
    expect(actual.paymentIdentifierRequired).toBe(
      expected.paymentIdentifierRequired,
    );
  }
  if (expected.extensionKeys !== undefined) {
    expect(actual.extensionKeys).toEqual(expected.extensionKeys);
  }
  // A pinned id is asserted exactly; an unpinned-but-required id is
  // asserted only against the spec pattern (the runner generated it).
  if (expected.paymentIdentifierId !== undefined) {
    expect(actual.paymentIdentifierId).toBe(expected.paymentIdentifierId);
  } else if (expected.hasPaymentIdentifier && expected.paymentIdentifierRequired) {
    expect(actual.paymentIdentifierId, "required id was not echoed").toMatch(
      /^[A-Za-z0-9_-]{16,128}$/,
    );
  }
}

const vectors = loadVectors();

// Execute one vector against one runner and compare against `expect`.
// Throws (via vitest `expect`) on any mismatch; returns "unsupported" when the
// runner declares it cannot express the vector's mode.
async function checkVector(
  command: string[],
  cwd: string,
  vector: ConformanceVector,
): Promise<"pass" | { unsupported: string }> {
  const result = await runVector(command, vector, cwd);
  expect(result.id).toBe(vector.id);

  // A runner that cannot express a vector's mode for its SDK's role (e.g.
  // verify-transaction on a client-only SDK) reports `unsupported-mode`, or
  // a reject whose error starts with "unsupported-mode". The reconciler
  // decides whether that is allowed for this (SDK, vector).
  if (
    (result.outcome as string) === "unsupported-mode" ||
    (result.outcome === "reject" && (result.error ?? "").startsWith("unsupported-mode"))
  ) {
    return { unsupported: result.error ?? "unsupported-mode" };
  }

  expect(
    result.outcome,
    `expected ${vector.expect.outcome} but runner said ${result.outcome}: ${result.error ?? ""}`,
  ).toBe(vector.expect.outcome);

  if (vector.expect.outcome === "reject") {
    // Pin WHY the SDK rejected, not just that it did. A vector that
    // declares a rejectCode forces the runner to have mapped its native
    // error onto the shared category, so a guard that fires for the wrong
    // reason fails here instead of passing on outcome alone.
    if (vector.expect.rejectCode !== undefined) {
      expect(
        result.rejectCode,
        `expected reject category ${vector.expect.rejectCode} but runner emitted ${result.rejectCode ?? "(none)"}: ${result.error ?? ""}`,
      ).toBe(vector.expect.rejectCode);
    }
    return "pass";
  }

  if (vector.mode === "canonical-bytes") {
    const wanted = vector.expect.exactBytes;
    expect(wanted, "canonical-bytes vector missing expect.exactBytes").toBeDefined();
    if (wanted?.canonicalJson !== undefined) {
      expect(result.exactBytes?.canonicalJson).toBe(wanted.canonicalJson);
    }
    if (wanted?.base64Url !== undefined) {
      expect(result.exactBytes?.base64Url).toBe(wanted.base64Url);
    }
    if (wanted?.bytes !== undefined) {
      expect(result.exactBytes?.bytes).toEqual(wanted.bytes);
    }
    return "pass";
  }

  if (vector.intent === "x402-exact") {
    if (vector.expect.x402EnvelopeShape) {
      assertEnvelopeShape(vector.expect.x402EnvelopeShape, result.x402EnvelopeShape);
    }
    return "pass";
  }

  if (vector.expect.transactionShape) {
    await assertShape(vector.expect.transactionShape, result.transactionShape);
  }
  return "pass";
}

const EXPECTATIONS = loadAllExpectations();
const vectorRefs: CaseRef[] = vectors.map((v) => ({
  suite: "vector",
  id: v.id,
  capability: v.intent,
}));

describe("cross-SDK conformance vectors", () => {
  it("loaded at least the seeded vector classes", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(10);
    const modes = new Set(vectors.map((v) => v.mode));
    expect(modes.has("build-transaction")).toBe(true);
    expect(modes.has("verify-transaction")).toBe(true);
    expect(modes.has("canonical-bytes")).toBe(true);
  });

  it("vector ids are unique", () => {
    const ids = vectors.map((v) => v.id);
    expect(ids.length).toBe(new Set(ids).size);
  });

  it("every runner manifest has expectations claiming vectors, and vice versa", () => {
    const manifests = new Set(discoverRunners().map((r) => r.language));
    const claiming = new Set(
      [...EXPECTATIONS.values()]
        .filter((e) => e.capabilities.vector.size > 0)
        .map((e) => e.language),
    );
    expect([...manifests].sort()).toEqual([...claiming].sort());
  });

  for (const { language, command, cwd: runnerCwd } of RUNNERS) {
    describe(`${language} reference runner`, () => {
      const exp = EXPECTATIONS.get(language);
      if (!exp) throw new Error(`no harness/expectations/${language}.toml`);
      const recorder = new CaseRecorder("vector", language);

      it("expectations have no dangling entries", () => {
        expect(danglingEntries(exp, "vector", vectorRefs)).toEqual([]);
      });

      for (const [index, vector] of vectors.entries()) {
        const ref = vectorRefs[index];
        const decision = discoveryMode() ? { kind: "pass" as const } : decide(exp, ref);
        if (decision.kind === "unclaimed") {
          recorder.record(ref, decision, undefined);
          continue;
        }
        it(`${vector.id} (${vector.mode}) -> ${vector.expect.outcome} [${decision.kind}]`, async () => {
          const observed = await observe(() => checkVector(command, runnerCwd, vector));
          recorder.verdict(exp, ref, decision, observed);
        }, 60_000);
      }

      afterAll(() => {
        recorder.flush();
        if (requireMode() && !discoveryMode()) recorder.assertComplete(vectorRefs, exp);
      });
    });
  }
});
