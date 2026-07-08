// Cross-SDK conformance-vector driver.
//
// Loads every vector under harness/vectors/, spawns the TypeScript
// reference runner once per vector over stdin/stdout, and asserts the
// runner output against the vector's `expect` block. The oracle is the
// DECODED SEMANTIC SHAPE for build/verify vectors and EXACT BYTES for
// canonical-bytes vectors.
//
// This suite is deterministic and RPC-free: it needs no surfpool, no
// loopback socket, and no live validator. Only the TS reference runner
// ships in this change; runners for the other SDKs are a tracked
// follow-up (see harness/vectors/README.md), at which point this driver
// gains a `RUNNERS` table and asserts every runner agrees per vector.

import { spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { address } from "@solana/kit";
import { findAssociatedTokenPda } from "@solana-program/token";
import { describe, expect, it } from "vitest";
import {
  assertConformanceVector,
  assertRunnerResult,
} from "../src/conformance/contract-schema";
import { discoverRunners } from "../src/conformance/runners";
import { parseLanguageAllowlist } from "../src/conformance/select";
import type {
  ConformanceVector,
  RunnerResult,
  TransactionShape,
  X402EnvelopeShape,
} from "../src/conformance/schema";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "vectors");

function loadVectors(): ConformanceVector[] {
  const files = readdirSync(vectorsDir).filter((name) => name.endsWith(".json"));
  const vectors: ConformanceVector[] = [];
  for (const file of files) {
    const parsed = JSON.parse(
      readFileSync(join(vectorsDir, file), "utf8"),
    ) as ConformanceVector[];
    for (const vector of parsed) {
      // Validate the vector against the ABI at load so an authoring mistake
      // (wrong mode, missing expect.outcome, stray envelope key) fails here
      // with a clear message instead of deep inside a runner.
      assertConformanceVector(vector, `${file}:${vector?.id ?? "(no id)"}`);
      vectors.push(vector);
    }
  }
  return vectors;
}

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

describe("cross-SDK conformance vectors", () => {
  it("loaded at least the seeded vector classes", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(10);
    const modes = new Set(vectors.map((v) => v.mode));
    expect(modes.has("build-transaction")).toBe(true);
    expect(modes.has("verify-transaction")).toBe(true);
    expect(modes.has("canonical-bytes")).toBe(true);
  });

  for (const { language, command, cwd: runnerCwd, intents } of RUNNERS) {
    describe(`${language} reference runner`, () => {
      for (const vector of vectors) {
        it(`${vector.id} (${vector.mode}) -> ${vector.expect.outcome}`, async (ctx) => {
          // Skip vectors for an intent this runner does not declare. Lets a new
          // intent (e.g. "session") land with only the SDKs that implement it;
          // runners without an explicit `intents` list default to the original
          // cross-SDK set ("charge", "x402-exact").
          if (!intents.includes(vector.intent)) {
            ctx.skip();
            return;
          }
          const result = await runVector(command, vector, runnerCwd);
          expect(result.id).toBe(vector.id);

          // A runner that does not support a vector's mode for this SDK's
          // role (e.g. verify-transaction on a client-only SDK) declares it
          // either as a dedicated `unsupported-mode` outcome or as a reject
          // whose error is prefixed "unsupported-mode". Both conventions are
          // honored so every SDK runner registers cleanly regardless of its
          // style. The prefix is a deliberate sentinel and never a real
          // reject category, so it skips even when the vector itself expects
          // a reject (a client-only SDK cannot exercise a verify-reject
          // vector at all). Skip the vector for this language rather than
          // fail it.
          if (
            (result.outcome as string) === "unsupported-mode" ||
            (result.outcome === "reject" &&
              (result.error ?? "").startsWith("unsupported-mode"))
          ) {
            ctx.skip();
            return;
          }

          expect(
            result.outcome,
            `expected ${vector.expect.outcome} but runner said ${result.outcome}: ${result.error ?? ""}`,
          ).toBe(vector.expect.outcome);

          if (vector.expect.outcome === "reject") {
            // Pin WHY the SDK rejected, not just that it did. A vector that
            // declares a rejectCode forces the runner to have mapped its
            // native error onto the shared category, so a guard that fires
            // for the wrong reason (e.g. a decimals mismatch caught only by a
            // generic no-matching-transfer fallback) fails here instead of
            // passing on outcome alone.
            if (vector.expect.rejectCode !== undefined) {
              expect(
                result.rejectCode,
                `expected reject category ${vector.expect.rejectCode} but runner emitted ${result.rejectCode ?? "(none)"}: ${result.error ?? ""}`,
              ).toBe(vector.expect.rejectCode);
            }
            return;
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
            return;
          }

          if (vector.intent === "x402-exact") {
            if (vector.expect.x402EnvelopeShape) {
              assertEnvelopeShape(
                vector.expect.x402EnvelopeShape,
                result.x402EnvelopeShape,
              );
            }
            return;
          }

          if (vector.expect.transactionShape) {
            await assertShape(vector.expect.transactionShape, result.transactionShape);
          }
        }, 60_000);
      }
    });
  }
});
