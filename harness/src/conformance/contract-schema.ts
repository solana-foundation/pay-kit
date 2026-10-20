// Runtime JSON-Schema validation of the conformance vectors at load.
//
// `loadVectors()` (used by the coverage table) validates every filled vector
// against this schema so an authoring mistake (wrong mode, missing
// expect.outcome, stray envelope key) fails with a clear message.
//
// The testee result contract (`RunnerResult`) is validated by the driver,
// `pkc run` (rust/crates/conformance/src/run/result.rs), with the same
// `additionalProperties: false` strictness the retired vitest driver used.

import Ajv from "ajv";
import type { ErrorObject, ValidateFunction } from "ajv";

// The shared reject vocabulary. Kept in lockstep with schema.ts RejectCode:
// a runner that maps onto a category outside this list is a contract drift.
const rejectCodeSchema = {
  enum: [
    "compute-price-over-cap",
    "compute-limit-over-cap",
    "fee-payer-not-authority",
    "fee-payer-is-funds-source",
    "decimals-mismatch",
    "splits-exceed-amount",
    "too-many-splits",
    "unexpected-instruction",
    "no-matching-transfer",
    "amount-mismatch",
    "invalid-payload",
    "unsupported-version",
    "wrong-network",
    "payment-identifier-required",
    "invalid-challenge",
    "voucher-expired",
    "voucher-expires-before-settlement",
    "accepted-mismatch",
  ],
} as const;

// A filled vector. Permissive on the input payload bodies (request,
// x402Offer, ...) but strict on the envelope keys so a malformed vector
// fails at load.
export const conformanceVectorSchema = {
  $id: "ConformanceVector",
  type: "object",
  additionalProperties: false,
  required: ["id", "intent", "mode", "spec", "input", "expect"],
  properties: {
    id: { type: "string", pattern: "^[a-z][a-z0-9-]*[a-z0-9]$" },
    intent: { enum: ["charge", "x402-exact", "session"] },
    mode: {
      enum: ["build-transaction", "verify-transaction", "canonical-bytes"],
    },
    description: { type: "string" },
    // Every vector names the sentence it encodes, inside a pinned spec repo.
    spec: {
      type: "object",
      additionalProperties: false,
      required: ["doc", "section", "quote"],
      properties: {
        doc: { type: "string", pattern: "^(mpp-specs|x402)/specs/[^.][^\\s]*\\.md$" },
        section: { type: "string", minLength: 1 },
        quote: { type: "string", minLength: 12 },
      },
    },
    requirements: {
      type: "array",
      items: { type: "string", pattern: "^(MPP|X402)-[0-9a-f]{10}$" },
    },
    bugType: {
      enum: ["replay", "auth-bypass", "settlement", "wire", "defaults", "malleability", "precedence"],
    },
    tier: { enum: ["offline", "interop", "onchain"] },
    role: { enum: ["client", "server", "both"] },
    provenance: { enum: ["generated", "authored"] },
    input: { type: "object" },
    expect: {
      type: "object",
      required: ["outcome"],
      properties: {
        outcome: { enum: ["accept", "reject"] },
        rejectCode: rejectCodeSchema,
      },
    },
  },
} as const;

const ajv = new Ajv({ allErrors: true });
const validateConformanceVector = ajv.compile(conformanceVectorSchema);

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  if (!errors || errors.length === 0) return "(no detail)";
  return errors
    .map((e) => `${e.instancePath || "(root)"} ${e.message ?? ""}`.trim())
    .join("; ");
}

function assertValid(
  validate: ValidateFunction,
  value: unknown,
  label: string,
): void {
  if (!validate(value)) {
    throw new Error(
      `${label} violates the conformance ABI: ${formatErrors(validate.errors)}`,
    );
  }
}

// Throws if `vector` is not a structurally valid ConformanceVector. Called
// once per vector at load so an authoring mistake fails at the boundary,
// not deep in a runner.
export function assertConformanceVector(vector: unknown, context: string): void {
  assertValid(validateConformanceVector, vector, `vector ${context}`);
}
