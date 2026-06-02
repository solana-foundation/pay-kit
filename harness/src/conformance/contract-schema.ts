// Runtime JSON-Schema validation of the conformance adapter ABI.
//
// The driver (test/conformance.test.ts) spawns each SDK's runner over a
// stdin (ConformanceVector) / stdout (RunnerResult) JSON contract. Until
// now the contract was enforced only by TypeScript types, which vanish at
// runtime: a runner that emits a structurally-wrong `result` line (a wrong
// field type, an undeclared key, a missing `outcome`) would either pass for
// the wrong reason or fail with a confusing downstream assertion far from
// the real cause.
//
// These schemas validate the vector the driver SENDS and the result a
// runner RETURNS at the process boundary, so a malformed shape fails loudly
// and attributably ("runner X emitted a result that violates the ABI:
// <ajv error>") instead of silently. Mirrors mpp-tools' harness.py, which
// JSON-Schema-validates every adapter request and every success/error value.
//
// `additionalProperties: false` is deliberate: an over-typed shape (a key
// the contract does not declare) is a contract drift and must surface, not
// be tolerated.

import Ajv from "ajv";
import type { ErrorObject, ValidateFunction } from "ajv";

const exactBytesSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    canonicalJson: { type: "string" },
    base64Url: { type: "string" },
    bytes: { type: "array", items: { type: "integer" } },
  },
} as const;

const transferSchema = {
  type: "object",
  additionalProperties: false,
  required: ["kind", "amount"],
  properties: {
    kind: { enum: ["spl", "sol"] },
    destination: { type: "string" },
    destinationOwner: { type: "string" },
    mint: { type: "string" },
    amount: { type: "string" },
    decimals: { type: "integer" },
    tokenProgram: { type: "string" },
  },
} as const;

const transactionShapeSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    feePayer: { type: "string" },
    transfers: { type: "array", items: transferSchema },
    forbiddenPrograms: { type: "array", items: { type: "string" } },
    maxComputeUnitLimit: { type: "integer" },
    maxComputeUnitPrice: { type: "string" },
    memo: { type: "array", items: { type: "string" } },
  },
} as const;

const x402EnvelopeShapeSchema = {
  type: "object",
  additionalProperties: false,
  required: ["x402Version", "hasAccepted", "payloadHasTransaction"],
  properties: {
    x402Version: { type: "number" },
    scheme: { type: "string" },
    network: { type: "string" },
    hasAccepted: { type: "boolean" },
    payloadHasTransaction: { type: "boolean" },
    acceptedScheme: { type: "string" },
    acceptedNetwork: { type: "string" },
    acceptedAsset: { type: "string" },
    acceptedPayTo: { type: "string" },
    acceptedAmount: { type: "string" },
  },
} as const;

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
  ],
} as const;

// What a runner is allowed to write to stdout for one vector.
export const runnerResultSchema = {
  $id: "RunnerResult",
  type: "object",
  additionalProperties: false,
  required: ["id", "outcome"],
  properties: {
    id: { type: "string" },
    outcome: { enum: ["accept", "reject", "unsupported-mode"] },
    transactionShape: transactionShapeSchema,
    x402EnvelopeShape: x402EnvelopeShapeSchema,
    exactBytes: exactBytesSchema,
    error: { type: "string" },
    rejectCode: rejectCodeSchema,
  },
} as const;

// What the driver is allowed to send to a runner on stdin. Permissive on
// the input payload bodies (request/x402Offer/etc. are validated by the
// runners themselves and the expect block by the driver) but strict on the
// envelope keys so a malformed vector authored by mistake fails at load.
export const conformanceVectorSchema = {
  $id: "ConformanceVector",
  type: "object",
  additionalProperties: false,
  required: ["id", "intent", "mode", "input", "expect"],
  properties: {
    id: { type: "string" },
    intent: { enum: ["charge", "x402-exact"] },
    mode: {
      enum: ["build-transaction", "verify-transaction", "canonical-bytes"],
    },
    description: { type: "string" },
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
const validateRunnerResult = ajv.compile(runnerResultSchema);
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

// Throws if `result` is not a structurally valid RunnerResult. Called on
// every runner stdout line before the driver asserts against the vector's
// expect block.
export function assertRunnerResult(result: unknown, context: string): void {
  assertValid(validateRunnerResult, result, `runner result for ${context}`);
}

// Throws if `vector` is not a structurally valid ConformanceVector. Called
// once per vector at load so an authoring mistake fails at the boundary,
// not deep in a runner.
export function assertConformanceVector(vector: unknown, context: string): void {
  assertValid(validateConformanceVector, vector, `vector ${context}`);
}
