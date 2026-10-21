// `x402-batch-settlement` vectors for the TypeScript testee. pay-kit has no
// batch-settlement implementation, so the testee drives the vendored upstream
// `@x402/svm` batch-settlement mechanism (the tarball pay-kit bundles). The
// testee passes the vector's input to the SDK unchanged (harness/AGENTS.md):
//
// - canonical-bytes: `encodeBatchAuthorizationMessage`,
//   `encodeCloseAuthorizationDigest`, and the wire guards `isBatchPayload` /
//   `isBatchFacilitatorPayload` (a payload the guard accepts is echoed in its
//   JCS form). The upstream package exports no voucher-message, channel-PDA,
//   binding-memo or requirements codec: those keys are unsupported.
// - verify-transaction: the upstream facilitator (`BatchSvmScheme`) behind
//   `x402Facilitator`, on the route's `batchRequirements` and `input.rpcUrl`.
//   It is stateless: it never sees the resource server's store record.
// - build-transaction: the upstream client scheme through `x402Client`, for
//   the first `deposit` only (later operations need the upstream client's
//   own channel storage).
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { canonicalizeJson, base64UrlFromUtf8 } from "../jcs";
import { classifyReject } from "../reject";
import type { ConformanceVector, RunnerResult } from "../schema";
// Vendored upstream x402 (the tarballs @solana/pay-kit bundles).
import { x402Client } from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/client/index.mjs";
import { x402Facilitator } from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/facilitator/index.mjs";
import {
  decodePaymentSignatureHeader,
  encodePaymentSignatureHeader,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/http/index.mjs";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/types/index.mjs";
import {
  encodeBatchAuthorizationMessage,
  encodeCloseAuthorizationDigest,
  isBatchFacilitatorPayload,
  isBatchPayload,
  toFacilitatorSvmSigner,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/index.mjs";
import { BatchSvmScheme as BatchClient } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/batch-settlement/client/index.mjs";
import { BatchSvmScheme as BatchFacilitator } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/batch-settlement/facilitator/index.mjs";

type Json = Record<string, unknown>;

function unsupported(vector: ConformanceVector, reason: string): RunnerResult {
  return {
    error: `unsupported-mode: ${reason}`,
    id: vector.id,
    outcome: "unsupported-mode",
  };
}

function rejected(vector: ConformanceVector, message: string): RunnerResult {
  return {
    error: message,
    id: vector.id,
    outcome: "reject",
    rejectCode: classifyReject(message),
  };
}

function exactBytes(
  vector: ConformanceVector,
  bytes: Uint8Array,
): RunnerResult {
  const buffer = Buffer.from(bytes);
  return {
    exactBytes: {
      base64Url: buffer.toString("base64url"),
      bytes: Array.from(buffer),
    },
    id: vector.id,
    outcome: "accept",
  };
}

function rpcUrl(input: Json): string {
  if (typeof input.rpcUrl !== "string")
    throw new Error("driver did not inject input.rpcUrl");
  return input.rpcUrl;
}

function canonical(vector: ConformanceVector, input: Json): RunnerResult {
  const am = input.batchAuthorizationMessage as Json | undefined;
  if (am) {
    try {
      return exactBytes(
        vector,
        encodeBatchAuthorizationMessage({
          authorizedAmount: BigInt(String(am.authorizedAmount)),
          channelId: String(am.channelId),
          expiresAt: Number(am.expiresAt),
          operator: String(am.operator),
          payer: String(am.payer),
          requestId: String(am.requestId),
        }),
      );
    } catch (error) {
      return {
        error: `invalid payload: ${String(error)}`,
        id: vector.id,
        outcome: "reject",
        rejectCode: "invalid-payload",
      };
    }
  }
  const cd = input.batchCloseAuthorizationDigest as Json | undefined;
  if (cd) {
    try {
      return exactBytes(
        vector,
        encodeCloseAuthorizationDigest({
          channelId: String(cd.channelId),
          feePayer: String(cd.feePayer),
          maxClaimableAmount: BigInt(String(cd.maxClaimableAmount)),
          network: String(cd.network),
          programId: String(cd.programId),
          validBefore: Number(cd.validBefore),
          voucherExpiresAt: BigInt(Number(cd.voucherExpiresAt)),
        }),
      );
    } catch (error) {
      return {
        error: `invalid payload: ${String(error)}`,
        id: vector.id,
        outcome: "reject",
        rejectCode: "invalid-payload",
      };
    }
  }
  const wire = input.batchWire as
    { shape?: string; value?: unknown } | undefined;
  if (wire) {
    const guard =
      wire.shape === "payload"
        ? isBatchPayload
        : wire.shape === "redemption"
          ? isBatchFacilitatorPayload
          : undefined;
    if (!guard) {
      return unsupported(
        vector,
        `@x402/svm exports no codec or guard for batch ${wire.shape} objects`,
      );
    }
    if (!guard(wire.value)) {
      return {
        error: `invalid payload: @x402/svm rejects the batch ${wire.shape}`,
        id: vector.id,
        outcome: "reject",
        rejectCode: "invalid-payload",
      };
    }
    const canonicalJson = canonicalizeJson(wire.value);
    return {
      exactBytes: {
        base64Url: base64UrlFromUtf8(canonicalJson),
        canonicalJson,
      },
      id: vector.id,
      outcome: "accept",
    };
  }
  return unsupported(
    vector,
    "@x402/svm exports no batch voucher-message, channel-PDA or receiver-binding memo encoder",
  );
}

async function verify(
  vector: ConformanceVector,
  input: Json,
): Promise<RunnerResult> {
  if (input.batchCorrective) {
    return unsupported(
      vector,
      "@x402/svm adopts a corrective 402 only inside its client channel flow, with no single-shot entry point",
    );
  }
  const server = input.batchServer as Json;
  const requirements = input.batchRequirements as PaymentRequirements;
  const feePayer = await createKeyPairSignerFromBytes(
    new Uint8Array(server.feePayerSecretKey as number[]),
  );
  // As for x402 exact: the facilitator signer minus simulation, since the
  // vectors run without a validator.
  const signer = {
    ...toFacilitatorSvmSigner(feePayer, { defaultRpcUrl: rpcUrl(input) }),
    simulateTransaction: async (): Promise<void> => {},
  };
  const facilitator = new x402Facilitator().register(
    requirements.network as Network,
    new BatchFacilitator(signer, { rpcUrl: rpcUrl(input) }),
  );
  let payload: PaymentPayload;
  try {
    payload = decodePaymentSignatureHeader(String(input.x402PaymentHeader));
  } catch (error) {
    return rejected(vector, `invalid payload: ${String(error)}`);
  }
  try {
    const verification = await facilitator.verify(payload, requirements);
    if (!verification.isValid) {
      const reason = verification.invalidReason ?? "invalid_payload";
      return rejected(
        vector,
        verification.invalidMessage
          ? `${reason}: ${verification.invalidMessage}`
          : reason,
      );
    }
  } catch (error) {
    return rejected(
      vector,
      error instanceof Error ? error.message : String(error),
    );
  }
  return { id: vector.id, outcome: "accept" };
}

async function build(
  vector: ConformanceVector,
  input: Json,
): Promise<RunnerResult> {
  const c = input.batchClient as Json;
  if (c.operation !== "deposit") {
    return unsupported(
      vector,
      `@x402/svm builds a batch ${String(c.operation)} only from its own client channel storage`,
    );
  }
  const requirements = c.requirements as PaymentRequirements;
  const signer = await createKeyPairSignerFromBytes(
    new Uint8Array(c.secretKey as number[]),
  );
  const client = new x402Client().register(
    requirements.network as Network,
    new BatchClient(signer, {
      depositAmount: String(c.depositAmount),
      discoverChannels: false,
      rpcUrl: rpcUrl(input),
    }),
  );
  try {
    const payment = await client.createPaymentPayload({
      accepts: [requirements],
      resource: { url: "https://conformance.invalid/resource" },
      x402Version: 2,
    } as Parameters<typeof client.createPaymentPayload>[0]);
    return {
      id: vector.id,
      outcome: "accept",
      x402PaymentHeader: encodePaymentSignatureHeader(payment),
    } as RunnerResult;
  } catch (error) {
    return rejected(
      vector,
      error instanceof Error ? error.message : String(error),
    );
  }
}

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input as unknown as Json;
  if (vector.mode === "canonical-bytes") return canonical(vector, input);
  if (vector.mode === "verify-transaction") return verify(vector, input);
  return build(vector, input);
}
