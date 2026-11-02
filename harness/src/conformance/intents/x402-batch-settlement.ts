// `x402-batch-settlement` vectors for the TypeScript testee. pay-kit has no
// batch-settlement implementation, so the testee drives the vendored upstream
// `@x402/svm` batch-settlement mechanism (the tarball pay-kit bundles). The
// testee passes the vector's input to the SDK unchanged (harness/AGENTS.md):
//
// - canonical-bytes: the SDK's encoders (`encodeBatchAuthorizationMessage`,
//   `encodeCloseAuthorizationDigest`, `encodeBatchVoucherMessage`,
//   `deriveBatchChannelId`, `encodeReceiverBindingMemo`) and wire guards
//   (`isBatchPayload`, `isBatchFacilitatorPayload`, `isBatchRequirements`,
//   `isBatchPaymentPayloadEnvelope`, `isBatchSettlementResponse`,
//   `isBatchPaymentRequired`; a value the guard accepts is echoed in its JCS
//   form).
// - verify-transaction: the upstream facilitator (`BatchSvmScheme`) behind
//   `x402Facilitator`, on the route's `batchRequirements` and `input.rpcUrl`.
//   A verdict that rests on the resource server's store record
//   (`batchVerdictFromStore`, RULINGS B1) goes through the upstream resource
//   server instead: `x402ResourceServer.verifyPayment` with the server
//   `BatchSvmScheme`, its channel store seeded with `batchServerChannel`.
//   `batchCorrective` runs the client's `checkCorrectiveState`.
// - build-transaction: the upstream client scheme through `x402Client` for a
//   first `deposit`; `buildBatchVoucherPayload`, `buildBatchTopUpPayload` and
//   `buildBatchRefundPayload` for a channel the vector's client tracks.
import { createKeyPairSignerFromBytes, getBase58Encoder } from "@solana/kit";
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
import { x402ResourceServer } from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/server/index.mjs";
import {
  buildBatchRefundPayload,
  buildBatchTopUpPayload,
  buildBatchVoucherPayload,
  checkCorrectiveState,
  deriveBatchChannelId,
  encodeBatchAuthorizationMessage,
  encodeBatchVoucherMessage,
  encodeCloseAuthorizationDigest,
  encodeReceiverBindingMemo,
  isBatchFacilitatorPayload,
  isBatchPayload,
  isBatchPaymentPayloadEnvelope,
  isBatchPaymentRequired,
  isBatchRequirements,
  isBatchSettlementResponse,
  toFacilitatorSvmSigner,
  type BatchChannelConfig,
  type BatchTrackedChannel,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/index.mjs";
import { BatchSvmScheme as BatchClient } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/batch-settlement/client/index.mjs";
import { BatchSvmScheme as BatchFacilitator } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/batch-settlement/facilitator/index.mjs";
import {
  BatchSvmScheme as BatchServer,
  MemoryChannelStore,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/batch-settlement/server/index.mjs";

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
    const guard = WIRE_GUARDS[wire.shape ?? ""];
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
  const memo = input.batchReceiverBindingMemo as Json | undefined;
  if (memo) {
    return exactBytes(
      vector,
      new TextEncoder().encode(encodeReceiverBindingMemo(String(memo.receiverAuthorizer))),
    );
  }
  return unsupported(vector, "no batch canonical-bytes path for this input");
}

// The SDK's guard for each batch wire shape.
const WIRE_GUARDS: Record<string, ((value: unknown) => boolean) | undefined> = {
  payload: isBatchPayload,
  redemption: isBatchFacilitatorPayload,
  requirements: isBatchRequirements,
  paymentPayload: isBatchPaymentPayloadEnvelope,
  settlementResponse: isBatchSettlementResponse,
  paymentRequired: isBatchPaymentRequired,
};

// The voucher message and channel id, through the SDK's encoders (async: the
// channel id is a PDA derivation).
async function canonicalAsync(
  vector: ConformanceVector,
  input: Json,
): Promise<RunnerResult | undefined> {
  const vm = input.batchVoucherMessage as Json | undefined;
  if (vm) {
    try {
      return exactBytes(
        vector,
        encodeBatchVoucherMessage({
          channelId: String(vm.channelId),
          expiresAt: vm.expiresAt as number,
          maxClaimableAmount: vm.maxClaimableAmount as string,
        }),
      );
    } catch (error) {
      return invalidPayload(vector, error);
    }
  }
  const cid = input.batchChannelId as Json | undefined;
  if (cid) {
    try {
      const id = await deriveBatchChannelId(
        cid.channelConfig as BatchChannelConfig,
        String(cid.feePayer),
      );
      return exactBytes(vector, getBase58Encoder().encode(id) as Uint8Array);
    } catch (error) {
      return invalidPayload(vector, error);
    }
  }
  return undefined;
}

function invalidPayload(vector: ConformanceVector, error: unknown): RunnerResult {
  return {
    error: `invalid payload: ${error instanceof Error ? error.message : String(error)}`,
    id: vector.id,
    outcome: "reject",
    rejectCode: "invalid-payload",
  };
}

async function verify(
  vector: ConformanceVector,
  input: Json,
): Promise<RunnerResult> {
  if (input.batchCorrective) return corrective(vector, input.batchCorrective as Json);
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
  // The facilitator's own accepted set ("The facilitator enforces its own
  // accepted set"); absent keeps the default [0, 1].
  const versions = server.transactionVersions as Array<0 | 1> | undefined;
  const facilitator = new x402Facilitator().register(
    requirements.network as Network,
    new BatchFacilitator(signer, versions !== undefined ? { transactionVersions: versions } : {}),
  );
  let payload: PaymentPayload;
  try {
    payload = decodePaymentSignatureHeader(String(input.x402PaymentHeader));
  } catch (error) {
    return rejected(vector, `invalid payload: ${String(error)}`);
  }
  try {
    // A verdict resting on the server's store record goes through the
    // upstream resource server, which owns that record (RULINGS B1).
    const verification =
      input.batchVerdictFromStore === true
        ? await serverVerify(input, facilitator, payload, requirements)
        : await facilitator.verify(payload, requirements);
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
  const requirements = c.requirements as PaymentRequirements;
  const signer = await createKeyPairSignerFromBytes(
    new Uint8Array(c.secretKey as number[]),
  );
  if (c.operation !== "deposit") return buildTracked(vector, input, c, signer);
  // The highest version the client's signer signs, through the upstream
  // client's own option, as @solana/pay-kit maps its maxTransactionVersion
  // (typescript/packages/pay-kit/src/client/index.ts).
  const maxVersion = c.maxTransactionVersion as 0 | 1 | undefined;
  const client = new x402Client().register(
    requirements.network as Network,
    new BatchClient(signer, {
      depositAmount: String(c.depositAmount),
      discoverChannels: false,
      rpcUrl: rpcUrl(input),
      ...(maxVersion !== undefined
        ? { transactionVersions: maxVersion === 0 ? [0] : [0, 1] }
        : {}),
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

// The upstream resource server's verify with the vector's store record: the
// server scheme's hooks run against the seeded channel store, then (when they
// do not decide) the facilitator.
async function serverVerify(
  input: Json,
  facilitator: InstanceType<typeof x402Facilitator>,
  payload: PaymentPayload,
  requirements: PaymentRequirements,
): Promise<{ isValid: boolean; invalidReason?: string; invalidMessage?: string }> {
  const store = new MemoryChannelStore();
  const record = input.batchServerChannel as Json | undefined;
  if (record) await store.put(await storedChannel(record, payload, requirements));
  const scheme = new BatchServer({ store });
  const client = {
    getSupported: async () => facilitator.getSupported(),
    settle: (p: PaymentPayload, r: PaymentRequirements) => facilitator.settle(p, r),
    verify: (p: PaymentPayload, r: PaymentRequirements) => facilitator.verify(p, r),
  };
  const resourceServer = new x402ResourceServer(client as never).register(
    requirements.network as Network,
    scheme,
  );
  return resourceServer.verifyPayment(payload, requirements);
}

// The server's record for the channel as `batchServerChannel` describes it
// (channel id, payer, authorizer, openSlot, deposit, charged and settled
// watermarks, a close-pending mark), with the route's terms. The record
// names the channel by its PDA; the salt seed comes from the payload's
// config and must derive that PDA, so a record and payload for different
// channels fail here rather than pass.
async function storedChannel(
  record: Json,
  payment: PaymentPayload,
  requirements: PaymentRequirements,
) {
  const extra = requirements.extra as Json;
  const raw = payment.payload as Json;
  const payloadConfig = raw.channelConfig as BatchChannelConfig;
  const channelConfig: BatchChannelConfig = {
    ...payloadConfig,
    openSlot: Number(record.openSlot),
    payer: String(record.payer),
    payerAuthorizer: String(record.payerAuthorizer),
  };
  const channelId = String(record.channelId);
  if ((await deriveBatchChannelId(channelConfig, String(extra.feePayer))) !== channelId) {
    throw new Error("invalid payload: batchServerChannel names another channel than the payload");
  }
  const charged = BigInt(String(record.chargedCumulativeAmount));
  const settled = BigInt(String(record.settled ?? "0"));
  const closeRequestedAt =
    typeof record.closeRequestedAt === "number" ? record.closeRequestedAt : undefined;
  return {
    channelConfig,
    channelId,
    chargedCumulativeAmount: charged,
    closeRequestedAt,
    deposit: BigInt(String(record.deposit)),
    feePayer: String(extra.feePayer),
    mint: requirements.asset,
    onchainSyncedAt: Date.now(),
    openSlot: BigInt(channelConfig.openSlot),
    payer: channelConfig.payer,
    payerAuthorizer: channelConfig.payerAuthorizer,
    payoutWatermark: settled,
    receiver: requirements.payTo,
    receiverAuthorizer: String(extra.receiverAuthorizer),
    salt: BigInt(channelConfig.salt),
    settled,
    signedMaxClaimable: charged,
    status: closeRequestedAt !== undefined ? ("closing" as const) : ("open" as const),
    tokenProgram: String(extra.tokenProgram),
    withdrawDelay: channelConfig.withdrawDelay,
  };
}

// A corrective 402 through the client's single-shot check: the channel id
// is derived from the client's own config, never read from the snapshot.
async function corrective(vector: ConformanceVector, c: Json): Promise<RunnerResult> {
  const channel = c.channel as Json;
  const accept = c.requirements as PaymentRequirements;
  try {
    const channelConfig = channel.channelConfig as BatchChannelConfig;
    await checkCorrectiveState({
      accept,
      channelConfig,
      channelId: await deriveBatchChannelId(channelConfig, String(accept.extra?.feePayer)),
      deposit: BigInt(String(channel.deposit)),
    });
  } catch (error) {
    return rejected(vector, error instanceof Error ? error.message : String(error));
  }
  return { id: vector.id, outcome: "accept" };
}

// A voucher, top-up or refund for the channel the vector's client tracks,
// through the SDK's single-shot builders.
async function buildTracked(
  vector: ConformanceVector,
  input: Json,
  c: Json,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<RunnerResult> {
  const requirements = c.requirements as PaymentRequirements;
  const channel = c.channel as BatchTrackedChannel;
  const maxVersion = c.maxTransactionVersion as 0 | 1 | undefined;
  const common = {
    channel,
    requirements,
    rpcUrl: rpcUrl(input),
    signer,
    ...(typeof c.blockhash === "string"
      ? { blockhash: { blockhash: c.blockhash, lastValidBlockHeight: 0n } }
      : {}),
    ...(maxVersion !== undefined
      ? { transactionVersions: maxVersion === 0 ? [0] : [0, 1] }
      : {}),
  };
  try {
    let payload: unknown;
    switch (c.operation) {
      case "voucher":
        payload = await buildBatchVoucherPayload(common);
        break;
      case "topUp":
        payload = await buildBatchTopUpPayload({
          ...common,
          depositAmount: String(c.depositAmount),
        });
        break;
      case "refund":
        payload = await buildBatchRefundPayload(common);
        break;
      default:
        return unsupported(vector, `no batch build path for operation ${String(c.operation)}`);
    }
    return {
      id: vector.id,
      outcome: "accept",
      x402PaymentHeader: encodePaymentSignatureHeader({
        accepted: requirements,
        payload,
        resource: { url: "https://conformance.invalid/resource" },
        x402Version: 2,
      } as PaymentPayload),
    } as RunnerResult;
  } catch (error) {
    return rejected(vector, error instanceof Error ? error.message : String(error));
  }
}

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input as unknown as Json;
  if (vector.mode === "canonical-bytes") {
    return (await canonicalAsync(vector, input)) ?? canonical(vector, input);
  }
  if (vector.mode === "verify-transaction") return verify(vector, input);
  return build(vector, input);
}
