// `x402-upto` vectors for the TypeScript testee. The testee passes the
// vector's input to the SDK unchanged (harness/AGENTS.md).
//
//   build  -> pay-kit's client (`createPayKitClient().fetch`, which registers
//             the vendored `@x402/svm` UptoSvmScheme) answers a loopback 402
//             carrying the vector's upto offer; the testee captures the
//             PAYMENT-SIGNATURE header it retries with. The client computes
//             expiresAt from its clock, so the testee drives Date.now at the
//             vector's nowSeconds.
//   verify -> the vendored `@x402/svm` upto facilitator pay-kit's upto
//             adapter registers (adapters/x402-upto.ts), run through its
//             read-only `verify` preflight against requirements shaped like
//             the adapter's `#requirements` from the x402Server* route. The
//             adapter's own verifyOpen goes through `settle` (deposit), which
//             broadcasts the open, so it cannot run offline.
//   canonical bytes -> the voucher message through @solana/mpp's
//             encodeVoucherMessageBytes, which pay-kit's upto adapter signs.
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { caip2, toNetwork } from "@solana/pay-kit";
import { createPayKitClient } from "@solana/pay-kit/client";
import { encodeVoucherMessageBytes } from "@solana/mpp/server";
import { x402Facilitator } from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/facilitator/index.mjs";
import { decodePaymentSignatureHeader } from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/http/index.mjs";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
} from "../../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/types/index.mjs";
import { toFacilitatorSvmSigner } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/index.mjs";
import { UptoSvmScheme as UptoSvmFacilitator } from "../../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/upto/facilitator/index.mjs";
import type { ConformanceVector, RejectCode, RunnerResult } from "../schema";

function rpcUrlOf(vector: ConformanceVector): string {
  if (!vector.input.rpcUrl)
    throw new Error("driver did not inject input.rpcUrl");
  return vector.input.rpcUrl;
}

// Drive the SDK at the vector's clock (`honoursClock`): the upto client and
// facilitator read Date.now for expiresAt and the validity window.
async function atClock<T>(
  nowSeconds: number | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  if (nowSeconds === undefined) return fn();
  const realNow = Date.now;
  Date.now = () => nowSeconds * 1000;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

class Reject extends Error {
  constructor(
    message: string,
    readonly rejectCode: RejectCode | undefined,
  ) {
    super(message);
  }
}

// The facilitator's reason codes (scheme_upto_svm.md §7 plus its
// implementation codes) onto the shared vocabulary; an open-transaction
// failure is split by the verifier's message.
function codeFor(reason: string, message: string): RejectCode | undefined {
  const m = message.toLowerCase();
  switch (reason) {
    case "invalid_upto_svm_payload_unexpected_voucher":
      return "unexpected-voucher";
    case "invalid_upto_svm_payload_type":
      return "unexpected-type";
    case "invalid_upto_svm_channel_already_open":
      return "channel-already-open";
    case "invalid_upto_svm_payload_channel_lifetime_exceeded":
      return "channel-lifetime-exceeded";
    case "invalid_upto_svm_payload_expires_at_mismatch":
      return "expires-at-mismatch";
    case "invalid_upto_svm_payload_not_yet_active":
      return "not-yet-active";
    case "invalid_upto_svm_payload_expired":
      return "voucher-expired";
    case "invalid_upto_svm_payload_amount_mismatch":
      return "amount-mismatch";
    case "invalid_upto_svm_payload_deposit_not_ceiling":
      return "deposit-not-ceiling";
    case "invalid_upto_svm_payload_receiver_authorizer":
      return "receiver-authorizer-mismatch";
    case "invalid_upto_svm_payload_channel_id":
      return "channel-id-mismatch";
    case "invalid_upto_svm_payload_nonce":
    case "invalid_upto_svm_payload_payer_mismatch":
      return "open-binding-mismatch";
    case "unsupported_scheme":
    case "network_mismatch":
    case "facilitator_mismatch":
      return "accepted-mismatch";
    case "unsupported_transaction_version":
      return "unsupported-version";
    case "unsupported_payload_type":
    case "invalid_upto_svm_payload_amount":
    case "invalid_upto_svm_payload_channel_seed":
    case "invalid_upto_svm_payment_requirements":
      return "invalid-payload";
    case "invalid_upto_svm_payload_open_transaction":
      break;
    default:
      return undefined;
  }
  if (/unsupported_transaction_version|transaction version/.test(m))
    return "unsupported-version";
  if (/setcomputeunitprice .* exceeds/.test(m)) return "compute-price-over-cap";
  if (/setcomputeunitlimit .* exceeds/.test(m)) return "compute-limit-over-cap";
  if (
    /feepayer must not appear in (lighthouse|memo|computebudget) instruction accounts/.test(
      m,
    )
  ) {
    return "fee-payer-not-authority";
  }
  if (
    /address-lookup tables|missing signature|invalid signature|^verifyopentransaction: feepayer \S+ != expected/.test(
      m,
    )
  ) {
    return "invalid-payload";
  }
  if (
    /computebudget|setcomputeunit|no payment-channels open|unexpected instruction program|is not `open`|optional instructions|lighthouse instructions|required-signer|required signer|invoked program/.test(
      m,
    )
  ) {
    return "unexpected-instruction";
  }
  if (/memo/.test(m)) return "invalid-payload";
  if (/channel pda/.test(m)) return "channel-id-mismatch";
  return "open-binding-mismatch";
}

async function build(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  if (!input.x402Offer)
    throw new Error(
      "invalid payload: upto build vector missing input.x402Offer",
    );
  if (!input.signerSecretKey)
    throw new Error(
      "invalid payload: upto build vector missing input.signerSecretKey",
    );
  const signer = await createKeyPairSignerFromBytes(
    new Uint8Array(input.signerSecretKey),
  );
  let captured: string | undefined;
  const server = createServer((req, res) => {
    const paid = req.headers["payment-signature"] ?? req.headers["x-payment"];
    if (typeof paid === "string") {
      captured = paid;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    const paymentRequired = {
      accepts: [input.x402Offer],
      resource: { url: `http://${req.headers.host}${req.url ?? "/"}` },
      x402Version: 2,
    };
    res.writeHead(402, {
      "content-type": "application/json",
      "payment-required": Buffer.from(
        JSON.stringify(paymentRequired),
        "utf8",
      ).toString("base64"),
    });
    res.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address() as AddressInfo;
    // Permissions are the client's spending policy, not wire behaviour.
    const client = await createPayKitClient({
      accept: ["x402"],
      permissions: false,
      rpcUrl: rpcUrlOf(vector),
      signer,
    });
    let response: Response;
    try {
      response = await atClock(input.nowSeconds, () =>
        client.fetch(`http://127.0.0.1:${port}/resource`),
      );
    } catch (error) {
      // The build input is the challenge alone: a refusal is a refused
      // challenge, or no buildable transaction version.
      const message = error instanceof Error ? error.message : String(error);
      throw new Reject(
        message,
        /unsupported_transaction_version|transaction version/i.test(message)
          ? "unsupported-version"
          : "invalid-challenge",
      );
    }
    if (captured === undefined) {
      throw new Error(
        `invalid challenge: pay-kit client did not pay the 402 (final status ${response.status})`,
      );
    }
    return { id: vector.id, outcome: "accept", x402PaymentHeader: captured };
  } finally {
    server.close();
  }
}

async function verify(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  if (!input.x402PaymentHeader)
    throw new Error(
      "invalid payload: upto verify vector missing x402PaymentHeader",
    );
  if (
    !input.x402ServerFeePayerSecretKey ||
    input.x402ServerNetwork === undefined
  ) {
    throw new Error(
      "invalid payload: upto verify vector missing the server route",
    );
  }
  const operator = await createKeyPairSignerFromBytes(
    new Uint8Array(input.x402ServerFeePayerSecretKey),
  );
  if (
    input.x402ServerFeePayer !== undefined &&
    input.x402ServerFeePayer !== operator.address
  ) {
    throw new Error(
      "invalid payload: x402ServerFeePayer does not match its secret key",
    );
  }
  const network = caip2(
    toNetwork(input.x402ServerNetwork as Parameters<typeof toNetwork>[0]),
  ) as Network;
  const facilitator = new x402Facilitator().register(
    network,
    new UptoSvmFacilitator(
      toFacilitatorSvmSigner(operator, { defaultRpcUrl: rpcUrlOf(vector) }),
      {
        ...(input.x402ServerMaxChannelLifetimeSeconds !== undefined
          ? {
              maxChannelLifetimeSecs: input.x402ServerMaxChannelLifetimeSeconds,
            }
          : {}),
      },
    ),
  );
  // Same shape as pay-kit's `X402Upto#requirements` (adapters/x402-upto.ts),
  // with the route's withdraw delay, timeout and declared memo.
  const requirements: PaymentRequirements = {
    amount: input.x402ServerAmount!,
    asset: input.x402ServerCurrency!,
    extra: {
      feePayer: operator.address,
      receiverAuthorizer: input.x402ServerReceiverAuthorizer,
      tokenProgram: input.x402ServerTokenProgram,
      withdrawDelay: input.x402ServerWithdrawDelay,
      ...(input.x402ServerMemo !== undefined
        ? { memo: input.x402ServerMemo }
        : {}),
      ...(input.x402ServerTransactionVersions !== undefined
        ? { transactionVersions: input.x402ServerTransactionVersions }
        : {}),
    },
    maxTimeoutSeconds: input.x402ServerMaxTimeoutSeconds!,
    network,
    payTo: input.x402ServerRecipient!,
    scheme: "upto",
  };
  let payload: PaymentPayload;
  try {
    payload = decodePaymentSignatureHeader(input.x402PaymentHeader);
  } catch (error) {
    throw new Reject(
      `invalid payload: ${error instanceof Error ? error.message : String(error)}`,
      "invalid-payload",
    );
  }
  const verification = await atClock(input.nowSeconds, () =>
    facilitator.verify(payload, requirements),
  );
  if (!verification.isValid) {
    const reason = verification.invalidReason ?? "invalid_proof";
    const message = verification.invalidMessage ?? "";
    throw new Reject(
      message ? `${reason}: ${message}` : reason,
      codeFor(reason, message),
    );
  }
  return { id: vector.id, outcome: "accept" };
}

function canonical(vector: ConformanceVector): RunnerResult {
  const input = vector.input;
  if (input.x402UptoVoucher) {
    const v = input.x402UptoVoucher;
    let bytes: Uint8Array;
    try {
      bytes = encodeVoucherMessageBytes({
        channelId: v.channelId,
        cumulativeAmount: BigInt(v.cumulativeAmount),
        expiresAt: BigInt(v.expiresAt ?? 0),
      });
    } catch (error) {
      throw new Reject(
        `invalid payload: ${error instanceof Error ? error.message : String(error)}`,
        "invalid-payload",
      );
    }
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
  return {
    error:
      "unsupported-mode: @solana/pay-kit and the vendored @x402/svm expose no distribution-hash or channel-PDA helper",
    id: vector.id,
    outcome: "unsupported-mode",
  };
}

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  try {
    if (vector.mode === "canonical-bytes") return canonical(vector);
    if (vector.mode === "build-transaction") return await build(vector);
    return await verify(vector);
  } catch (error) {
    if (error instanceof Reject) {
      return {
        error: error.message,
        id: vector.id,
        outcome: "reject",
        ...(error.rejectCode ? { rejectCode: error.rejectCode } : {}),
      };
    }
    throw error;
  }
}
