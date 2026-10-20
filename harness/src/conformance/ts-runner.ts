// TypeScript REFERENCE conformance runner.
//
// Reads a single conformance vector as JSON on stdin, drives the real
// @solana/mpp (+ JCS reference) TS implementation, and emits a
// RunnerResult as JSON on stdout. The driver (test/conformance.test.ts)
// spawns one runner process per vector and asserts the runner output
// against the vector's `expect` block.
//
// This is the language-complete contract every other SDK's conformance
// runner must satisfy: same stdin vector shape, same stdout result shape.
// Only the TS runner ships in this change; other languages are a tracked
// follow-up (see harness/vectors/README.md).

import { createHmac } from "node:crypto";
import { createKeyPairSignerFromBytes, getBase58Decoder } from "@solana/kit";
import { session as sessionMethod } from "@solana/mpp";
import {
  buildChargeTransaction,
  sessionAuthenticationMessage,
  voucherMessageBytes,
} from "@solana/mpp/client";
import {
  encodeVoucherMessageBytes,
  verifyChargeTransaction,
  verifyVoucherForChannel,
} from "@solana/mpp/server";
import { decodeTransactionShape } from "./decode";
import { base64UrlFromUtf8, canonicalizeJson } from "./jcs";
import { classifyReject } from "./reject";
import {
  buildPaymentHeader,
  decodeEnvelopeShape,
  echoExtensions,
  generatePaymentIdentifierId,
  requiresPaymentIdentifier,
  verifyPaymentHeader,
  withPaymentIdentifierId,
  type PaymentExtensions,
} from "./x402";
import type {
  ConformanceVector,
  RunnerResult,
  VectorChargeRequest,
} from "./schema";

// Pass the decoded challenge request to the SDK verbatim. The runner never
// applies field precedence, fills defaults or resolves token programs:
// chain state comes from the fixture RPC (input.rpcUrl), so whatever the
// SDK does with an omitted field is what the vector judges
// (harness/expectations/RULINGS.md C2-C4).
function sdkRequest(
  request: VectorChargeRequest,
): Parameters<typeof buildChargeTransaction>[0]["request"] {
  return request as unknown as Parameters<typeof buildChargeTransaction>[0]["request"];
}

function rpcUrlOf(vector: ConformanceVector): string {
  if (!vector.input.rpcUrl) throw new Error("driver did not inject input.rpcUrl");
  return vector.input.rpcUrl;
}

async function buildTransactionForVector(
  vector: ConformanceVector,
): Promise<string> {
  const input = vector.input;
  if (!input.request) {
    throw new Error("build/verify vector is missing input.request");
  }
  if (!input.signerSecretKey) {
    throw new Error("build/verify vector is missing input.signerSecretKey");
  }
  const signer = await createKeyPairSignerFromBytes(
    new Uint8Array(input.signerSecretKey),
  );
  const request = sdkRequest(input.request);
  return await buildChargeTransaction({
    ...(input.request.computeUnitLimit !== undefined
      ? { computeUnitLimit: input.request.computeUnitLimit }
      : {}),
    ...(input.request.computeUnitPrice !== undefined
      ? { computeUnitPrice: BigInt(input.request.computeUnitPrice) }
      : {}),
    request,
    rpcUrl: rpcUrlOf(vector),
    signer,
  });
}

function shapeFromDecoded(transactionBase64: string): RunnerResult["transactionShape"] {
  const decoded = decodeTransactionShape(transactionBase64);
  return {
    feePayer: decoded.feePayer,
    forbiddenPrograms: [],
    ...(decoded.computeUnitLimit !== undefined
      ? { maxComputeUnitLimit: decoded.computeUnitLimit }
      : {}),
    ...(decoded.computeUnitPrice !== undefined
      ? { maxComputeUnitPrice: decoded.computeUnitPrice }
      : {}),
    memo: decoded.memos,
    transfers: decoded.transfers.map((t) => ({
      amount: t.amount,
      destination: t.destination,
      kind: t.kind,
      ...(t.decimals !== undefined ? { decimals: t.decimals } : {}),
      ...(t.mint ? { mint: t.mint } : {}),
      ...(t.tokenProgram ? { tokenProgram: t.tokenProgram } : {}),
    })),
  };
}

// x402-exact: the oracle is the decoded envelope shape, not a tx shape.
// build -> wrap the selected offer into a v1/v2 payment header, decode the
// shape. verify -> run the envelope-level verify against the server route.
function runX402Vector(vector: ConformanceVector): RunnerResult {
  const input = vector.input;
  if (vector.mode === "build-transaction") {
    if (!input.x402Offer) {
      throw new Error("invalid payload: x402 build vector missing input.x402Offer");
    }
    const version = input.x402Version ?? 2;
    // Deterministic, RPC-free: the conformance oracle is the envelope, so
    // the signed-transaction proof is a pinned placeholder. A real SDK
    // signs a Solana tx here; the harness matrix asserts that path.
    const transaction =
      input.x402PinnedTransaction ?? "AA==";

    // Echo-and-append (x402 v2 §5.1.2): take the server's advertised
    // extensions, preserve unknown keys verbatim, and fill the required
    // client-side payment-identifier.info.id when the server requires it.
    // When the server advertised nothing, echoExtensions returns undefined
    // and the build omits the `extensions` object entirely (no empty {}).
    let extensions: PaymentExtensions | undefined = echoExtensions(
      input.x402AdvertisedExtensions as PaymentExtensions | undefined,
    );
    if (requiresPaymentIdentifier(extensions)) {
      const id =
        input.x402PaymentIdentifierId ?? generatePaymentIdentifierId();
      extensions = withPaymentIdentifierId(extensions, id);
    }
    const header = buildPaymentHeader(
      version,
      input.x402Offer,
      transaction,
      extensions,
    );
    return {
      id: vector.id,
      outcome: "accept",
      x402EnvelopeShape: decodeEnvelopeShape(header),
    };
  }

  // verify-transaction (x402).
  if (!input.x402PaymentHeader) {
    throw new Error(
      "invalid payload: x402 verify vector missing input.x402PaymentHeader",
    );
  }
  if (
    input.x402ServerNetwork === undefined ||
    input.x402ServerRecipient === undefined ||
    input.x402ServerCurrency === undefined ||
    input.x402ServerAmount === undefined
  ) {
    throw new Error("invalid payload: x402 verify vector missing server route");
  }
  verifyPaymentHeader(input.x402PaymentHeader, {
    network: input.x402ServerNetwork,
    recipient: input.x402ServerRecipient,
    currency: input.x402ServerCurrency,
    amount: input.x402ServerAmount,
    ...(input.x402ServerRequiresPaymentIdentifier !== undefined
      ? {
          requiresPaymentIdentifier:
            input.x402ServerRequiresPaymentIdentifier,
        }
      : {}),
  });
  return {
    id: vector.id,
    outcome: "accept",
    x402EnvelopeShape: decodeEnvelopeShape(input.x402PaymentHeader),
  };
}

// Session voucher verify: sign one voucher with the vector key and drive the
// production verifier against a fresh channel at the pinned clock.
async function runSessionVoucherVerify(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input.sessionVoucherVerify!;
  if (!vector.input.signerSecretKey) throw new Error("vector is missing signerSecretKey");
  const signer = await createKeyPairSignerFromBytes(Uint8Array.from(vector.input.signerSecretKey));
  const message = encodeVoucherMessageBytes({
    channelId: input.channelId,
    cumulativeAmount: BigInt(input.cumulativeAmount),
    expiresAt: BigInt(input.expiresAt),
  });
  const [signatures] = await signer.signMessages([{ content: message, signatures: {} }]);
  const signature = signatures?.[signer.address];
  if (!signature) throw new Error("signer did not produce a signature");
  const result = await verifyVoucherForChannel({
    deposit: BigInt(input.deposit),
    nowSeconds: BigInt(input.nowSeconds),
    settlementWindow: BigInt(input.settlementWindowSeconds),
    signed: {
      signature: getBase58Decoder().decode(signature),
      signatureType: "ed25519",
      signer: signer.address,
      voucher: {
        channelId: input.channelId,
        cumulativeAmount: input.cumulativeAmount,
        expiresAt: input.expiresAt,
      },
    },
    state: {
      authorizedSigner: signer.address,
      channelId: input.channelId,
      committedDeliveries: [],
      cumulative: 0n,
      deposit: BigInt(input.deposit),
      nextDeliverySequence: 0n,
      payer: signer.address,
      pendingDeliveries: [],
      processedUses: [],
      rentPayer: signer.address,
      sealed: false,
      settledOnChain: 0n,
      spentAmount: 0n,
    },
  });
  if (result.status === "accepted") return { id: vector.id, outcome: "accept" };
  if (result.status === "replayed") {
    return { error: "unexpected replay", id: vector.id, outcome: "reject" };
  }
  const rejectCode =
    result.reason === "expired"
      ? ("voucher-expired" as const)
      : result.reason === "expires-within-settlement-window"
        ? ("voucher-expires-before-settlement" as const)
        : undefined;
  return {
    error: `${result.reason}: ${result.detail}`,
    id: vector.id,
    outcome: "reject",
    ...(rejectCode ? { rejectCode } : {}),
  };
}

async function runVector(vector: ConformanceVector): Promise<RunnerResult> {
  if (vector.intent === "x402-exact") {
    return runX402Vector(vector);
  }
  if (vector.intent === "session" && vector.mode === "verify-transaction") {
    if (!vector.input.sessionVoucherVerify) {
      return { error: "unsupported-mode: session verify input", id: vector.id, outcome: "unsupported-mode" };
    }
    return runSessionVoucherVerify(vector);
  }
  if (vector.mode === "canonical-bytes") {
    const exactBytes: NonNullable<RunnerResult["exactBytes"]> = {};
    if (vector.input.value !== undefined) {
      const canonicalJson = canonicalizeJson(vector.input.value);
      exactBytes.canonicalJson = canonicalJson;
      exactBytes.base64Url = base64UrlFromUtf8(canonicalJson);
    }
    if (vector.input.encodeBase64Url) {
      const enc = vector.input.encodeBase64Url;
      if (enc.hexBytes) {
        const bytes = Buffer.from(enc.hexBytes, "hex");
        exactBytes.bytes = Array.from(bytes);
        exactBytes.base64Url = bytes.toString("base64url");
      } else if (enc.utf8) {
        exactBytes.base64Url = base64UrlFromUtf8(enc.utf8);
      }
    }
    if (vector.input.voucherPreimage) {
      // The 50-byte session voucher preimage, computed by the production
      // SDK packer (voucherMessageBytes) so a byte mismatch is caught
      // cross-SDK rather than behind a live channel. Mirrors the Go and
      // Python runners.
      const vp = vector.input.voucherPreimage;
      // An omitted expiresAt exercises the SDK's never-expires default
      // (encoded verbatim as 0), the exact path the session signer uses.
      const preimage = Buffer.from(
        voucherMessageBytes({
          channelId: vp.channelId,
          cumulativeAmount: vp.cumulativeAmount,
          expiresAt: vp.expiresAt ?? 0,
        }),
      );
      exactBytes.bytes = Array.from(preimage);
      exactBytes.base64Url = preimage.toString("base64url");
    }
    if (vector.input.sessionAuthenticationMessage) {
      // Drive the PRODUCTION session-authentication message builder so a
      // domain/field/ordering drift in the SDK is caught byte-for-byte,
      // never a local re-implementation of the preimage.
      const p = vector.input.sessionAuthenticationMessage;
      const message = Buffer.from(
        sessionAuthenticationMessage({
          challengeId: p.challengeId,
          channelId: p.channelId,
          payer: p.payer,
        }),
      );
      exactBytes.canonicalJson = message.toString("utf8");
      exactBytes.base64Url = message.toString("base64url");
    }
    if (vector.input.sessionWire) {
      // Round-trip the session wire shape through the PRODUCTION schema:
      // parse with the shared zod contract (@solana/mpp Methods.session),
      // re-encode the parsed value, and JCS-canonicalize. A field the SDK
      // renamed, dropped, or retyped either fails the parse (reject) or
      // diverges from the frozen canonical bytes.
      const sw = vector.input.sessionWire;
      let decoded: unknown;
      try {
        decoded =
          sw.shape === "request"
            ? sessionMethod.schema.request.parse(sw.value)
            : sessionMethod.schema.credential.payload.parse(sw.value);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`invalid session payload: ${detail}`);
      }
      const canonicalJson = canonicalizeJson(decoded);
      exactBytes.canonicalJson = canonicalJson;
      exactBytes.base64Url = base64UrlFromUtf8(canonicalJson);
    }
    if (vector.input.challengeId) {
      const c = vector.input.challengeId;
      // base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
      // digest|opaque)); absent optionals join as empty strings. Mirrors
      // rust compute_challenge_id (protocol/core/challenge.rs).
      const hmacInput = [
        c.realm,
        c.method,
        c.intent,
        c.request,
        c.expires ?? "",
        c.digest ?? "",
        c.opaque ?? "",
      ].join("|");
      const mac = createHmac("sha256", c.secretKey).update(hmacInput).digest();
      exactBytes.base64Url = mac.toString("base64url");
    }
    return { exactBytes, id: vector.id, outcome: "accept" };
  }

  if (vector.mode === "build-transaction") {
    const tx = await buildTransactionForVector(vector);
    return {
      id: vector.id,
      outcome: "accept",
      transactionShape: shapeFromDecoded(tx),
    };
  }

  // verify-transaction: use a provided tx or build one, then verify.
  const tx = vector.input.transaction ?? (await buildTransactionForVector(vector));
  if (!vector.input.request) {
    throw new Error("verify vector is missing input.request");
  }
  await verifyChargeTransaction(tx, sdkRequest(vector.input.request));
  return {
    id: vector.id,
    outcome: "accept",
    transactionShape: shapeFromDecoded(tx),
  };
}

async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    throw new Error("ts-runner received empty stdin");
  }
  const vector = JSON.parse(raw) as ConformanceVector;

  let result: RunnerResult;
  try {
    result = await runVector(vector);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    result = {
      error: message,
      id: vector.id,
      outcome: "reject",
      rejectCode: classifyReject(message),
    };
  }
  process.stdout.write(JSON.stringify(result) + "\n");
}

void main();
