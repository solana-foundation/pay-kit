// TypeScript REFERENCE conformance runner.
//
// Reads a single conformance vector as JSON on stdin, drives the real
// @solana/mpp (+ JCS reference) TS implementation, and emits a
// RunnerResult as JSON on stdout, or with `--serve` speaks testee ABI v2
// (one long-lived process, newline JSON; harness/README.md). The driver,
// `pkc run` (rust/crates/conformance), asserts every result.
//
// This is the language-complete contract every other SDK's conformance
// runner must satisfy: same stdin vector shape, same stdout result shape.
// Only the TS runner ships in this change; other languages are a tracked
// follow-up (see harness/vectors/README.md).

import { createHmac } from "node:crypto";
import { run as runBatch } from "./intents/x402-batch-settlement";
import { run as runSubscription } from "./intents/subscription";
import { run as runUpto } from "./intents/x402-upto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createKeyPairSignerFromBytes, getBase58Decoder } from "@solana/kit";
import { caip2, readPaymentIdentifier, toNetwork, verifyX402ExactCredential } from "@solana/pay-kit";
import { createPayKitClient } from "@solana/pay-kit/client";
import { charge as chargeMethod, session as sessionMethod } from "@solana/mpp";
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
import { decodeEnvelopeShape } from "./x402";
// The vendored x402 SDK that pay-kit is built on. pay-kit bundles it into
// its dist without re-exporting the facilitator, so the runner loads the
// same packages through the pay-kit workspace package that depends on them.
import { x402Facilitator } from "../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/facilitator/index.mjs";
import { decodePaymentSignatureHeader } from "../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/http/index.mjs";
import { PaymentRequirementsV2Schema } from "../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/schemas/index.mjs";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
} from "../../../typescript/packages/pay-kit/node_modules/@x402/core/dist/esm/types/index.mjs";
import { toFacilitatorSvmSigner } from "../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/index.mjs";
import { ExactSvmScheme as ExactSvmFacilitator } from "../../../typescript/packages/pay-kit/node_modules/@x402/svm/dist/esm/exact/facilitator/index.mjs";
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

// ── x402-exact ─────────────────────────────────────────────────────────
//
// The TypeScript x402 SDK is @solana/pay-kit, built on the vendored
// @x402/core + @x402/svm. The oracle is the decoded envelope shape, but the
// envelope comes out of (build) or goes through (verify) the real SDK:
//
//   build  -> pay-kit's client (`createPayKitClient().fetch`) answers a
//             loopback 402 carrying the vector's offer and advertised
//             extensions. It reads the mint over input.rpcUrl, builds and
//             signs a real exact transfer, and the runner captures the
//             payment header it retries with.
//   verify -> the exact facilitator pay-kit's x402 adapter wires
//             (adapters/x402.ts: `new x402Facilitator().register(network,
//             new ExactSvmScheme(toFacilitatorSvmSigner(operator)))`), run
//             on the vector's real transaction against requirements shaped
//             like the adapter's `requirementsFor`. A route that requires a
//             payment-identifier first runs pay-kit's `readPaymentIdentifier`,
//             the check the adapter applies to a `paymentIdentifier:
//             'required'` gate before any chain work (a failure is HTTP 400).

const X402_V1_UNSUPPORTED =
  "unsupported-mode: @solana/pay-kit speaks x402 v2 only (its client answers only the PAYMENT-REQUIRED header and its server registers only the v2 exact facilitator)";

// The 402 a server would send for the vector's offer. v1 challenges travel
// in the response body; v2 in the base64 PAYMENT-REQUIRED header.
function challengeResponse(
  input: ConformanceVector["input"],
  resourceUrl: string,
): { headers: Record<string, string>; body: string } {
  const offer = input.x402Offer!;
  if ((input.x402Version ?? 2) === 1) {
    return {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ x402Version: 1, error: "payment required", accepts: [offer] }),
    };
  }
  const paymentRequired = {
    x402Version: 2,
    resource: { url: resourceUrl },
    accepts: [offer],
    ...(input.x402AdvertisedExtensions !== undefined
      ? { extensions: input.x402AdvertisedExtensions }
      : {}),
  };
  return {
    headers: {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(paymentRequired), "utf8").toString("base64"),
    },
    body: "{}",
  };
}

async function buildX402Vector(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  if (!input.x402Offer) {
    throw new Error("invalid payload: x402 build vector missing input.x402Offer");
  }
  if (!input.signerSecretKey) {
    throw new Error("invalid payload: x402 build vector missing input.signerSecretKey");
  }
  if (input.x402PaymentIdentifierId !== undefined) {
    return {
      error:
        "unsupported-mode: @solana/pay-kit generates the payment-identifier id itself and has no option to supply a caller-chosen id",
      id: vector.id,
      outcome: "unsupported-mode",
    };
  }
  if (input.signerMaxTransactionVersion !== undefined) {
    return { error: SIGNER_VERSION_UNSUPPORTED, id: vector.id, outcome: "unsupported-mode" };
  }
  const signer = await createKeyPairSignerFromBytes(new Uint8Array(input.signerSecretKey));
  let captured: string | undefined;
  const server = createServer((req, res) => {
    const paid = req.headers["payment-signature"] ?? req.headers["x-payment"];
    if (typeof paid === "string") {
      captured = paid;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    const challenge = challengeResponse(input, `http://${req.headers.host}${req.url ?? "/"}`);
    res.writeHead(402, challenge.headers);
    res.end(challenge.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address() as AddressInfo;
    // Permissions are the client's spending policy, not wire behaviour; the
    // vector judges the payment the SDK builds, so allow every payment.
    const client = await createPayKitClient({
      accept: ["x402"],
      permissions: false,
      rpcUrl: rpcUrlOf(vector),
      signer,
    });
    const response = await client.fetch(`http://127.0.0.1:${port}/resource`);
    if (captured === undefined) {
      if ((input.x402Version ?? 2) === 1) {
        return { error: X402_V1_UNSUPPORTED, id: vector.id, outcome: "unsupported-mode" };
      }
      throw new Error(`pay-kit client did not pay the 402 (final status ${response.status})`);
    }
    return {
      id: vector.id,
      outcome: "accept",
      x402EnvelopeShape: decodeEnvelopeShape(captured),
      // The built header, so pkc can verify it with the Rust kit.
      x402PaymentHeader: captured,
    };
  } finally {
    server.close();
  }
}

type X402VerifyInput = ConformanceVector["input"];

// Transaction-version knobs the TypeScript SDKs do not expose. The runner
// cannot express them, so it reports unsupported-mode instead of guessing.
const SIGNER_VERSION_UNSUPPORTED =
  "unsupported-mode: neither @solana/mpp buildChargeTransaction nor the @solana/pay-kit x402 client takes a highest signable transaction version (input.signerMaxTransactionVersion)";
const SPONSOR_VERSIONS_UNSUPPORTED =
  "unsupported-mode: the vendored @x402/svm exact facilitator (x402 @03b3919b, before x402-foundation/x402 PR 3474) has no accepted transaction-version set to configure (input.x402ServerTransactionVersions other than [0])";

function sponsorVersionsExpressible(versions: ConformanceVector["input"]["x402ServerTransactionVersions"]): boolean {
  return versions === undefined || (versions.length === 1 && versions[0] === 0);
}

async function verifyX402Vector(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input as X402VerifyInput;
  if (!sponsorVersionsExpressible(vector.input.x402ServerTransactionVersions)) {
    return { error: SPONSOR_VERSIONS_UNSUPPORTED, id: vector.id, outcome: "unsupported-mode" };
  }
  if (!input.x402PaymentHeader) {
    throw new Error("invalid payload: x402 verify vector missing input.x402PaymentHeader");
  }
  if (
    input.x402ServerNetwork === undefined ||
    input.x402ServerRecipient === undefined ||
    input.x402ServerCurrency === undefined ||
    input.x402ServerAmount === undefined ||
    input.x402ServerFeePayerSecretKey === undefined
  ) {
    throw new Error("invalid payload: x402 verify vector missing server route");
  }
  const operator = await createKeyPairSignerFromBytes(
    new Uint8Array(input.x402ServerFeePayerSecretKey),
  );
  if (input.x402ServerFeePayer !== undefined && input.x402ServerFeePayer !== operator.address) {
    throw new Error("invalid payload: x402ServerFeePayer does not match its secret key");
  }
  // The route's network through pay-kit's own slug -> CAIP-2 mapping.
  const network = caip2(
    toNetwork(input.x402ServerNetwork as Parameters<typeof toNetwork>[0]),
  ) as Network;
  // The facilitator signer pay-kit builds, minus simulation: the vectors run
  // without a validator, so verification is the SDK's pre-broadcast checks
  // (envelope, signatures, instruction layout, transfer, memo).
  const facilitatorSigner = {
    ...toFacilitatorSvmSigner(operator, { defaultRpcUrl: rpcUrlOf(vector) }),
    simulateTransaction: async (): Promise<void> => {},
  };
  const facilitator = new x402Facilitator().register(
    network,
    new ExactSvmFacilitator(facilitatorSigner, undefined, {}),
  );
  // Same shape as pay-kit's `requirementsFor` (adapters/x402.ts).
  const requirements: PaymentRequirements = {
    amount: input.x402ServerAmount,
    asset: input.x402ServerCurrency,
    // The route's extra.memo, which the verifier enforces (§3.1).
    extra: {
      feePayer: operator.address,
      ...(input.x402ServerMemo !== undefined ? { memo: input.x402ServerMemo } : {}),
    },
    maxTimeoutSeconds: 300,
    network,
    payTo: input.x402ServerRecipient,
    scheme: "exact",
  };

  let payload: PaymentPayload;
  try {
    payload = decodePaymentSignatureHeader(input.x402PaymentHeader);
  } catch (error) {
    throw new Error(`invalid payload: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (input.x402ServerRequiresPaymentIdentifier) {
    readPaymentIdentifier(payload.extensions, "required");
  }
  // pay-kit's own checks ahead of the facilitator, as its x402 adapter runs
  // them: `accepted` bound to the route, fee payer out of every instruction.
  // v1 envelopes carry no `accepted`; the facilitator refuses them below.
  if (payload.x402Version === 2) {
    verifyX402ExactCredential(payload, requirements);
  }
  let verification: Awaited<ReturnType<typeof facilitator.verify>>;
  try {
    verification = await facilitator.verify(payload, requirements);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/no facilitator registered for x402 version: 1$/i.test(message)) {
      return { error: X402_V1_UNSUPPORTED, id: vector.id, outcome: "unsupported-mode" };
    }
    throw error;
  }
  if (!verification.isValid) {
    const reason = verification.invalidReason ?? "invalid_proof";
    throw new Error(
      verification.invalidMessage ? `${reason}: ${verification.invalidMessage}` : reason,
    );
  }
  return {
    id: vector.id,
    outcome: "accept",
    x402EnvelopeShape: decodeEnvelopeShape(input.x402PaymentHeader),
  };
}

function runX402Vector(vector: ConformanceVector): Promise<RunnerResult> {
  return vector.mode === "build-transaction" ? buildX402Vector(vector) : verifyX402Vector(vector);
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
  if (vector.intent === "x402-upto") return runUpto(vector);
  if (vector.intent === "x402-batch-settlement") return runBatch(vector);
  if (vector.intent === "subscription") return runSubscription(vector);
  if (vector.intent === "x402-exact" && vector.mode !== "canonical-bytes") {
    return runX402Vector(vector);
  }
  if (vector.mode === "build-transaction" && vector.input.signerMaxTransactionVersion !== undefined) {
    return { error: SIGNER_VERSION_UNSUPPORTED, id: vector.id, outcome: "unsupported-mode" };
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
    if (vector.input.chargeWire) {
      // Round-trip a charge request through the PRODUCTION schema
      // (@solana/mpp Methods.charge request), as sessionWire does.
      let decoded: unknown;
      try {
        decoded = chargeMethod.schema.request.parse(vector.input.chargeWire.value);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`invalid payload: charge request: ${detail}`);
      }
      const canonicalJson = canonicalizeJson(decoded);
      exactBytes.canonicalJson = canonicalJson;
      exactBytes.base64Url = base64UrlFromUtf8(canonicalJson);
    }
    if (vector.input.x402Wire) {
      // One accepts[] entry through the vendored @x402/core v2 schema.
      let decoded: unknown;
      try {
        decoded = PaymentRequirementsV2Schema.parse(vector.input.x402Wire.value);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(`invalid payload: payment requirements: ${detail}`);
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
      // The built transaction, so pkc can verify it with the Rust kit.
      transaction: tx,
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

// One vector to one RunnerResult; an SDK error is a classified reject.
async function resultFor(vector: ConformanceVector): Promise<RunnerResult> {
  try {
    return await runVector(vector);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      error: message,
      id: vector.id,
      outcome: "reject",
      rejectCode: classifyReject(message),
    };
  }
}

// Intents this runner implements; pkc checks them against
// harness/expectations/typescript.toml.
const INTENTS = ["charge", "x402-exact", "session", "x402-upto", "x402-batch-settlement", "subscription"];

// Testee ABI v2 (harness/README.md): newline JSON {id, op, input} in,
// {id, ok, result | error} out, one long-lived process. `input` is the v1
// vector and `result` the v1 RunnerResult.
async function serve(): Promise<void> {
  const { createInterface } = await import("node:readline");
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const write = (value: unknown) => process.stdout.write(`${JSON.stringify(value)}\n`);
  for await (const line of lines) {
    if (!line.trim()) continue;
    let request: { id?: unknown; op?: unknown; input?: unknown };
    try {
      request = JSON.parse(line) as typeof request;
    } catch (error) {
      write({ id: null, ok: false, error: "bad-request", detail: String(error) });
      continue;
    }
    const id = request.id ?? null;
    if (request.op === "capabilities") {
      write({ id, ok: true, result: { abi: 2, language: "typescript", intents: INTENTS, honoursClock: true } });
    } else if (request.op === "build" || request.op === "verify" || request.op === "canonical-bytes") {
      write({ id, ok: true, result: await resultFor(request.input as ConformanceVector) });
    } else {
      write({ id, ok: false, error: "unknown-op", detail: String(request.op) });
    }
  }
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
  process.stdout.write(JSON.stringify(await resultFor(vector)) + "\n");
}

void (process.argv.includes("--serve") ? serve() : main());
