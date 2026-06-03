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
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { buildChargeTransaction } from "@solana/mpp/client";
import {
  defaultTokenProgramForCurrency,
  resolveStablecoinMint,
  verifyChargeTransaction,
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

// Apply the precedence rules a vector can probe: top-level `asset` /
// `payTo` win over `currency` / `recipient`; the methodDetails carry the
// network/decimals/tokenProgram/recentBlockhash. A vector that sets both
// pins which one the SDK must honor.
function flattenRequest(
  request: VectorChargeRequest,
  mintOwners: Record<string, string> | undefined,
): Parameters<typeof buildChargeTransaction>[0]["request"] {
  const currency = request.asset ?? request.currency;
  const recipient = request.payTo ?? request.recipient;
  if (!recipient) {
    throw new Error("vector request is missing recipient/payTo");
  }
  const md = request.methodDetails ?? {};
  const network = md.network ?? "mainnet";

  // tokenProgram precedence: explicit methodDetails wins, then rpc fixture
  // mint owner, then default-by-currency. This keeps the build path
  // RPC-free for SPL vectors.
  let tokenProgram = md.tokenProgram;
  const resolvedMint = resolveStablecoinMint(currency, network) ?? currency;
  if (!tokenProgram && currency.toLowerCase() !== "sol") {
    tokenProgram =
      (mintOwners && mintOwners[resolvedMint]) ??
      defaultTokenProgramForCurrency(currency, network);
  }

  // decimals default: 6 for SPL when omitted (matches buildChargeTransaction).
  const decimals =
    md.decimals ?? (currency.toLowerCase() === "sol" ? undefined : 6);

  return {
    amount: request.amount,
    currency,
    ...(request.externalId ? { externalId: request.externalId } : {}),
    methodDetails: {
      network,
      ...(decimals !== undefined ? { decimals } : {}),
      ...(tokenProgram ? { tokenProgram } : {}),
      ...(md.recentBlockhash ? { recentBlockhash: md.recentBlockhash } : {}),
      ...(md.feePayer !== undefined ? { feePayer: md.feePayer } : {}),
      ...(md.feePayerKey ? { feePayerKey: md.feePayerKey } : {}),
      ...(md.splits ? { splits: md.splits } : {}),
    },
    recipient,
  };
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
  const request = flattenRequest(input.request, input.rpcFixtures?.mintOwners);
  // Offline determinism: a build vector must supply recentBlockhash so the
  // build path does not reach for a live RPC. If it is missing the build
  // will throw against the bogus rpcUrl, surfacing as a clear failure.
  return await buildChargeTransaction({
    ...(input.request.computeUnitLimit !== undefined
      ? { computeUnitLimit: input.request.computeUnitLimit }
      : {}),
    ...(input.request.computeUnitPrice !== undefined
      ? { computeUnitPrice: BigInt(input.request.computeUnitPrice) }
      : {}),
    request,
    rpcUrl: "http://127.0.0.1:1",
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
    // signs a Solana tx here; the interop matrix asserts that path.
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

async function runVector(vector: ConformanceVector): Promise<RunnerResult> {
  if (vector.intent === "x402-exact") {
    return runX402Vector(vector);
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
  const request = flattenRequest(
    vector.input.request,
    vector.input.rpcFixtures?.mintOwners,
  );
  await verifyChargeTransaction(tx, request);
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
