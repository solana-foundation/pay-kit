// Session server and client vectors for the TypeScript testee
// (`input.sessionServerVerify`, `input.sessionOpenVerify`,
// `input.sessionOpenBuild`). The testee passes the vector's input to the SDK
// unchanged (harness/AGENTS.md "Never put logic in the testee").
//
// - verify: @solana/mpp's `createSessionServer` configured from
//   `sessionServerVerify.server` over a memory store holding
//   `sessionServerVerify.channel` (the server's per-channel state), and the
//   client's `credential` parsed with the SDK's session action schema, then:
//   `open` through `verifyOpenPreBroadcast` against `challenge`, `voucher`
//   through `verifyVoucherForAmount` at the challenged `amount`, `topUp`
//   through `verifyTopUpPreBroadcast`, `close` through `processClose`, and
//   `use` through `processUse` (the challenged amount) or, with a
//   `meteredAmount`, `authenticateUse` then `chargeOperatorRequest`.
// - sessionOpenVerify: the same server's `verifyOpenPreBroadcast` on the
//   vector's `open` against the challenged blockhash.
// - build: `createPaymentChannelSessionOpener` on `sessionOpenBuild.request`
//   with the salt and deposit its options take; the result carries the
//   `open` action as `sessionCredential`.
//
// Mirrors rust/crates/kit/examples/vector_runner/session.rs.
import {
  createKeyPairSignerFromBytes,
  createSolanaRpc,
  generateKeyPairSigner,
  type KeyPairSigner,
} from "@solana/kit";
import { session as sessionMethod } from "@solana/mpp";
import { createPaymentChannelSessionOpener } from "@solana/mpp/client";
import {
  type ChannelState,
  createMemorySessionStore,
  createSessionServer,
  type SessionServer,
  type SessionStore,
} from "@solana/mpp/server";
import type { ConformanceVector, RejectCode, RunnerResult } from "../schema";

type Json = Record<string, unknown>;
type SessionParameters = Parameters<typeof createSessionServer>[0];
type SessionAction = ReturnType<typeof sessionMethod.schema.credential.payload.parse>;

class Reject extends Error {
  constructor(
    message: string,
    readonly rejectCode: RejectCode | undefined,
  ) {
    super(message);
  }
}

function rejected(id: string, error: unknown, code?: RejectCode): RunnerResult {
  const message = error instanceof Error ? error.message : String(error);
  const rejectCode = error instanceof Reject ? error.rejectCode : (code ?? codeFor(message));
  return { error: message, id, outcome: "reject", ...(rejectCode ? { rejectCode } : {}) };
}

function unsupported(id: string, reason: string): RunnerResult {
  return { error: `unsupported-mode: ${reason}`, id, outcome: "unsupported-mode" };
}

function rpcUrlOf(vector: ConformanceVector): string {
  if (!vector.input.rpcUrl) throw new Error("driver did not inject input.rpcUrl");
  return vector.input.rpcUrl;
}

function keyOf(bytes: number[] | undefined, name: string): Promise<KeyPairSigner> {
  if (!bytes) throw new Error(`input.${name} missing`);
  return createKeyPairSignerFromBytes(Uint8Array.from(bytes));
}

function u64(value: unknown, name: string): bigint | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  throw new Error(`invalid ${name}`);
}

function text(value: Json, key: string, scope: string): string {
  const v = value[key];
  if (typeof v !== "string") throw new Error(`${scope}.${key} missing`);
  return v;
}

/**
 * The shared code for an @solana/mpp session server refusal. The table names
 * what each normalized category means for this SDK's messages (mirrors
 * `code_for` in rust/crates/kit/examples/vector_runner/session.rs).
 */
export function codeFor(message: string): RejectCode | undefined {
  const m = message.toLowerCase();
  const has = (needle: string) => m.includes(needle);
  if (has("transaction version") && has("not accepted")) return "unsupported-version";
  if (has("used for a different request")) return "invalid-challenge";
  if (has("compute unit price") && (has("exceed") || has("maximum"))) return "compute-price-over-cap";
  if (has("compute unit limit") && (has("exceed") || has("maximum"))) return "compute-limit-over-cap";
  if (has("invalid payload") || has("invalid session payload")) return "invalid-payload";
  if (
    has("client-mode close requires a voucher") ||
    has("client-mode close must not include") ||
    has("operator-mode close must not include") ||
    has("operator-mode close requires")
  ) {
    return "close-authorization";
  }
  if (has("authentication") || has("does not authenticate") || has("only valid for operator-signed")) {
    return "authentication-invalid";
  }
  if (has("fee payer does not match") || has("fee payer must") || has("transaction fee payer")) {
    return "fee-payer-mismatch";
  }
  if (
    has("does not match derived channel pda") ||
    has("channel pda") ||
    has("does not match the signed voucher's channelid") ||
    has("does not match the close channelid") ||
    has("does not match persisted channel state")
  ) {
    return "channel-id-mismatch";
  }
  if (
    has("unexpected instruction") ||
    has("more than one open instruction") ||
    has("no payment-channels open instruction") ||
    has("top-up instruction not found") ||
    has("unsupported compute budget")
  ) {
    return "unexpected-instruction";
  }
  if (
    has("below minimumdeposit") ||
    has("deposit must be greater than zero") ||
    has("additionalamount must be positive") ||
    has("does not match additionalamount") ||
    has("insufficient authorized voucher availability") ||
    has("charge amount must be positive")
  ) {
    return "amount-mismatch";
  }
  if (has("signature slot") || has("invalid client signature") || has("must sign the open transaction")) {
    return "invalid-payload";
  }
  if (
    has("payment-channel") ||
    has("verifyopentx") ||
    has("open openslot") ||
    has("idletimeoutseconds") ||
    has("authorizedsigner") ||
    has("privileges")
  ) {
    return "open-binding-mismatch";
  }
  if (has("invalid-signature") || has("signature verification failed")) return "voucher-signature";
  if (has("must exceed watermark") || has("already accepted")) return "cumulative-amount-mismatch";
  if (has("exceeds deposit") || has("insufficient channel availability")) return "cumulative-exceeds-deposit";
  if (has("voucher expired")) return "voucher-expired";
  if (has("settlement window")) return "voucher-expires-before-settlement";
  if (has("close is pending") || has("close already requested")) return "channel-closing";
  if (has("already sealed")) return "close-state";
  if (has("not found")) return "channel-state";
  if (has("invalid") || has("decode") || has("not an unsigned integer")) return "invalid-payload";
  return undefined;
}

/** The SDK server `server` describes (mirrors `kit_server` in the Rust testee). */
async function sdkServer(
  vector: ConformanceVector,
  server: Json,
  store: SessionStore,
): Promise<SessionServer | RunnerResult> {
  const input = vector.input;
  const voucherSigner = server.voucherSigner ?? "client";
  if (voucherSigner !== "client" && voucherSigner !== "operator") {
    throw new Error(`invalid server.voucherSigner ${String(voucherSigner)}`);
  }
  const versions = server.transactionVersions as number[] | undefined;
  if (versions !== undefined && !(new Set(versions).size === 1 && versions.includes(0))) {
    return unsupported(
      vector.id,
      "@solana/mpp's session server takes no accepted transaction-version set (server.transactionVersions other than [0])",
    );
  }
  let feePayerSigner: KeyPairSigner | undefined;
  if (typeof server.feePayer === "string") {
    feePayerSigner = await keyOf(input.sessionServerFeePayerSecretKey, "sessionServerFeePayerSecretKey");
    if (feePayerSigner.address !== server.feePayer) {
      throw new Error("sessionServerFeePayerSecretKey is not server.feePayer");
    }
  }
  const operatorVoucherSigner = input.sessionServerOperatorSecretKey
    ? await keyOf(input.sessionServerOperatorSecretKey, "sessionServerOperatorSecretKey")
    : undefined;
  const parameters: SessionParameters = {
    amount: u64(server.amount, "amount") ?? 0n,
    currency: text(server, "currency", "server"),
    decimals: server.decimals as number,
    ...(server.distributionSplits !== undefined
      ? { distributionSplits: server.distributionSplits as SessionParameters["distributionSplits"] }
      : {}),
    ...(feePayerSigner ? { feePayer: true, feePayerSigner } : {}),
    gracePeriodSeconds: server.gracePeriodSeconds as number,
    ...(server.idleTimeoutOptionsSeconds !== undefined
      ? { idleTimeoutOptionsSeconds: server.idleTimeoutOptionsSeconds as number[] }
      : {}),
    ...(server.idleTimeoutSeconds !== undefined ? { idleTimeoutSeconds: server.idleTimeoutSeconds as number } : {}),
    ...(server.minimumDeposit !== undefined ? { minimumDeposit: u64(server.minimumDeposit, "minimumDeposit") } : {}),
    network: text(server, "network", "server"),
    operator: text(server, "operator", "server"),
    ...(operatorVoucherSigner ? { operatorVoucherSigner } : {}),
    recipient: text(server, "recipient", "server"),
    // The fixture RPC: the pre-broadcast checks never reach it.
    rpc: createSolanaRpc(rpcUrlOf(vector)),
    // The settlement signer; settlement is not part of any vector.
    signer: await generateKeyPairSigner(),
    store,
    ...(server.suggestedDeposit !== undefined
      ? { suggestedDeposit: u64(server.suggestedDeposit, "suggestedDeposit") }
      : {}),
    ...(typeof server.tokenProgram === "string" ? { tokenProgram: server.tokenProgram } : {}),
    voucherSigner,
  };
  return createSessionServer(parameters);
}

/** The server's per-channel state (`channel`) as the SDK stores it. */
function storedChannel(channel: Json): ChannelState {
  const number = (key: string): bigint => {
    const value = u64(channel[key], `channel.${key}`);
    if (value === undefined) throw new Error(`channel.${key} missing`);
    return value;
  };
  const highest = channel.highestVoucher as { signature?: string; voucher?: { expiresAt?: number } } | undefined;
  const processedUses = ((channel.processedUses as Json[] | undefined) ?? []).map(entry => ({
    amount: u64(entry.amount, "channel.processedUses[].amount"),
    challengeId: text(entry, "challengeId", "channel.processedUses[]"),
    cumulative: u64(entry.cumulativeAmount, "channel.processedUses[].cumulativeAmount") ?? 0n,
    idempotencyKey: text(entry, "idempotencyKey", "channel.processedUses[]"),
    voucherSignature: text(entry, "voucherSignature", "channel.processedUses[]"),
  }));
  const voucherSigner = text(channel, "voucherSigner", "channel");
  if (voucherSigner !== "client" && voucherSigner !== "operator") throw new Error("invalid channel.voucherSigner");
  return {
    ...(channel.authentication ? { authentication: channel.authentication as ChannelState["authentication"] } : {}),
    authorizedSigner: text(channel, "authorizedSigner", "channel"),
    channelId: text(channel, "channelId", "channel"),
    closeRequestedAt: u64(channel.closureStartedAt, "channel.closureStartedAt"),
    committedDeliveries: [],
    cumulative: number("acceptedCumulative"),
    deposit: number("escrowedAmount"),
    highestVoucherExpiresAt: highest ? BigInt(highest.voucher?.expiresAt ?? 0) : undefined,
    highestVoucherSignature: highest?.signature,
    idleTimeoutSeconds: channel.idleTimeoutSeconds as number | undefined,
    lastActivityAt: Date.now(),
    nextDeliverySequence: 0n,
    openSlot: u64(channel.openSlot, "channel.openSlot"),
    openingChallengeId: typeof channel.openingChallengeId === "string" ? channel.openingChallengeId : undefined,
    payer: text(channel, "payer", "channel"),
    pendingDeliveries: [],
    processedUses,
    rentPayer: text(channel, "rentPayer", "channel"),
    schemaVersion: 1,
    sealed: text(channel, "status", "channel") === "closed",
    settledOnChain: number("settledOnChain"),
    spentAmount: number("spentAmount"),
    voucherSigner,
  };
}

function parseAction(credential: unknown): SessionAction {
  try {
    return sessionMethod.schema.credential.payload.parse(credential);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Reject(`invalid payload: session credential: ${detail}`, "invalid-payload");
  }
}

function challengeOf(params: Json): { id: string; recentBlockhash: string; recentSlot: bigint } {
  const challenge = (params.challenge ?? {}) as Json;
  const recentSlot = u64(challenge.recentSlot, "challenge.recentSlot");
  if (recentSlot === undefined) throw new Error("challenge.recentSlot missing");
  return {
    id: typeof challenge.id === "string" ? challenge.id : "",
    recentBlockhash: typeof challenge.recentBlockhash === "string" ? challenge.recentBlockhash : "",
    recentSlot,
  };
}

async function verifyServer(vector: ConformanceVector): Promise<RunnerResult> {
  const params = vector.input.sessionServerVerify as unknown as Json;
  const store = createMemorySessionStore();
  if (params.channel) {
    const state = storedChannel(params.channel as Json);
    await store.updateChannel(state.channelId, () => state);
  }
  const server = (params.server ?? {}) as Json;
  const sdk = await sdkServer(vector, server, store);
  if (!("verifyOpenPreBroadcast" in sdk)) return sdk;
  const action = parseAction(params.credential);
  switch (action.action) {
    case "open": {
      const challenge = challengeOf(params);
      await sdk.verifyOpenPreBroadcast(action, {
        challengeId: challenge.id,
        recentBlockhash: challenge.recentBlockhash,
        recentSlot: challenge.recentSlot,
      });
      return { id: vector.id, outcome: "accept" };
    }
    case "voucher":
      await sdk.verifyVoucherForAmount(action, u64(server.amount, "server.amount") ?? 0n);
      return { id: vector.id, outcome: "accept" };
    case "topUp":
      await sdk.verifyTopUpPreBroadcast(action);
      return { id: vector.id, outcome: "accept" };
    case "close":
      await sdk.processClose(action);
      return { id: vector.id, outcome: "accept" };
    case "use": {
      const operator = await keyOf(vector.input.sessionServerOperatorSecretKey, "sessionServerOperatorSecretKey");
      const challengeId = typeof (params.challenge as Json | undefined)?.id === "string"
        ? ((params.challenge as Json).id as string)
        : "";
      const idempotencyKey = typeof params.idempotencyKey === "string" ? params.idempotencyKey : "";
      const metered = u64(params.meteredAmount, "meteredAmount");
      const charge =
        metered === undefined
          ? await sdk.processUse(action, challengeId, idempotencyKey)
          : await sdk.chargeOperatorRequest(
              await sdk.authenticateUse(action, challengeId, idempotencyKey),
              operator,
              metered,
            );
      // Read the result back from the store: the persisted watermark and
      // spent amount, after checking the persisted voucher is the returned one.
      const stored = await store.getChannel(charge.voucher.voucher.channelId);
      if (!stored) throw new Error("channel missing after use");
      if (
        stored.highestVoucherSignature !== charge.voucher.signature ||
        stored.cumulative.toString() !== charge.voucher.voucher.cumulativeAmount
      ) {
        throw new Error(
          `the returned voucher (cumulative ${charge.voucher.voucher.cumulativeAmount}) is not the persisted one (cumulative ${stored.cumulative})`,
        );
      }
      return {
        id: vector.id,
        outcome: "accept",
        sessionVoucher: {
          channelId: stored.channelId,
          cumulativeAmount: stored.cumulative.toString(),
          signer: charge.voucher.signer,
          spentAmount: stored.spentAmount.toString(),
        },
      };
    }
  }
}

async function verifyOpenTransaction(vector: ConformanceVector): Promise<RunnerResult> {
  const params = vector.input.sessionOpenVerify as unknown as Json;
  const server = { voucherSigner: "client", ...((params.server ?? {}) as Json) };
  const sdk = await sdkServer(vector, server, createMemorySessionStore());
  if (!("verifyOpenPreBroadcast" in sdk)) return sdk;
  const action = parseAction({ action: "open", ...((params.open ?? {}) as Json) });
  if (action.action !== "open") throw new Error("sessionOpenVerify.open is not an open");
  const blockhash = params.challengedBlockhash;
  if (typeof blockhash !== "string") throw new Error("sessionOpenVerify.challengedBlockhash missing");
  // The open's own slot is the challenged one: this input pins only the
  // blockhash, as the Rust testkit's transaction-only hook does.
  await sdk.verifyOpenPreBroadcast(action, {
    challengeId: "",
    recentBlockhash: blockhash,
    recentSlot: BigInt(action.openSlot),
  });
  return { id: vector.id, outcome: "accept" };
}

/** The shared code for a session client refusal (mirrors `build_code_for` in the Rust testee). */
function buildCodeFor(message: string): RejectCode | undefined {
  const m = message.toLowerCase();
  return [
    "challenge",
    "network",
    "program",
    "tokenprogram",
    "feepayerkey",
    "operator",
    "spl token",
    "graceperiod",
    "decimals",
    "invalid",
  ].some(needle => m.includes(needle))
    ? "invalid-challenge"
    : undefined;
}

async function build(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  const params = input.sessionOpenBuild as unknown as Json;
  const payer = await keyOf(input.signerSecretKey, "signerSecretKey");
  const sessionSigner = await keyOf(input.sessionSignerSecretKey, "sessionSignerSecretKey");
  const challenge = (params.challenge ?? {}) as Json;
  try {
    let request: Parameters<ReturnType<typeof createPaymentChannelSessionOpener>>[0]["challenge"]["request"];
    try {
      request = sessionMethod.schema.request.parse(params.request) as typeof request;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`invalid challenge: ${detail}`);
    }
    const opener = createPaymentChannelSessionOpener({
      deposit: text(params, "deposit", "sessionOpenBuild"),
      rpcUrl: rpcUrlOf(vector),
      salt: text(params, "salt", "sessionOpenBuild"),
      sessionSigner,
      signer: payer,
    });
    const opened = await opener({
      challenge: {
        id: typeof challenge.id === "string" ? challenge.id : "",
        intent: "session",
        method: "solana",
        realm: "conformance",
        request,
      },
    } as Parameters<typeof opener>[0]);
    return { id: vector.id, outcome: "accept", sessionCredential: JSON.stringify(opened.payload) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return rejected(vector.id, error, buildCodeFor(message));
  }
}

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  try {
    if (vector.mode === "build-transaction") {
      if (!vector.input.sessionOpenBuild) return unsupported(vector.id, "session build vector without sessionOpenBuild");
      return await build(vector);
    }
    if (vector.input.sessionServerVerify) return await verifyServer(vector);
    if (vector.input.sessionOpenVerify) return await verifyOpenTransaction(vector);
  } catch (error) {
    return rejected(vector.id, error);
  }
  return unsupported(vector.id, "no session runner path for this input");
}
