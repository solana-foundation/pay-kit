// `subscription` vectors for the TypeScript testee. The testee passes the
// vector's input to the SDK unchanged (harness/AGENTS.md).
//
// - canonical bytes: the bearer-proof message (subscriptionAuthenticationMessage),
//   the period mapping (mapSubscriptionPeriodToHours), the delegation and
//   authority PDAs, and the wire shapes through the shared zod schema
//   (@solana/mpp `subscription`), re-encoded as JCS;
// - build: buildSubscriptionActivationTransaction on the request parsed with
//   the same schema, against the fixture RPC;
// - verify: the route's subscription() server method `verify` at the pinned
//   clock (Date.now is pinned for the call), or
//   verifySubscriptionAuthentication. The offline tier stops at the network:
//   an activation that passes every check reaches simulateTransaction /
//   sendTransaction, which the fixture RPC refuses; that refusal is the
//   accept signal, exactly where the Rust testkit stops.
import { address, createKeyPairSignerFromBytes } from "@solana/kit";
import {
  deriveSubscriptionAuthorityPda,
  deriveSubscriptionPda,
  mapSubscriptionPeriodToHours,
  subscription as subscriptionMethod,
} from "@solana/mpp";
import {
  buildSubscriptionActivationTransaction,
  subscriptionAuthenticationMessage,
  verifySubscriptionAuthentication,
} from "@solana/mpp/client";
import { subscription as subscriptionServer } from "@solana/mpp/server";
import { Credential } from "mppx";
import { base64UrlFromUtf8, canonicalizeJson } from "../jcs";
import type { ConformanceVector, RejectCode, RunnerResult } from "../schema";

type Json = Record<string, unknown>;

function exactJson(id: string, value: unknown): RunnerResult {
  const canonicalJson = canonicalizeJson(value);
  return {
    exactBytes: { base64Url: base64UrlFromUtf8(canonicalJson), canonicalJson },
    id,
    outcome: "accept",
  };
}

function rejected(
  id: string,
  error: unknown,
  rejectCode?: RejectCode,
): RunnerResult {
  const message = error instanceof Error ? error.message : String(error);
  const code = rejectCode ?? classifySubscriptionReject(message);
  return {
    error: message,
    id,
    outcome: "reject",
    ...(code ? { rejectCode: code } : {}),
  };
}

function unsupported(id: string, reason: string): RunnerResult {
  return {
    error: `unsupported-mode: ${reason}`,
    id,
    outcome: "unsupported-mode",
  };
}

function rpcUrlOf(vector: ConformanceVector): string {
  if (!vector.input.rpcUrl)
    throw new Error("driver did not inject input.rpcUrl");
  return vector.input.rpcUrl;
}

async function canonical(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  if (input.subscriptionAuthenticationMessage) {
    const bytes = Buffer.from(
      subscriptionAuthenticationMessage(
        input.subscriptionAuthenticationMessage,
      ),
    );
    return {
      exactBytes: {
        base64Url: bytes.toString("base64url"),
        canonicalJson: bytes.toString("utf8"),
      },
      id: vector.id,
      outcome: "accept",
    };
  }
  if (input.subscriptionPeriod) {
    const { periodUnit, periodCount } = input.subscriptionPeriod;
    try {
      // The SDK's own client reads periodCount with Number() before mapping.
      const periodHours = mapSubscriptionPeriodToHours(
        periodUnit as "day" | "week",
        Number(periodCount),
      );
      return exactJson(vector.id, { periodHours });
    } catch (error) {
      return rejected(vector.id, error, "invalid-challenge");
    }
  }
  if (input.subscriptionPda) {
    const p = input.subscriptionPda;
    const programId = address(p.subscriptionProgram);
    const derived =
      p.kind === "delegation"
        ? await deriveSubscriptionPda({
            planPda: address(p.planAddress ?? ""),
            programId,
            subscriber: address(p.subscriber),
          })
        : await deriveSubscriptionAuthorityPda({
            mint: address(p.mint ?? ""),
            programId,
            subscriber: address(p.subscriber),
          });
    return exactJson(vector.id, { address: derived });
  }
  if (input.subscriptionInstruction) {
    return unsupported(
      vector.id,
      "@solana/mpp exposes no subscriptions instruction-data encoder (it delegates to @solana/subscriptions)",
    );
  }
  if (input.subscriptionWire) {
    const { shape, value } = input.subscriptionWire;
    try {
      const parsed =
        shape === "request"
          ? subscriptionMethod.schema.request.parse(value)
          : subscriptionMethod.schema.credential.payload.parse(value);
      return exactJson(vector.id, parsed);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return shape === "request"
        ? rejected(
            vector.id,
            new Error(`invalid subscription challenge: ${detail}`),
            "invalid-challenge",
          )
        : rejected(
            vector.id,
            new Error(`invalid subscription payload: ${detail}`),
            "invalid-payload",
          );
    }
  }
  return unsupported(vector.id, "no subscription canonical-bytes input");
}

async function build(vector: ConformanceVector): Promise<RunnerResult> {
  const input = vector.input;
  if (!input.signerSecretKey || !input.subscriptionChallenge) {
    throw new Error(
      "build vector is missing signerSecretKey or subscriptionChallenge",
    );
  }
  const signer = await createKeyPairSignerFromBytes(
    Uint8Array.from(input.signerSecretKey),
  );
  try {
    let request: Parameters<
      typeof buildSubscriptionActivationTransaction
    >[0]["request"];
    try {
      request = subscriptionMethod.schema.request.parse(
        input.subscriptionChallenge.request,
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`invalid subscription challenge: ${detail}`);
    }
    const transaction = await buildSubscriptionActivationTransaction({
      request,
      rpcUrl: rpcUrlOf(vector),
      signer,
    });
    return { id: vector.id, outcome: "accept", transaction };
  } catch (error) {
    // Every refusal of the client builder is a refusal of the challenge.
    return rejected(vector.id, error, "invalid-challenge");
  }
}

const NETWORK_STEP =
  /method (simulateTransaction|sendTransaction) is not served by the conformance fixture RPC/;

async function withClock<T>(
  nowSeconds: number,
  run: () => Promise<T>,
): Promise<T> {
  const original = Date.now;
  Date.now = () => nowSeconds * 1000;
  try {
    return await run();
  } finally {
    Date.now = original;
  }
}

async function verifyActivation(
  vector: ConformanceVector,
): Promise<RunnerResult> {
  const input = vector.input;
  const route = input.subscriptionServer!;
  const signer = input.subscriptionServerFeePayerSecretKey
    ? await createKeyPairSignerFromBytes(
        Uint8Array.from(input.subscriptionServerFeePayerSecretKey),
      )
    : undefined;
  const method = subscriptionServer({
    decimals: route.decimals,
    mint: route.mint,
    network: route.network,
    periodCount: route.periodCount,
    periodUnit: route.periodUnit as "day" | "week",
    planId: route.planAddress,
    puller: route.puller,
    recipient: route.recipient,
    rpcUrl: rpcUrlOf(vector),
    ...(signer ? { signer } : {}),
    subscriptionProgram: route.subscriptionProgram,
    tokenProgram: route.tokenProgram,
  });
  let credential: ReturnType<typeof Credential.deserialize>;
  try {
    credential = Credential.deserialize(input.subscriptionAuthorization!);
  } catch (error) {
    return rejected(vector.id, error, "invalid-payload");
  }
  try {
    await withClock(input.nowSeconds!, () =>
      method.verify!({
        credential: credential as never,
        request: credential.challenge.request as never,
      } as never),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (NETWORK_STEP.test(message)) return { id: vector.id, outcome: "accept" };
    return rejected(vector.id, error);
  }
  return {
    error: "verify settled without reaching the network",
    id: vector.id,
    outcome: "reject",
  };
}

async function verifyProof(vector: ConformanceVector): Promise<RunnerResult> {
  const p = vector.input.subscriptionProof!;
  const ok = await verifySubscriptionAuthentication(
    p.authentication as Parameters<typeof verifySubscriptionAuthentication>[0],
    p.subscriptionDelegation,
  );
  return ok
    ? { id: vector.id, outcome: "accept" }
    : rejected(
        vector.id,
        new Error("the proof does not verify for this delegation"),
        "authentication-invalid",
      );
}

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  if (vector.mode === "canonical-bytes") return canonical(vector);
  if (vector.mode === "build-transaction") return build(vector);
  if (vector.input.subscriptionAuthorization) return verifyActivation(vector);
  if (vector.input.subscriptionProof) return verifyProof(vector);
  if (vector.input.subscriptionActive) {
    return unsupported(
      vector.id,
      '@solana/mpp has no stateless active-subscription check; delegation usability is only re-checked inside verify of a bound type="proof" credential',
    );
  }
  return unsupported(
    vector.id,
    "subscription verify input carries no credential",
  );
}

// SDK error message -> shared category, for the subscription surface.
// Mirrors rust/crates/conformance/src/realize/subscription.rs `classify`.
const PATTERNS: Array<[RegExp, RejectCode]> = [
  [/network does not match|network mismatch/i, "wrong-network"],
  [
    /hmac mismatch|did not issue|was not issued by this server|does not match this server|is not a subscription|terms do not match|does not match this route/i,
    "challenge-mismatch",
  ],
  [/challenge has expired|challenge expired/i, "challenge-expired"],
  [/subscription has expired|subscription expired/i, "subscription-expired"],
  [
    /authentication proof|proof challengeid does not match|proof payer does not match|missing authentication|authentication\.type|authentication is required/i,
    "authentication-invalid",
  ],
  [
    /receiver does not match|transfer_subscription accounts do not match/i,
    "recipient-mismatch",
  ],
  [/source.*(does not match|did:pkh)/i, "source-mismatch"],
  [
    /fee payer must be|fee payer pubkey not present|fee-payer signer does not match/i,
    "fee-payer-mismatch",
  ],
  [/compute unit limit exceeds/i, "compute-limit-over-cap"],
  [/compute unit price exceeds/i, "compute-price-over-cap"],
  [
    /unsupported program|multiple subscribe|multiple transfer_subscription|multiple initialize_subscription_authority|initialize_subscription_authority is not allowed|idempotent|ata creation|unsupported subscriptions instruction|unsupported compute-budget|multiple memo|multiple compute-unit/i,
    "unexpected-instruction",
  ],
  [
    /missing subscribe|missing transfer_subscription|subscribe must precede|subscribe accounts do not match|transfer_subscription data does not match|transfer_subscription amount does not match|transfer_subscription delegator does not match|transfer_subscription mint does not match|memo does not match|missing challenge externalid memo|signers must be exactly/i,
    "activation-scope",
  ],
  [
    /not paid for the current billing period|cancellation has taken effect|authority has been invalidated|subscriptionauthority account|subscriptiondelegation account|does not match the bound plan and payer|owner mismatch|subscriptiondelegation discriminator|subscriptiondelegation length/i,
    "subscription-inactive",
  ],
  [
    /invalid subscription challenge|requires feepayerkey|feepayerkey is required|untrusted subscription program|currency must match|must match amount|must match recipient|does not match the challenge|plan owner does not match|plan account not found|invalid recentblockhash|pubkey|periodcount|period_hours|periodunit|methoddetails|invalid amount/i,
    "invalid-challenge",
  ],
  [
    /push-mode|unsupported payload type|payload type|missing `transaction`|missing transaction|failed to decode|tx decode|invalid transaction|could not identify subscriber|subscriber cannot|does not verify|cannot be used with fee sponsorship/i,
    "invalid-payload",
  ],
];

export function classifySubscriptionReject(
  message: string,
): RejectCode | undefined {
  for (const [pattern, code] of PATTERNS) {
    if (pattern.test(message)) return code;
  }
  return undefined;
}
