// TypeScript REFERENCE for the x402 `exact` intent conformance oracle.
//
// The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
// produces a base64(JSON) payment header and a SERVER verify consumes one.
// So the cross-SDK oracle is the DECODED ENVELOPE shape, not the signed
// Solana transaction inside `payload.transaction` (that is the interop
// matrix's job). This module mirrors the Rust spine line-for-line:
//   - build v2 -> rust `build_payment_header`  (PAYMENT-SIGNATURE)
//   - build v1 -> rust `build_payment_header_v1` (X-PAYMENT)
//   - verify   -> rust `X402::parse_payment_signature` + the `accepted`
//                 vs route field comparison in `verify_envelope_payload`
//
// It is intentionally RPC-free and deterministic. There is no production
// TS x402 SDK in this tree (`@solana/mpp` ships charge only), so this
// reference IS the contract every per-SDK x402 runner is validated
// against. Constants and resolution rules are copied verbatim from
// `rust/crates/x402/src/{constants.rs, protocol/schemes/exact/types.rs}`.

import type { X402EnvelopeShape, X402Offer } from "./schema";

// ── Canonical network identifiers (rust types.rs) ──
export const SOLANA_NETWORK = "solana"; // legacy v1 mainnet slug
export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
export const SOLANA_TESTNET = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z";

export const EXACT_SCHEME = "exact";
export const X402_VERSION_V1 = 1;
export const X402_VERSION_V2 = 2;

// Headers (rust constants.rs).
export const X402_V1_PAYMENT_HEADER = "X-PAYMENT";
export const X402_V1_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED";
export const X402_V2_PAYMENT_HEADER = "PAYMENT-SIGNATURE";
export const X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";

// Map a cluster/network identifier to its CAIP-2 form. Mirrors
// `caip2_network_for_cluster`.
export function caip2NetworkForCluster(cluster: string): string {
  switch (cluster) {
    case SOLANA_MAINNET:
    case SOLANA_NETWORK:
    case "mainnet":
    case "mainnet-beta":
      return SOLANA_MAINNET;
    case SOLANA_TESTNET:
    case "testnet":
    case "solana-testnet":
      return SOLANA_TESTNET;
    case "devnet":
    case "localnet":
    case SOLANA_DEVNET:
    case "solana-devnet":
      return SOLANA_DEVNET;
    default:
      return SOLANA_MAINNET;
  }
}

// Legacy v1 network slug for a given offer. Mirrors
// `v1_network_for_requirements`: devnet-family -> "solana-devnet",
// everything else -> "solana".
export function v1NetworkForOffer(offer: X402Offer): string {
  const caip2 = caip2NetworkForCluster(offer.network);
  return caip2 === SOLANA_DEVNET ? "solana-devnet" : SOLANA_NETWORK;
}

// Canonical v2 `accepted` object for an offer. Mirrors
// `PaymentRequirements::to_accepted_value`: maxTimeoutSeconds defaults to
// 300, extra defaults to {}.
export function toAcceptedValue(offer: X402Offer): Record<string, unknown> {
  return {
    scheme: offer.scheme ?? EXACT_SCHEME,
    network: offer.network,
    amount: offer.amount,
    asset: offer.asset,
    payTo: offer.payTo,
    maxTimeoutSeconds: offer.maxTimeoutSeconds ?? 300,
    extra: offer.extra ?? {},
  };
}

type PaymentProof = { transaction: string };

type PaymentSignatureEnvelope = {
  scheme?: string;
  network?: string;
  x402Version: number;
  accepted?: Record<string, unknown>;
  payload: PaymentProof;
};

function encodeEnvelope(envelope: PaymentSignatureEnvelope): string {
  // Drop undefined keys so the wire JSON matches rust's
  // skip_serializing_if = "Option::is_none" exactly.
  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(envelope)) {
    if (value !== undefined) clean[key] = value;
  }
  return Buffer.from(JSON.stringify(clean), "utf8").toString("base64");
}

// Build a v2 PAYMENT-SIGNATURE header. Mirrors rust `build_payment_header`:
// no top-level scheme/network, accepted echoes the offer.
export function buildPaymentHeaderV2(
  offer: X402Offer,
  transaction: string,
): string {
  return encodeEnvelope({
    x402Version: X402_VERSION_V2,
    accepted: toAcceptedValue(offer),
    payload: { transaction },
  });
}

// Build a v1 X-PAYMENT header. Mirrors rust `build_payment_header_v1`:
// top-level scheme="exact" + legacy network slug, NO accepted.
export function buildPaymentHeaderV1(
  offer: X402Offer,
  transaction: string,
): string {
  return encodeEnvelope({
    scheme: EXACT_SCHEME,
    network: v1NetworkForOffer(offer),
    x402Version: X402_VERSION_V1,
    payload: { transaction },
  });
}

export function buildPaymentHeader(
  version: number,
  offer: X402Offer,
  transaction: string,
): string {
  return version === X402_VERSION_V1
    ? buildPaymentHeaderV1(offer, transaction)
    : buildPaymentHeaderV2(offer, transaction);
}

// Decode an envelope header into the conformance shape oracle.
export function decodeEnvelopeShape(header: string): X402EnvelopeShape {
  const raw = Buffer.from(header, "base64").toString("utf8");
  const env = JSON.parse(raw) as PaymentSignatureEnvelope;
  const accepted = env.accepted;
  const shape: X402EnvelopeShape = {
    x402Version: env.x402Version,
    hasAccepted: accepted !== undefined && accepted !== null,
    payloadHasTransaction:
      env.payload !== undefined &&
      typeof env.payload.transaction === "string" &&
      env.payload.transaction.length > 0,
  };
  if (env.scheme !== undefined) shape.scheme = env.scheme;
  if (env.network !== undefined) shape.network = env.network;
  if (accepted) {
    shape.acceptedScheme = accepted.scheme as string | undefined;
    shape.acceptedNetwork = accepted.network as string | undefined;
    shape.acceptedAsset = accepted.asset as string | undefined;
    shape.acceptedPayTo = accepted.payTo as string | undefined;
    shape.acceptedAmount = accepted.amount as string | undefined;
  }
  return shape;
}

export type X402ServerRoute = {
  network: string; // CAIP-2 or cluster slug; normalized via caip2NetworkForCluster
  recipient: string;
  currency: string;
  amount: string; // base units
};

// Verify a payment header against a server route. Mirrors the version
// dispatch + network gate in rust `parse_payment_signature` and the
// `accepted`-vs-route field comparison in `verify_envelope_payload`.
// RPC-free: the signed-transaction settlement (decode/transferChecked
// validation) is out of scope for the envelope oracle, so a structurally
// valid, route-matching envelope is accepted here.
export function verifyPaymentHeader(
  header: string,
  route: X402ServerRoute,
): { ok: true } {
  let env: PaymentSignatureEnvelope;
  try {
    const raw = Buffer.from(header, "base64").toString("utf8");
    env = JSON.parse(raw) as PaymentSignatureEnvelope;
  } catch (error) {
    throw new Error(
      `invalid payload: undecodable payment header (${String(error)})`,
    );
  }

  const expectedNetwork = caip2NetworkForCluster(route.network);

  if (env.x402Version === X402_VERSION_V1) {
    const scheme = env.scheme ?? "";
    if (scheme !== EXACT_SCHEME) {
      throw new Error(`invalid payload: unexpected scheme ${scheme}`);
    }
    const network = env.network ?? "";
    if (caip2NetworkForCluster(network) !== expectedNetwork) {
      throw new Error(
        `Network mismatch: expected ${expectedNetwork}, got ${network}`,
      );
    }
  } else if (env.x402Version === X402_VERSION_V2) {
    const accepted = env.accepted;
    if (!accepted) {
      throw new Error("invalid payload: v2 envelope missing accepted");
    }
    const acceptedNetwork = (accepted.network as string | undefined) ?? "";
    if (acceptedNetwork !== expectedNetwork) {
      throw new Error(
        `Network mismatch: expected ${expectedNetwork}, got ${acceptedNetwork}`,
      );
    }
    // accepted-vs-route field comparison (rust verify_envelope_payload).
    const acceptedAmount = (accepted.amount as string | undefined) ?? "";
    if (acceptedAmount !== route.amount) {
      throw new Error(
        `Amount mismatch: expected ${route.amount}, got ${acceptedAmount}`,
      );
    }
    const acceptedPayTo = (accepted.payTo as string | undefined) ?? "";
    if (acceptedPayTo !== route.recipient) {
      throw new Error(
        "Recipient mismatch: credential claims a different recipient",
      );
    }
    const acceptedAsset = (accepted.asset as string | undefined) ?? "";
    if (acceptedAsset !== route.currency) {
      throw new Error(
        `Currency mismatch: expected ${route.currency}, got ${acceptedAsset}`,
      );
    }
  } else {
    throw new Error(
      `invalid payload: Unsupported x402 version: ${env.x402Version}`,
    );
  }

  if (
    env.payload === undefined ||
    typeof env.payload.transaction !== "string" ||
    env.payload.transaction.length === 0
  ) {
    throw new Error("invalid payload: missing transaction proof");
  }

  return { ok: true };
}
