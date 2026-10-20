// x402 `exact` envelope helpers for the conformance harness.
//
// The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
// produces a base64(JSON) payment header and a SERVER verify consumes one.
// The cross-SDK oracle is the DECODED ENVELOPE shape (`decodeEnvelopeShape`),
// which every runner reports after its SDK built or verified the envelope.
//
// The TypeScript runner no longer builds or verifies with anything here: it
// drives @solana/pay-kit and the vendored @x402/svm (see ts-runner.ts). The
// envelope builders, challenge parsers and `verifyPaymentHeader` below are a
// harness-local port of the Rust envelope rules that only
// test/x402-v1-exact.test.ts still exercises; they are not an SDK and no
// vector outcome depends on them.

import type { X402EnvelopeShape, X402Offer } from "./schema";

// ── Canonical network identifiers (rust types.rs) ──
export const SOLANA_NETWORK = "solana"; // legacy v1 mainnet slug
export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
export const SOLANA_TESTNET = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z";

export const EXACT_SCHEME = "exact";
export const X402_VERSION_V1 = 1;
export const X402_VERSION_V2 = 2;

// Challenge headers (rust constants.rs).
export const X402_V1_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED";
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

// ── x402 v2 extensions ──
//
// The `extensions` object rides on BOTH the inbound PAYMENT-REQUIRED
// challenge and the outbound PAYMENT-SIGNATURE credential. The spec JSON
// key is kebab-case `payment-identifier`; `info` is camelCase
// `{ required?, id? }`; `schema?` is echoed verbatim.

export const PAYMENT_IDENTIFIER_KEY = "payment-identifier";

// Spec id pattern (extensions/payment_identifier.md).
export const PAYMENT_IDENTIFIER_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

export type PaymentIdentifierInfo = { required?: boolean; id?: string };
export type PaymentIdentifierExtension = {
  info: PaymentIdentifierInfo;
  schema?: unknown;
};

// Typed view over the v2 `extensions` object. Known extensions are
// fielded out; unknown ones flow through verbatim under their own key so
// the echo rule does not drop forward-compatible payloads. Mirrors rust
// `PaymentExtensions { payment_identifier, #[serde(flatten)] other }`.
export type PaymentExtensions = Record<string, unknown> & {
  [PAYMENT_IDENTIFIER_KEY]?: PaymentIdentifierExtension;
};

// rust `PaymentExtensions::is_empty`: no payment_identifier and no other
// keys. Callers use this to avoid emitting an empty `extensions: {}`.
export function extensionsIsEmpty(
  extensions: PaymentExtensions | undefined,
): boolean {
  if (!extensions) return true;
  return Object.keys(extensions).length === 0;
}

type PaymentSignatureEnvelope = {
  scheme?: string;
  network?: string;
  x402Version: number;
  accepted?: Record<string, unknown>;
  payload: PaymentProof;
  extensions?: PaymentExtensions;
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
// no top-level scheme/network, accepted echoes the offer. The optional
// `extensions` is the echoed-and-appended inbound extensions object; when
// undefined (or structurally empty) it is omitted entirely so the wire
// never carries an empty `extensions: {}` (rust skip_serializing_if =
// "Option::is_none" + PaymentExtensions::is_empty guidance).
export function buildPaymentHeaderV2(
  offer: X402Offer,
  transaction: string,
  extensions?: PaymentExtensions,
): string {
  return encodeEnvelope({
    x402Version: X402_VERSION_V2,
    accepted: toAcceptedValue(offer),
    payload: { transaction },
    extensions:
      extensions && !extensionsIsEmpty(extensions) ? extensions : undefined,
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
  // Surface the v2 extensions object. `hasExtensions` is false when the
  // key is absent OR present-but-empty (the echo-and-omit rule means a
  // conforming build never emits an empty `extensions: {}`, but a decoder
  // must still classify a stray `{}` as "no extensions").
  const extensions = env.extensions;
  if (extensions !== undefined && extensions !== null) {
    const keys = Object.keys(extensions).sort();
    shape.hasExtensions = keys.length > 0;
    shape.extensionKeys = keys;
    const pid = extensions[PAYMENT_IDENTIFIER_KEY] as
      | PaymentIdentifierExtension
      | undefined;
    shape.hasPaymentIdentifier = pid !== undefined;
    if (pid !== undefined) {
      if (pid.info?.required !== undefined) {
        shape.paymentIdentifierRequired = pid.info.required;
      }
      if (pid.info?.id !== undefined) {
        shape.paymentIdentifierId = pid.info.id;
      }
    }
  } else {
    // No extensions object on the wire (the conforming echo-and-omit
    // case). Pin the absence explicitly so a vector can assert it.
    shape.hasExtensions = false;
    shape.hasPaymentIdentifier = false;
    shape.extensionKeys = [];
  }
  return shape;
}

// A parsed offer selected from a v1/express 402 JSON body. Mirrors the
// subset of rust `PaymentRequirements` the client commits to after
// `parse_accepts_body` (client/exact/payment.rs:278-286): the legacy v1
// challenge carries `accepts[]` with `maxAmountRequired`/`payTo`/`asset`.
export type X402ParsedOffer = {
  network: string;
  amount: string;
  asset: string;
  payTo: string;
};

type V1ChallengeAccept = {
  scheme?: string;
  network?: string;
  // v1 amount field; v2 spelling `amount` also accepted for robustness.
  maxAmountRequired?: string;
  amount?: string;
  // v1 recipient field; legacy `recipient` also accepted.
  payTo?: string;
  recipient?: string;
  // v1 asset field; legacy `currency` also accepted.
  asset?: string;
  currency?: string;
};

type V1ChallengeBody = {
  x402Version?: number;
  error?: string;
  accepts?: V1ChallengeAccept[];
};

// Parse a v1 / x402-express 402 JSON BODY challenge into a selected offer.
// Mirrors rust `parse_accepts_body` field fallbacks
// (protocol/schemes/exact/types.rs:334-355): amount <- maxAmountRequired,
// recipient <- payTo, currency <- asset. Picks the first Solana `accepts`
// entry (the harness oracle uses single-offer v1 bodies). Returns
// `undefined` when the body has no usable Solana offer. RPC-free.
export function parseV1ChallengeBody(body: string): X402ParsedOffer | undefined {
  let parsed: V1ChallengeBody;
  try {
    parsed = JSON.parse(body) as V1ChallengeBody;
  } catch {
    return undefined;
  }
  const accepts = parsed.accepts;
  if (!Array.isArray(accepts) || accepts.length === 0) return undefined;
  const offer = accepts[0];
  const network = offer.network ?? "";
  const amount = offer.maxAmountRequired ?? offer.amount ?? "";
  const payTo = offer.payTo ?? offer.recipient ?? "";
  const asset = offer.asset ?? offer.currency ?? "";
  if (!network || !amount || !payTo || !asset) return undefined;
  return { network, amount, asset, payTo };
}

// Parse an x402 challenge from response headers AND/OR body, in the rust
// precedence order (client/exact/payment.rs:232-262): the v2
// PAYMENT-REQUIRED header first, then the v1 X-PAYMENT-REQUIRED header,
// then the v1/express body as the fallback. Returns the selected offer or
// `undefined`. Header values are standard base64 of the challenge JSON.
export function parseX402Challenge(
  headers: Array<[string, string]>,
  body: string | undefined,
): X402ParsedOffer | undefined {
  const find = (name: string): string | undefined =>
    headers.find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

  const v2Header = find(X402_V2_PAYMENT_REQUIRED_HEADER);
  if (v2Header) {
    try {
      const decoded = Buffer.from(v2Header, "base64").toString("utf8");
      const offer = parseV1ChallengeBody(decoded);
      if (offer) return offer;
    } catch {
      /* fall through to v1 header / body */
    }
  }

  const v1Header = find(X402_V1_PAYMENT_REQUIRED_HEADER);
  if (v1Header) {
    // The rust spine parses X-PAYMENT-REQUIRED as RAW JSON
    // (client/exact/payment.rs: serde_json::from_str on the header value),
    // not base64. Accept both: raw JSON first (rust parity), then a base64
    // envelope, so this oracle harnesserates with either producer.
    try {
      const offer = parseV1ChallengeBody(v1Header);
      if (offer) return offer;
    } catch {
      /* not raw JSON; try base64 */
    }
    try {
      const decoded = Buffer.from(v1Header, "base64").toString("utf8");
      const offer = parseV1ChallengeBody(decoded);
      if (offer) return offer;
    } catch {
      /* fall through to body */
    }
  }

  if (body) {
    const offer = parseV1ChallengeBody(body);
    if (offer) return offer;
  }

  return undefined;
}

export type X402ServerRoute = {
  network: string; // CAIP-2 or cluster slug; normalized via caip2NetworkForCluster
  recipient: string;
  currency: string;
  amount: string; // base units
  // When true the route advertised payment-identifier with
  // info.required=true: the credential MUST echo back a valid
  // `pay_`-shaped id or the server rejects.
  requiresPaymentIdentifier?: boolean;
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
    // Extensions reject gate: when the route requires a payment-identifier,
    // the echoed credential must carry a valid `pay_`-shaped id. Missing,
    // empty, or pattern-violating ids are rejected (coinbase spec: 400).
    if (route.requiresPaymentIdentifier) {
      const pid = env.extensions?.[PAYMENT_IDENTIFIER_KEY];
      const id = pid?.info?.id;
      if (id === undefined || id === "") {
        throw new Error(
          "payment-identifier required but credential echoed no id",
        );
      }
      if (!PAYMENT_IDENTIFIER_ID_PATTERN.test(id)) {
        throw new Error(
          `payment-identifier id is invalid: ${id} does not match ^[A-Za-z0-9_-]{16,128}$`,
        );
      }
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
