// TypeScript REFERENCE for the x402 `exact` intent conformance oracle.
//
// The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
// produces a base64(JSON) payment header and a SERVER verify consumes one.
// So the cross-SDK oracle is the DECODED ENVELOPE shape, not the signed
// Solana transaction inside `payload.transaction` (that is the harness
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

import {
  address,
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";
import { findAssociatedTokenPda } from "@solana-program/token";
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

// ── x402 v2 extensions (rust types.rs PaymentExtensions et al.) ──
//
// The `extensions` object rides on BOTH the inbound PAYMENT-REQUIRED
// challenge and the outbound PAYMENT-SIGNATURE credential. The client
// echoes the inbound object back, fills required client-side fields
// (e.g. payment-identifier.info.id), preserves unknown extensions
// verbatim (forward-compat echo-and-append, x402 v2 §5.1.2), and omits
// the object entirely when the server advertised none.
//
// The spec JSON key is kebab-case `payment-identifier` (rust
// `#[serde(rename = "payment-identifier")]`). `info` is camelCase
// `{ required?, id? }`; `schema?` is echoed verbatim.

export const PAYMENT_IDENTIFIER_KEY = "payment-identifier";

// rust `generate_payment_identifier_id`: `pay_` + 32 lowercase hex
// (36 total), satisfying the spec pattern ^[A-Za-z0-9_-]{16,128}$ and
// the canonical Solana ^pay_[a-zA-Z0-9_-]{10,120}$ shape.
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

export function generatePaymentIdentifierId(): string {
  // 16 random bytes -> 32 hex chars; `pay_` prefix. Mirrors rust.
  let hex = "";
  for (let i = 0; i < 16; i += 1) {
    hex += Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0");
  }
  return `pay_${hex}`;
}

// rust `PaymentExtensions::echoing`: deep-copy the inbound extensions
// blob so unknown keys round-trip verbatim. Returns undefined when the
// server advertised no extensions (so the outbound omits the object).
export function echoExtensions(
  inbound: PaymentExtensions | undefined | null,
): PaymentExtensions | undefined {
  if (inbound === undefined || inbound === null) return undefined;
  return JSON.parse(JSON.stringify(inbound)) as PaymentExtensions;
}

// rust `PaymentExtensions::requires_payment_identifier`:
// payment-identifier.info.required === true.
export function requiresPaymentIdentifier(
  extensions: PaymentExtensions | undefined,
): boolean {
  return extensions?.[PAYMENT_IDENTIFIER_KEY]?.info?.required === true;
}

// rust `PaymentExtensions::with_payment_identifier_id`: set the
// client-side id, creating the entry if the server did not advertise it,
// preserving server-side info (required) and schema verbatim.
export function withPaymentIdentifierId(
  extensions: PaymentExtensions | undefined,
  id: string,
): PaymentExtensions {
  const next: PaymentExtensions = extensions
    ? (JSON.parse(JSON.stringify(extensions)) as PaymentExtensions)
    : {};
  const entry = (next[PAYMENT_IDENTIFIER_KEY] ?? { info: {} }) as
    PaymentIdentifierExtension;
  entry.info = { ...entry.info, id };
  next[PAYMENT_IDENTIFIER_KEY] = entry;
  return next;
}

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
  resource?: unknown;
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

export function buildPaymentHeader(
  version: number,
  offer: X402Offer,
  transaction: string,
  extensions?: PaymentExtensions,
): string {
  return version === X402_VERSION_V1
    ? buildPaymentHeaderV1(offer, transaction)
    : buildPaymentHeaderV2(offer, transaction, extensions);
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
  resource?: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  decimals?: number;
  tokenProgram?: string;
  // When true the route advertised payment-identifier with
  // info.required=true: the credential MUST echo back a valid
  // `pay_`-shaped id or the server rejects.
  requiresPaymentIdentifier?: boolean;
};

function normalizedJson(value: unknown): string {
  const normalize = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(normalize);
    if (input && typeof input === "object") {
      const entries = Object.entries(input as Record<string, unknown>)
        .filter(
          ([key]) =>
            key !== "recentBlockhash" && key !== "lastValidBlockHeight",
        )
        .sort(([a], [b]) => a.localeCompare(b));
      return Object.fromEntries(entries.map(([key, val]) => [key, normalize(val)]));
    }
    return input;
  };
  return JSON.stringify(normalize(value));
}

function acceptedExtra(accepted: Record<string, unknown>): Record<string, unknown> {
  const extra = accepted.extra;
  if (extra && typeof extra === "object" && !Array.isArray(extra)) {
    return extra as Record<string, unknown>;
  }
  return {};
}

function assertAcceptedField(
  field: string,
  expected: unknown,
  actual: unknown,
): void {
  if (normalizedJson(actual) !== normalizedJson(expected)) {
    throw new Error(
      `Accepted ${field} mismatch: expected ${normalizedJson(expected)}, got ${normalizedJson(actual)}`,
    );
  }
}

// Verify a payment header against a server route. Mirrors the version
// dispatch + network gate in rust `parse_payment_signature` and the
// `accepted`-vs-route field comparison in `verify_envelope_payload`, including
// the structural fields Rust compares after the targeted amount/payTo/asset
// checks. Transient blockhash hints are ignored, matching strip_blockhash_hints.
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
    if (route.resource !== undefined) {
      assertAcceptedField("resource", route.resource, accepted.resource);
    }
    if (route.maxTimeoutSeconds !== undefined) {
      assertAcceptedField(
        "maxTimeoutSeconds",
        route.maxTimeoutSeconds,
        accepted.maxTimeoutSeconds,
      );
    }
    const extra = acceptedExtra(accepted);
    if (route.extra !== undefined) {
      assertAcceptedField("extra", route.extra, extra);
    }
    if (route.decimals !== undefined) {
      assertAcceptedField(
        "extra.decimals",
        route.decimals,
        extra.decimals ?? accepted.decimals,
      );
    }
    if (route.tokenProgram !== undefined) {
      assertAcceptedField(
        "extra.tokenProgram",
        route.tokenProgram,
        extra.tokenProgram ?? accepted.tokenProgram,
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

// ── x402 `exact` structural fund-safety verifier (TS reference) ──────────────
//
// A faithful port of the Rust spine `verify_exact_instructions`
// (rust/crates/kit/src/x402/protocol/schemes/exact/verify.rs). Decodes the
// base64 versioned transaction, runs the 11-rule structural pass, and throws
// an Error whose message is the canonical `invalid_exact_svm_payload_*` reject
// string — byte-identical to the Rust spine — so the cross-SDK vectors bind
// the exact reject code. There is no production TS x402 SDK in this tree, so
// this reference IS the TS contract every per-SDK exact runner is validated
// against.

const EXACT_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const EXACT_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const EXACT_COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
const EXACT_MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const EXACT_LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000n;

export type X402ExactRequirement = {
  asset: string;
  payTo: string;
  amount: string;
  extra?: { tokenProgram?: string; memo?: string };
};

type ExactCompiledInstruction = {
  accountIndices: readonly number[];
  data: Uint8Array;
  programAddressIndex: number;
};

type ExactCompiledMessage = {
  instructions: readonly ExactCompiledInstruction[];
  staticAccounts: readonly string[];
};

function u64Le(data: Uint8Array, offset: number): bigint {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getBigUint64(offset, true);
}

async function deriveAta(
  owner: string,
  mint: string,
  tokenProgram: string,
): Promise<string> {
  const [ata] = await findAssociatedTokenPda({
    mint: address(mint),
    owner: address(owner),
    tokenProgram: address(tokenProgram),
  });
  return String(ata);
}

const MANAGED_SIGNER_FUNDING_ERROR =
  "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds";

// A transferChecked multisig puts every required signer after the authority.
// Any server-managed signer in that tail could authorize the transfer. Its
// destination at position 2 is deliberately excluded: receiving funds does not
// authorize or source a transfer. The source itself must also not be a managed
// key or a managed key's ATA, derived with the transfer's real Token or
// Token-2022 program.
export async function assertNoManagedTransferFunding(
  accountIndices: readonly number[],
  staticAccounts: readonly string[],
  mint: string,
  transferProgram: string,
  managedSigners: readonly string[],
): Promise<void> {
  const keyAt = (index: number): string => staticAccounts[index] ?? "";
  const source = keyAt(accountIndices[0]);
  const managed = new Set(managedSigners);

  for (const accountIndex of accountIndices.slice(3)) {
    if (managed.has(keyAt(accountIndex))) {
      throw new Error(MANAGED_SIGNER_FUNDING_ERROR);
    }
  }

  for (const signer of managed) {
    if (source === signer) {
      throw new Error(MANAGED_SIGNER_FUNDING_ERROR);
    }
    try {
      if (source === (await deriveAta(signer, mint, transferProgram))) {
        throw new Error(MANAGED_SIGNER_FUNDING_ERROR);
      }
    } catch (error) {
      if (error instanceof Error && error.message === MANAGED_SIGNER_FUNDING_ERROR) {
        throw error;
      }
      // Invalid configured signer keys cannot derive an ATA and therefore
      // cannot match the transaction's decoded source key.
    }
  }
}

// Run the 11-rule exact structural pass over a base64 versioned transaction.
// Resolves on accept; rejects with a canonical `invalid_exact_svm_payload_*`
// Error on the first rule failure.
export async function verifyExactTransaction(
  transactionBase64: string,
  requirement: X402ExactRequirement,
  managedSigners: string[],
): Promise<void> {
  const txBytes = getBase64Codec().encode(transactionBase64);
  const decoded = getTransactionDecoder().decode(txBytes);
  const message = getCompiledTransactionMessageDecoder().decode(
    decoded.messageBytes,
  ) as unknown as ExactCompiledMessage;

  const keys = message.staticAccounts.map(String);
  const ixs = message.instructions;
  const keyAt = (index: number): string => keys[index] ?? "";
  const programOf = (ix: ExactCompiledInstruction): string =>
    keyAt(ix.programAddressIndex);

  // Rule 1: instruction count 3..=6.
  if (ixs.length < 3 || ixs.length > 6) {
    throw new Error("invalid_exact_svm_payload_transaction_instructions_length");
  }

  // Rule 2: ix[0] = ComputeBudget SetComputeUnitLimit (disc 2, 5 bytes).
  const limit = ixs[0];
  if (
    programOf(limit) !== EXACT_COMPUTE_BUDGET_PROGRAM ||
    limit.data.length !== 5 ||
    limit.data[0] !== 2
  ) {
    throw new Error(
      "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
    );
  }

  // Rule 3: ix[1] = ComputeBudget SetComputeUnitPrice (disc 3, 9 bytes, <= MAX).
  const price = ixs[1];
  if (
    programOf(price) !== EXACT_COMPUTE_BUDGET_PROGRAM ||
    price.data.length !== 9 ||
    price.data[0] !== 3
  ) {
    throw new Error(
      "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
    );
  }
  if (u64Le(price.data, 1) > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS) {
    throw new Error(
      "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
    );
  }

  // Rules 4-8 + 11: transferChecked at ix[2].
  const transfer = ixs[2];
  const transferProgram = programOf(transfer);
  if (
    transferProgram !== EXACT_TOKEN_PROGRAM &&
    transferProgram !== EXACT_TOKEN_2022_PROGRAM
  ) {
    throw new Error("invalid_exact_svm_payload_no_transfer_instruction");
  }
  if (
    transfer.accountIndices.length < 4 ||
    transfer.data.length !== 10 ||
    transfer.data[0] !== 12
  ) {
    throw new Error("invalid_exact_svm_payload_no_transfer_instruction");
  }
  const source = keyAt(transfer.accountIndices[0]);
  const mint = keyAt(transfer.accountIndices[1]);
  const destination = keyAt(transfer.accountIndices[2]);

  // Rule 5: reject managed authorities, multisig signer tails, direct sources,
  // and managed ATAs. Mirrors Go/Rust's exact transfer verifier.
  await assertNoManagedTransferFunding(
    transfer.accountIndices,
    keys,
    mint,
    transferProgram,
    managedSigners,
  );

  // Rule 6: mint match.
  if (mint !== requirement.asset) {
    throw new Error("invalid_exact_svm_payload_mint_mismatch");
  }

  // Rule 7: destination ATA match (re-derive owner+mint+program).
  const expectedDestination = await deriveAta(
    requirement.payTo,
    requirement.asset,
    transferProgram,
  );
  if (destination !== expectedDestination) {
    throw new Error("invalid_exact_svm_payload_recipient_mismatch");
  }

  // Rule 8: amount match.
  if (u64Le(transfer.data, 1) !== BigInt(requirement.amount)) {
    throw new Error("invalid_exact_svm_payload_amount_mismatch");
  }

  // Rule 9: ix[3..] allowlist (Memo / Lighthouse only), positional reject codes.
  const reasons = [
    "invalid_exact_svm_payload_unknown_fourth_instruction",
    "invalid_exact_svm_payload_unknown_fifth_instruction",
    "invalid_exact_svm_payload_unknown_sixth_instruction",
  ];
  for (let i = 3; i < ixs.length; i += 1) {
    const program = programOf(ixs[i]);
    if (program === EXACT_MEMO_PROGRAM || program === EXACT_LIGHTHOUSE_PROGRAM) {
      continue;
    }
    throw new Error(
      reasons[i - 3] ??
        "invalid_exact_svm_payload_unknown_optional_instruction",
    );
  }

  // Rule 10: memo binding (exactly one Memo == extra.memo when the offer pins it).
  const expectedMemo = requirement.extra?.memo;
  if (expectedMemo !== undefined && expectedMemo !== "") {
    let memoCount = 0;
    let lastMemo: string | undefined;
    for (let i = 3; i < ixs.length; i += 1) {
      if (programOf(ixs[i]) === EXACT_MEMO_PROGRAM) {
        memoCount += 1;
        lastMemo = new TextDecoder().decode(ixs[i].data);
      }
    }
    if (memoCount !== 1) {
      throw new Error("invalid_exact_svm_payload_memo_count");
    }
    if (lastMemo !== expectedMemo) {
      throw new Error("invalid_exact_svm_payload_memo_mismatch");
    }
  }
}
