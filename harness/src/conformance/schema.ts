// Conformance-vector schema for the deterministic cross-SDK parity layer.
//
// A vector is a single declarative case that every SDK's conformance
// runner must agree on. The oracle is the DECODED SEMANTIC SHAPE of a
// built/verified transaction (fee payer, transfer set, forbidden
// programs, compute caps, memo) -- NOT raw transaction bytes, because
// signatures and account ordering can legitimately differ across SDKs
// while still conforming. The one exception is the `canonical-bytes`
// mode, which DOES pin exact bytes for header / JCS / base64url vectors
// where byte-for-byte agreement is the whole point.
//
// See harness/vectors/README.md for authoring guidance.

export type VectorMode = "build-transaction" | "verify-transaction" | "canonical-bytes";

export type VectorOutcome = "accept" | "reject";

// A runner may additionally report that it has no equivalent for a vector's
// mode (e.g. a server-only SDK asked to build a transaction). This is NOT a
// conformance failure: the driver SKIPs the vector for that runner. It is
// distinct from "reject", which is a genuine, asserted policy decision.
export type RunnerOutcome = VectorOutcome | "unsupported-mode";

export type VectorSplit = {
  recipient: string;
  amount: string;
  ataCreationRequired?: boolean;
  memo?: string;
};

// The decoded charge offer/request a build/verify vector operates on.
// Field omission is intentional and meaningful: a missing `decimals`
// must default to 6, a missing `tokenProgram` must default by currency,
// etc. Runners MUST NOT inject defaults the SDK would not.
export type VectorChargeRequest = {
  amount: string;
  currency: string;
  externalId?: string;
  recipient?: string;
  // Top-level precedence twins. When present these win over the
  // methodDetails copies; a vector can set conflicting values to pin
  // which one the SDK honors.
  payTo?: string;
  asset?: string;
  methodDetails?: {
    network?: string;
    decimals?: number;
    tokenProgram?: string;
    recentBlockhash?: string;
    feePayer?: boolean;
    feePayerKey?: string;
    splits?: VectorSplit[];
  };
  // Build-time compute budget overrides. Used by reject vectors that
  // exercise the server-side compute-unit-price / limit caps: the runner
  // builds a transaction carrying these values, then the verify path must
  // reject it.
  computeUnitLimit?: number;
  computeUnitPrice?: string;
};

export type VectorRpcFixtures = {
  // Pinned blockhash so the build path needs no live RPC.
  recentBlockhash?: string;
  // mint pubkey -> owning token program. Lets the build/verify path
  // resolve a token program without an RPC getAccountInfo call when the
  // vector omits methodDetails.tokenProgram.
  mintOwners?: Record<string, string>;
};

// The decoded semantic shape of an x402 `exact` envelope. This is the
// x402 oracle: a CLIENT build emits a base64(JSON) payment header and a
// SERVER verify consumes one, so the cross-SDK contract is the DECODED
// ENVELOPE shape, never raw transaction bytes (the signed Solana
// transaction inside `payload.transaction` is the harness matrix's job).
//
// v2 (canonical): { x402Version: 2, accepted: <offer object>, payload: { transaction } }
//   header PAYMENT-SIGNATURE; no top-level scheme/network.
// v1 (legacy):    { x402Version: 1, scheme: "exact", network: <legacy slug>, payload: { transaction } }
//   header X-PAYMENT; no `accepted`.
//
// Field presence is meaningful: `hasAccepted` MUST be true for v2 and
// false for v1; `scheme`/`network` MUST be present for v1 and absent for
// v2. `accepted*` echoes the offer the client committed to (v2 only).
export type X402EnvelopeShape = {
  x402Version: number;
  // v1 only: top-level scheme ("exact") + legacy network slug
  // ("solana-devnet" for devnet, else "solana"). Absent on v2.
  scheme?: string;
  network?: string;
  // True iff the envelope carries a v2 `accepted` offer object.
  hasAccepted: boolean;
  // True iff payload carries a base64 signed-transaction proof.
  payloadHasTransaction: boolean;
  // v2 only: the offer fields the client echoed back. Asserted so a
  // build that drops/rewrites the offer is caught.
  acceptedScheme?: string;
  acceptedNetwork?: string;
  acceptedAsset?: string;
  acceptedPayTo?: string;
  acceptedAmount?: string;
  // ── v2 extensions (rust PaymentExtensions) ──
  // True iff the envelope carries a non-empty `extensions` object. A v2
  // build that the server advertised no extensions for MUST NOT emit an
  // empty `extensions: {}`, so this is false in that case (echo-and-omit).
  hasExtensions?: boolean;
  // True iff `extensions["payment-identifier"]` is present.
  hasPaymentIdentifier?: boolean;
  // `extensions["payment-identifier"].info.required`, surfaced verbatim.
  paymentIdentifierRequired?: boolean;
  // `extensions["payment-identifier"].info.id`, surfaced verbatim. Lets a
  // vector assert the client generated/echoed a `pay_`-shaped id.
  paymentIdentifierId?: string;
  // The exact key list the outbound `extensions` carries, sorted. Pins
  // the echo-and-append rule: an unknown server extension must survive
  // verbatim alongside `payment-identifier`.
  extensionKeys?: string[];
};

// An x402 `exact` offer (the server's PaymentRequirements / the v2
// `accepted` object). Drives both build (client picks this offer and
// wraps it) and verify (server's route requirements). Field omission is
// meaningful: a missing `maxTimeoutSeconds` defaults to 300, a missing
// `extra` serializes as `{}` in the canonical accepted shape.
export type X402Offer = {
  scheme?: string;
  // CAIP-2 network identifier, e.g. "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".
  network: string;
  // Base units integer string (NOT the human price).
  amount: string;
  // Mint address (or "SOL").
  asset: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
};

export type TransactionShape = {
  feePayer?: string;
  transfers?: Array<{
    kind: "spl" | "sol";
    destination?: string;
    destinationOwner?: string;
    mint?: string;
    amount: string;
    decimals?: number;
    tokenProgram?: string;
  }>;
  // Programs that MUST NOT appear in the transaction.
  forbiddenPrograms?: string[];
  maxComputeUnitLimit?: number;
  maxComputeUnitPrice?: string;
  memo?: string[];
};

export type VectorExpect = {
  outcome: VectorOutcome;
  // For build/verify accept vectors: the decoded semantic shape to assert.
  transactionShape?: TransactionShape;
  // For x402-exact build/verify accept vectors: the decoded envelope shape.
  x402EnvelopeShape?: X402EnvelopeShape;
  // For canonical-bytes vectors: the exact bytes the SDK must produce.
  exactBytes?: {
    canonicalJson?: string;
    base64Url?: string;
    // Raw byte array (e.g. a 48-byte vector) the runner emits as numbers.
    bytes?: number[];
  };
  // Optional human-readable reason for reject vectors; not asserted, just
  // documents the divergence class.
  rejectReason?: string;
  // Normalized reject category asserted across every SDK. Pins WHY the SDK
  // rejected, not just that it did, so a guard that fires for the wrong
  // reason (e.g. a decimals-mismatch caught only by a generic
  // no-matching-transfer fallback) is flagged. Runners map their native
  // error taxonomy onto this shared vocabulary.
  rejectCode?: RejectCode;
};

// Shared reject vocabulary. Each runner maps its native error onto one of
// these so the harness can assert the SAME category across all SDKs.
export type RejectCode =
  | "compute-price-over-cap"
  | "compute-limit-over-cap"
  | "fee-payer-not-authority"
  | "fee-payer-is-funds-source"
  | "decimals-mismatch"
  | "splits-exceed-amount"
  | "too-many-splits"
  | "unexpected-instruction"
  | "no-matching-transfer"
  | "amount-mismatch"
  | "invalid-payload"
  // x402-exact: the envelope carried an x402Version the server does not
  // support (anything other than 1 or 2).
  | "unsupported-version"
  // x402-exact: the credential's network does not match the server's
  // configured network (v1 legacy slug or v2 accepted.network).
  | "wrong-network"
  // x402-exact extensions: the server advertised payment-identifier with
  // info.required=true but the credential echoed no valid `pay_`-shaped
  // id (missing, empty, or pattern-violating). The coinbase spec maps
  // this to HTTP 400; the conformance oracle pins it as a reject category.
  | "payment-identifier-required";

export type VectorInput = {
  // build-transaction / verify-transaction
  request?: VectorChargeRequest;
  // verify-transaction: the base64 wire transaction to verify. When
  // omitted, the runner builds one from `request` first (so a single
  // vector can assert "build then verify accepts the build output").
  transaction?: string;
  // Ed25519 secret key (64-byte array) for the transfer authority / signer.
  signerSecretKey?: number[];
  rpcFixtures?: VectorRpcFixtures;
  // canonical-bytes: the JSON value to canonicalize, OR the raw input for
  // a base64url / fixed-width byte vector.
  value?: unknown;
  // canonical-bytes: a base58 or hex string the runner base64url-encodes.
  encodeBase64Url?: { hexBytes?: string; utf8?: string };
  // canonical-bytes: MPP charge challenge-id HMAC derivation. The runner
  // computes base64url(HMAC-SHA256(secretKey, realm|method|intent|request|
  // expires|digest|opaque)) with absent optionals joined as empty strings,
  // and emits it as exactBytes.base64Url. This pins cross-SDK challenge-id
  // agreement byte-for-byte: two SDKs that compute a different id from the
  // same inputs are caught here, not buried behind a live-server roundtrip.
  // Mirrors rust `compute_challenge_id` (protocol/core/challenge.rs).
  challengeId?: {
    secretKey: string;
    realm: string;
    method: string;
    intent: string;
    request: string;
    expires?: string;
    digest?: string;
    opaque?: string;
  };

  // canonical-bytes (session): the 50-byte Ed25519 voucher preimage
  // `magic([0x56, 0x01]) || channelId(32, base58) || cumulativeAmount LE u64
  // || expiresAt LE i64`. The runner emits it as exactBytes
  // (hex/bytes/base64Url). This pins the single most load-bearing session
  // invariant byte-for-byte across SDKs. Mirrors the program
  // voucher_message_bytes layout.
  voucherPreimage?: {
    channelId: string;
    cumulativeAmount: string;
    /** Omitted means never-expires; the SDK must encode 0 verbatim. */
    expiresAt?: number;
  };

  // canonical-bytes (session): the UTF-8 JSON message a payer signs to mint
  // a reusable SessionAuthentication proof. The runner drives the
  // PRODUCTION SDK message builder (never a local re-implementation) and
  // emits the bytes as exactBytes.canonicalJson/base64Url. Pins the domain
  // constant, the field names, and the key order:
  // `{"channelId":…,"domain":"mpp-session-auth-v1","payer":…,
  //   "sessionChallengeId":…}` (compact, keys sorted — JCS-equivalent for
  // these all-string values).
  sessionAuthenticationMessage?: {
    challengeId: string;
    payer: string;
    channelId: string;
  };

  // canonical-bytes (session): a session wire-shape round-trip. The runner
  // DECODES `value` with the production SDK wire parser for `shape`
  // ("request" = the challenge SessionRequest incl. methodDetails;
  // "action" = the credential payload tagged union open/voucher/use/topUp/
  // close), RE-ENCODES it with the production serializer, JCS-canonicalizes
  // the result, and emits exactBytes.canonicalJson/base64Url. Accept
  // vectors carry exactly-canonical wire JSON, so any SDK that renames,
  // drops, or retypes a field diverges from the frozen bytes; reject
  // vectors pin the shapes every SDK must refuse (superseded draft field
  // names, unknown enum values, wrong action tags) with rejectCode
  // "invalid-payload".
  sessionWire?: {
    shape: "request" | "action";
    value: unknown;
  };

  // ── x402-exact inputs ────────────────────────────────────────────────
  // build-transaction (x402): the offer the client selects + wraps into a
  // payment header. The runner emits the decoded X402EnvelopeShape.
  x402Offer?: X402Offer;
  // build-transaction (x402): which wire version to build (1 = legacy
  // X-PAYMENT, 2 = canonical PAYMENT-SIGNATURE). Required for x402 builds.
  x402Version?: 1 | 2;
  // build-transaction (x402): a pinned base64 transaction proof so the
  // build path is deterministic and RPC-free. The conformance oracle is
  // the envelope shape, not the signed-transaction bytes; a real SDK
  // signs a Solana tx here, verified by the harness matrix.
  x402PinnedTransaction?: string;
  // verify-transaction (x402): the server's configured route. The server
  // verifies the submitted `paymentHeader` against this network/recipient/
  // amount/asset and accepts or rejects.
  x402ServerNetwork?: string;
  x402ServerRecipient?: string;
  x402ServerCurrency?: string;
  x402ServerAmount?: string;
  // verify-transaction (x402): the base64 PAYMENT-SIGNATURE / X-PAYMENT
  // header value the server must verify. Pinned so verify needs no build.
  x402PaymentHeader?: string;

  // ── x402-exact extensions inputs (rust PaymentExtensions) ────────────
  // build-transaction (x402): the `extensions` object the server
  // advertised on the inbound PAYMENT-REQUIRED. The client echoes it,
  // preserving unknown keys verbatim. Omit to assert the echo-and-omit
  // rule (no empty `extensions: {}` on the outbound).
  x402AdvertisedExtensions?: Record<string, unknown>;
  // build-transaction (x402): a pinned `pay_`-shaped id the client must
  // populate into payment-identifier.info.id (so the build is
  // deterministic; a real client calls generatePaymentIdentifierId()).
  // When omitted and the advertised payment-identifier requires an id,
  // the runner generates one and the vector asserts only the pattern.
  x402PaymentIdentifierId?: string;
  // verify-transaction (x402): when true, the server route requires a
  // payment-identifier id. The server rejects the credential if the
  // echoed `extensions["payment-identifier"].info.id` is missing or does
  // not match ^[A-Za-z0-9_-]{16,128}$.
  x402ServerRequiresPaymentIdentifier?: boolean;
};

export type ConformanceVector = {
  id: string;
  intent: "charge" | "x402-exact" | "session";
  mode: VectorMode;
  description?: string;
  input: VectorInput;
  expect: VectorExpect;
};

// `RunnerOutcome` (declared near the top of this file) is the per-runner
// outcome including the `unsupported-mode` skip signal.

// The result a runner emits to stdout for one vector.
export type RunnerResult = {
  id: string;
  // "accept" | "reject" assert against the vector's expect block;
  // "unsupported-mode" tells the driver to SKIP this vector for the runner.
  outcome: RunnerOutcome;
  // Present on build/verify accept. The decoded semantic shape.
  transactionShape?: TransactionShape;
  // Present on x402-exact build/verify accept. The decoded envelope shape.
  x402EnvelopeShape?: X402EnvelopeShape;
  // Present on canonical-bytes.
  exactBytes?: {
    canonicalJson?: string;
    base64Url?: string;
    bytes?: number[];
  };
  // Present on reject: the runner's reject message (for diagnostics).
  error?: string;
  // Present on reject: the normalized category the runner mapped its native
  // error onto. Asserted against VectorExpect.rejectCode when both are set.
  rejectCode?: RejectCode;
};
