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
// Field omission is intentional and meaningful: a mint challenge without
// `decimals` must be refused, and a missing `tokenProgram` must be resolved
// from the mint account via the fixture RPC (RULINGS C2, C3). Runners pass
// the request to the SDK verbatim and MUST NOT inject defaults.
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
  // Chain blockhash served by getLatestBlockhash. Defaults to the
  // challenge's methodDetails.recentBlockhash.
  recentBlockhash?: string;
  // mint address -> account served by getAccountInfo / getMultipleAccounts
  // (82-byte SPL mint layout). A mint absent here does not exist, so an SDK
  // that must look it up (tokenProgram omitted, x402 decimals) has to reject.
  mints?: Record<string, { owner: string; decimals: number }>;
  // address -> raw program account (payment channel, subscription plan, ...)
  // served verbatim; data is the account's exact bytes, base64. lamports
  // defaults to the rent-exempt minimum for the data length.
  accounts?: Record<string, { owner: string; data: string; lamports?: number }>;
  // Slot served by getSlot and as every response's context.slot.
  slot?: number;
  lastValidBlockHeight?: number;
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
  | "payment-identifier-required"
  // charge / x402 client: the challenge itself violates the method spec
  // (e.g. decimals missing for a mint, tokenProgram omitted and the mint
  // lookup failed or returned an unexpected owner) and must be refused.
  | "invalid-challenge"
  // session voucher verify: a non-zero expiry at/before now.
  | "voucher-expired"
  // session voucher verify: a non-zero expiry at/before now + settlement
  // window (the boundary is exclusive).
  | "voucher-expires-before-settlement"
  // x402-exact v2: the credential's `accepted` matches none of the route's
  // payment requirements (amount, payTo, asset or network differ). Covers
  // both targeted field checks and a structural match against the offers.
  | "accepted-mismatch"
  // x402-upto verify: the client payload carries voucherSignature (claim-only, server-owned).
  | "unexpected-voucher"
  // x402-upto verify: the client payload carries the per-settle `type`.
  | "unexpected-type"
  // x402-upto deposit: an account already exists at payload.channelId.
  | "channel-already-open"
  // x402-upto verify: maxTimeoutSeconds or expiresAt - now exceeds the facilitator's maxChannelLifetimeSecs.
  | "channel-lifetime-exceeded"
  // x402-upto verify: expiresAt is later than now + maxTimeoutSeconds (plus skew).
  | "expires-at-mismatch"
  // x402-upto verify: now < validAfter.
  | "not-yet-active"
  // x402-upto verify: payload.deposit differs from maxAmount.
  | "deposit-not-ceiling"
  // x402-upto verify: payload.authorizedSigner is not extra.receiverAuthorizer.
  | "receiver-authorizer-mismatch"
  // x402-upto verify: the PDA rederived from the open differs from the open's channel account or payload.channelId.
  | "channel-id-mismatch"
  // x402-upto verify: an open account, privilege or argument violates its required binding (payer, rent payer, payee, mint, token accounts, programs, salt, deposit, grace period, open slot, distribution, 14 accounts, no trailing bytes).
  | "open-binding-mismatch"
  // subscription server: the echoed challenge was not issued by this server or does not match the route (HMAC id, realm, method, intent, plan, program, terms).
  | "challenge-mismatch"
  // subscription server: the activation challenge's `expires` is at or before now.
  | "challenge-expired"
  // subscription server: `subscriptionExpires` is at or before now.
  | "subscription-expired"
  // subscription: the bearer proof is missing, bound to another challenge, payer or delegation, or its Ed25519 signature does not verify.
  | "authentication-invalid"
  // subscription server: the first-period charge goes to a receiver ATA not owned by `recipient`.
  | "recipient-mismatch"
  // subscription server: the subscribe / transfer_subscription pair is missing, misordered, or binds another plan, puller, subscriber, amount or mint than the challenge.
  | "activation-scope"
  // subscription server: the activation fee payer is not `feePayerKey` (sponsored) or the subscriber (unsponsored).
  | "fee-payer-mismatch"
  // subscription server: the on-chain delegation is not usable at now (missing, foreign, cancelled, unpaid period, authority invalidated).
  | "subscription-inactive"
  // subscription server: the credential `source` is not the did:pkh:solana of the activation subscriber.
  | "source-mismatch"
  | "unsupported-scheme"
  | "payload-type"
  | "payment-flow"
  | "token-program"
  | "voucher-signature"
  | "receiver-binding-unavailable"
  | "close-authorization"
  | "close-amount-unsupported"
  | "close-state"
  | "channel-closing"
  | "withdraw-delay-mismatch"
  | "withdraw-delay-out-of-range"
  | "cumulative-amount-mismatch"
  | "cumulative-exceeds-deposit"
  | "voucher-expiry"
  | "setup-transaction"
  | "settlement-simulation"
  | "channel-state"
  | "refund-transaction"
  | "duplicate-settlement"
  // charge verify, fee-sponsored: the payment legs are funded by more than
  // one authority, so the sponsor pays a signature fee for each.
  | "mixed-funding-authority"
  // charge verify, fee-sponsored: a required signer that is neither the fee
  // payer nor the payment's funding authority.
  | "unexpected-signer";

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
  // Injected by the driver, never authored: URL of a fixture JSON-RPC
  // server built from rpcFixtures (rust/crates/conformance/src/fixture_rpc.rs). Runners
  // MUST pass it to their SDK as the RPC endpoint and MUST NOT resolve
  // chain state (token programs, decimals) themselves.
  rpcUrl?: string;
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

  // verify-transaction (session): one voucher against a fresh channel
  // (cumulative 0, authorizedSigner = pubkey of `signerSecretKey`). The
  // runner signs the voucher preimage with `signerSecretKey` and drives the
  // PRODUCTION server voucher verifier at the pinned clock. Accept means the
  // verifier advanced the watermark; a reject maps the verifier's reason to
  // voucher-expired / voucher-expires-before-settlement.
  sessionVoucherVerify?: {
    channelId: string;
    cumulativeAmount: string;
    expiresAt: number;
    nowSeconds: number;
    settlementWindowSeconds: number;
    deposit: string;
  };

  // ── x402-exact inputs ────────────────────────────────────────────────
  // build-transaction (x402): the offer the client selects + wraps into a
  // payment header. The runner emits the decoded X402EnvelopeShape.
  x402Offer?: X402Offer;
  // build-transaction (x402): which wire version to build (1 = legacy
  // X-PAYMENT, 2 = canonical PAYMENT-SIGNATURE). Required for x402 builds.
  x402Version?: 1 | 2;
  // DEPRECATED, absent from every vector: builds must sign a real
  // transaction. Kept only until the TypeScript runner stops reading it.
  x402PinnedTransaction?: string;
  // verify-transaction (x402): the server's configured route. The server
  // verifies the submitted `paymentHeader` against this network/recipient/
  // amount/asset and accepts or rejects.
  x402ServerNetwork?: string;
  x402ServerRecipient?: string;
  x402ServerCurrency?: string;
  x402ServerAmount?: string;
  // verify-transaction (x402): the base64 PAYMENT-SIGNATURE / X-PAYMENT
  // header value the server must verify. Its payload carries a real,
  // partially signed transaction the SDK verifier must inspect (RULINGS S3).
  x402PaymentHeader?: string;
  // verify-transaction (x402): the server's fee payer, which the
  // transaction names as message fee payer with an empty signature slot.
  x402ServerFeePayer?: string;
  x402ServerFeePayerSecretKey?: number[];

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
  // verify-transaction (x402): the route's `extra.memo`. When present the
  // verifier MUST require exactly one Memo instruction carrying it
  // (scheme_exact_svm §3.1), and the route's accepted object carries it.
  x402ServerMemo?: string;

  // The pinned clock (Unix seconds) of a time-dependent vector; a testee
  // that honours clocks drives the SDK at it.
  nowSeconds?: number;

  // ── x402-upto inputs (scheme_upto_svm.md) ────────────────────────────
  // build: x402Offer is an upto PaymentRequirements whose extra carries the
  // recentBlockhash / recentSlot hints (no live RPC). The remaining build
  // keys are caller parameters for SDKs whose builder takes them; an SDK
  // that derives them itself (the TS client: expiresAt = now +
  // maxTimeoutSeconds, a random salt) ignores them, and the judge accepts
  // any value the Rust verifier accepts.
  x402UptoExpiresAt?: number;
  x402UptoRequestNonce?: string;
  // build: the highest message version the client's signer signs (0 or 1).
  x402ClientMaxTransactionVersion?: number;
  // verify: the route (with the x402-exact x402Server* keys above, amount in
  // base units = the authorized maximum). The receiver authorizer is the
  // channel's authorized signer (servers that sign vouchers configure its
  // secret); withdraw delay and timeout are advertised in the requirement.
  x402ServerReceiverAuthorizer?: string;
  x402ServerReceiverAuthorizerSecretKey?: number[];
  x402ServerTokenProgram?: string;
  x402ServerWithdrawDelay?: number;
  x402ServerMaxTimeoutSeconds?: number;
  // verify: the facilitator's maxChannelLifetimeSecs.
  x402ServerMaxChannelLifetimeSeconds?: number;
  // verify: the route's declared extra.memo (x402ServerMemo) is the memo of
  // this canonical request identity; SDKs that derive the memo from the
  // route (Rust `X402Upto::route_memo`) take the route.
  x402ServerRoute?: string;
  // canonical-bytes: the 50-byte voucher message, the distribution hash and
  // the channel PDA (32 bytes each), as exactBytes.bytes.
  x402UptoVoucher?: { channelId: string; cumulativeAmount: string; expiresAt?: number };
  x402UptoDistribution?: { recipients: Array<{ recipient: string; bps: number }> };
  x402UptoChannelPda?: {
    payer: string;
    payee: string;
    mint: string;
    authorizedSigner: string;
    salt: string;
    openSlot: string;
  };
  // ── subscription inputs (rust/crates/conformance/src/realize/subscription.rs)
  // (time-dependent subscription verdicts use nowSeconds above)
  // canonical-bytes: the bearer-proof message the subscriber signs (JCS of
  // {domain, payer, subscriptionChallengeId, subscriptionDelegation}).
  subscriptionAuthenticationMessage?: {
    challengeId: string;
    payer: string;
    subscriptionDelegation: string;
  };
  // canonical-bytes: a billing period mapped to period_hours, emitted as
  // the JCS of {"periodHours": n}.
  subscriptionPeriod?: { periodUnit: string; periodCount: string };
  // canonical-bytes: the SubscriptionDelegation / SubscriptionAuthority PDA,
  // emitted as the JCS of {"address": base58}.
  subscriptionPda?: {
    kind: "delegation" | "authority";
    subscriber: string;
    subscriptionProgram: string;
    planAddress?: string;
    mint?: string;
  };
  // canonical-bytes: subscribe / transfer_subscription instruction data.
  subscriptionInstruction?: Record<string, unknown>;
  // canonical-bytes: a request ("request") or credential payload
  // ("activation", "access") through the SDK's wire types, re-encoded as JCS.
  subscriptionWire?: { shape: "request" | "activation" | "access"; value: unknown };
  // build-transaction: the challenge the client signs an activation for
  // (request decoded); chain state (Plan, SubscriptionAuthority) comes from
  // rpcFixtures.accounts.
  subscriptionChallenge?: {
    id: string;
    realm: string;
    method: string;
    intent: string;
    expires?: string;
    request: Record<string, unknown>;
  };
  // verify-transaction: the server route.
  subscriptionServer?: {
    realm: string;
    secretKey: string;
    planAddress: string;
    mint: string;
    decimals: number;
    tokenProgram: string;
    puller: string;
    recipient: string;
    periodUnit: string;
    periodCount: number;
    amount: string;
    network: string;
    subscriptionProgram: string;
    feePayerKey?: string;
  };
  // verify-transaction: the sponsor's key when the route pays fees.
  subscriptionServerFeePayerSecretKey?: number[];
  // verify-transaction: the activation credential, an Authorization header
  // value ("Payment <base64url JCS credential>"), verified up to broadcast.
  subscriptionAuthorization?: string;
  // verify-transaction: check the on-chain delegation of `subscriber` at
  // nowSeconds against the route.
  subscriptionActive?: { subscriber: string; amount: string };
  // verify-transaction: a bearer proof against a delegation address.
  subscriptionProof?: { authentication: unknown; subscriptionDelegation: string };
  // ── transaction versions (SIMD-0385; charge, session, x402-exact) ───
  // build-transaction: the highest Solana message version the client's
  // signer can sign (0 or 1; a hardware wallet may sign version 0 only).
  // The runner hands it to the SDK builder's own option; the builder MUST
  // build the highest advertised version within it and refuse
  // (rejectCode "unsupported-version") when none is buildable. Absent: no
  // limit below what the counterparty advertises. The versions a charge or
  // session server accepts are its challenge's
  // `methodDetails.transactionVersions` (`[0]` when absent); charge verify
  // runners configure the server from it.
  signerMaxTransactionVersion?: 0 | 1;
  // verify-transaction (x402): the sponsor's own accepted message versions
  // (scheme_exact_svm §1.5: "The sponsor enforces its own accepted set";
  // absent means [0]). The route advertises them as
  // `extra.transactionVersions` and the vector's `accepted` echoes them.
  x402ServerTransactionVersions?: Array<0 | 1>;
  // canonical-bytes (charge): an MPP charge request round-trip. The runner
  // DECODES `value` with the production SDK charge-request type (incl.
  // typed methodDetails), RE-ENCODES it, JCS-canonicalizes the result and
  // emits exactBytes.canonicalJson/base64Url; a value the type refuses is
  // rejectCode "invalid-payload". Mirrors `sessionWire`.
  chargeWire?: { value: unknown };
  // canonical-bytes (x402-exact): one `accepts[]` PaymentRequirements
  // round-tripped through the production SDK requirements type, as
  // `chargeWire`.
  x402Wire?: { value: unknown };
  // verify-transaction (session): a client-submitted `open`. The runner
  // configures its SDK's session server from `server` (client vouchers,
  // client-paid opens; `transactionVersions` is the set it accepts and
  // advertises, [0] when absent) and runs the server's checks on `open`
  // (the credential's open action, its transaction built by the Rust kit's
  // client, possibly mutated) against the challenged `challengedBlockhash`,
  // before any co-sign or broadcast. Accept means the open would be
  // broadcast.
  sessionOpenVerify?: {
    server: {
      operator: string;
      recipient: string;
      currency: string;
      decimals: number;
      network: string;
      amount: string;
      minimumDeposit?: string;
      suggestedDeposit?: string;
      gracePeriodSeconds?: number;
      transactionVersions?: Array<0 | 1>;
    };
    challengedBlockhash: string;
    open: Record<string, unknown>;
  };
};

// Where a vector's rule is written down. `doc` is `<repo>/<path>` inside a
// pinned spec repository: `mpp-specs/...` (external/mpp-specs), `x402/...`
// (typescript/external/x402), or an unmerged draft (`mpp-specs-solana/`,
// `mpp-specs-txv1/`, `x402-txv1/`, under external/). `quote` appears verbatim (whitespace and
// markdown emphasis normalised) in that file; `pkc req-lint` enforces it.
export type VectorSpecRef = {
  doc: string;
  section: string;
  quote: string;
};

export type ConformanceVector = {
  id: string;
  intent:
    | "charge"
    | "x402-exact"
    | "session"
    | "x402-upto"
    | "x402-batch-settlement"
    | "subscription";
  mode: VectorMode;
  description?: string;
  // Required traceability (filled by `pkc fill`; never hand-edited).
  spec: VectorSpecRef;
  // Requirement ids from harness/requirements/{mpp,x402}.toml.
  requirements?: string[];
  bugType?: "replay" | "auth-bypass" | "settlement" | "wire" | "defaults" | "malleability" | "precedence";
  tier?: "offline" | "interop" | "onchain";
  role?: "client" | "server" | "both";
  // generated: expected value computed by the Rust kit. authored: taken
  // from the spec text.
  provenance?: "generated" | "authored";
  input: VectorInput;
  expect: VectorExpect;
};

// The fields a runner receives on stdin: the vector ABI without the
// traceability metadata, so runners keep working unchanged.
export const RUNNER_VECTOR_KEYS = ["id", "intent", "mode", "description", "input", "expect"] as const;

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
  // Present on an accepted charge build: the built base64 wire transaction.
  // `pkc run` runs the Rust kit's verifier on it and compares its
  // instruction multiset with the kit's own build of the same case.
  transaction?: string;
  // Present on an accepted x402 build: the built base64 payment header,
  // judged the same way.
  x402PaymentHeader?: string;
};
