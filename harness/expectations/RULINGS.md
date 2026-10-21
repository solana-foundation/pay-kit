# Spec rulings

How the harness and every SDK read the specs where implementations disagreed.
Each ruling quotes the text it rests on. Quotes are in curly marks (“…”) and
`pkc req-lint` checks that every one still appears verbatim (whitespace and
markdown emphasis normalised; `...` elides) in the pinned specs:

- mpp-specs, pinned as the submodule `external/mpp-specs` at `782abae`
  (tempoxyz/mpp-specs `main`): `specs/core/draft-httpauth-payment-01.md`,
  `specs/methods/solana/draft-solana-charge-00.md`.
- x402, pinned as the submodule `typescript/external/x402` at `03b3919b`:
  `specs/x402-specification-v2.md`, `specs/schemes/exact/scheme_exact_svm.md`,
  `specs/extensions/payment_identifier.md`.

## MPP charge (Solana)

**C1. `currency` is `"sol"` or a mint address, never a symbol.**
“For native SOL, MUST be the lowercase string `"sol"`. For SPL tokens, MUST be
the base58-encoded mint address”. A server MAY accept a symbol in its own
configuration but MUST resolve it before it reaches the wire.

**C2. `decimals` is required for a mint and forbidden for SOL.** “MUST be
present when `currency` is a mint address; MUST be absent when `currency` is
`"sol"`.” Servers MUST emit it for mints and omit it for SOL. A client MUST
NOT assume a value; a mint challenge without `decimals` is refused
(`invalid-challenge`).

**C3. `tokenProgram` is resolved from the mint, never defaulted.** “If omitted,
clients MUST determine the correct token program by fetching the mint account
... If that lookup fails, returns an unexpected owner, or cannot be verified,
clients MUST reject the challenge rather than falling back to the Token
Program.” A known-currency table is a fallback and is not allowed on the
client. “MUST NOT be present when `currency` is `"sol"`.”

**C4. There are no `asset` / `payTo` fields in an MPP charge request.** The
request defines `amount`, `currency`, `description`, `recipient`,
`externalId` and `methodDetails`. Nothing may let `asset` or `payTo` override
`currency` or `recipient`.

**C5. `ataCreationRequired` obliges the client in both fee modes.** “When the
client is the transaction fee payer ... clients MAY include ATA creation
instructions only for split recipients, and MUST include one for each split
whose entry sets `ataCreationRequired: true`. Clients MUST NOT include ATA
creation instructions for the top-level `recipient` or any other owner.” The
sentence fixes the shape of a client-paid transaction; it does not oblige a
client to accept the challenge, and Client-Side Verification leaves split
acceptance to the client. A client that will not fund that rent declines the
challenge, which is conformant; it never builds a transaction without the
instruction. Rust's low-level builder includes the creation by default, and
`PayKitClient`, whose spend cap covers only `amount`, declines.

## MPP core

**P1. An unterminated quoted-string is a grammar error.** The challenge uses
“auth-param = token BWS "=" BWS ( token / quoted-string )”, and “Unknown
parameters MUST be ignored by clients” governs well-formed parameters. A parser
MAY ignore a malformed unknown parameter (the canonical mpp-tools golden, which
assigns that case to the Python adapter only) or reject the header with
`parse_error`. Either is conformant; a pathological parse time is not.

## x402 v2

**X1. `PaymentRequirements` has exactly the spec's fields.** `scheme`,
`network`, `amount`, `asset`, `payTo`, `maxTimeoutSeconds`, `extra`. There is
no `protocol` field; clients MUST NOT require one. Servers MAY add fields, and
clients ignore what they do not understand. That covers the legacy aliases some
servers still send beside the x402 fields (`recipient`, `currency`, top-level
`decimals`, `tokenProgram`, `recentBlockhash`, `feePayerKey`): a client reads
each term from its x402 field only and never lets an alias replace it, so the
signed transfer pays what the echoed `accepted` names. Only `amount` and
`maxTimeoutSeconds` fall back to the v1 names a legacy credential uses. Vector:
`x402-exact-v2-build-ignores-non-spec-fields`.

**X2. `amount` is atomic units.** “Required payment amount in atomic token
units”. A server MUST NOT put a decimal or human price on the wire. A server
SDK that accepts a human price converts it with the asset's decimals and
validates the result is a positive integer at construction.

**X3. Extensions are echoed, never trimmed.** “The client must include at least
the info received; it may append additional info but cannot delete or
overwrite existing info.”

## x402 exact on SVM

**S1. `extra.feePayer` is required; decimals are not in `extra`.** The scheme
“requires the following inside the `extra` field”: `feePayer`, plus optional
`memo`, `recentBlockhash`, `lastValidBlockHeight`. A client needing decimals
for `TransferChecked` reads the mint account. An `extra.decimals` sent by a
server is a non-spec hint a client MAY use, but a client MUST work without it.

**S2. The client builds a real transfer with a memo.** “Clients MUST include a
Memo instruction containing either the value of `extra.memo` (when present) or
a random nonce (at least 16 bytes, hex-encoded for UTF-8 compliance).” The
fee payer is `extra.feePayer`, whose signature slot is left empty.

**S3. Verification inspects the transaction.** A verifier MUST find “exactly
one” `TransferChecked` of at least `amount` of `asset` to the ATA of `payTo`,
MUST keep the fee payer out of every instruction's accounts (§2.1.1), and, when
`extra.memo` is present, MUST verify exactly one matching Memo. A server that
accepts a credential without decoding its transaction does not conform.

**S4. `payment-identifier` with `required: true` and no id is a 400.** The id is
16–128 characters of `[A-Za-z0-9_-]`. A server that advertises the extension
as required MUST reject a payload without a valid id.

**S5. Overpayment is tolerated by default.** scheme_exact_svm.md §1.4: “A
matching transfer MAY exceed PaymentRequirements.amount ... it MUST NOT be
less.” The generic scheme_exact.md SVM bullet (“Amount exactness: the
transferred amount MUST equal maxAmountRequired”) is listed under “Examples
include”, uses the v1 field name, and is superseded by the network binding's
normative §1 outcome definition. §2.3 lets a sponsor reject overpayment only
as an explicit stricter policy; default verifiers MUST accept it.

**S6. A sponsor bounds the priority fee as limit times price.**
scheme_exact_svm.md §2.2.1: “Sponsors SHOULD bound their fee exposure by
enforcing maximum compute unit limits and maximum compute unit (priority fee)
price”. Capping each field alone still lets the largest limit pair with the
largest price, so the fee the sponsor pays is bounded as their product. The
pay-kit sponsors cap it at 2,000 lamports; a 200,000 unit limit at 5,000,000
micro-lamports per unit (each within its own cap, a 1,000,000 lamport fee) is
refused as `compute-price-over-cap`. Vector:
`x402-exact-verify-priority-fee-over-cap-reject`. A version-1 header
`priorityFee` is the same product, so the cap applies to it unchanged; the
txv1 per-unit cap (5 lamports per unit) still holds below it, and
`x402-verify-v1-priority-fee-{at,over}-cap-*` pin that boundary at a 300 unit
limit, where it binds before the total does.

## x402 upto on SVM

**U1. `openSlot` and `recentSlot` are numbers on the wire; verifiers accept the
decimal-string form too.** The pinned table reads “| openSlot | number | u64
slot encoded in the open instruction and used as a channel PDA seed. |” and
“| recentSlot | number | no |”. Every implementation emits decimal strings
(the session method's convention). Vectors use the string form everywhere
except `x402-upto-verify-open-slot-number-accept` and
`x402-upto-build-recent-slot-number`, which pin the spec's number form as
accepted; a verifier that also accepts the string form is not in breach (the
table types what a producer emits). Upstream: make the table say decimal
string, or require both parsers to accept both.

**U2. The read-only verify preflight runs the deposit's static checks, the
channel-exists read included.** “Facilitator /verify is not part of this
ordering; it MAY be offered as a read-only preflight of the same static checks
below without co-signing or broadcasting open.” Step 4 (“Confirm the channel
account does not already exist.”) is a read, not a write, so a preflight that
answers valid for an already-opened channel misreports the deposit's outcome.
`x402-upto-verify-channel-already-open-reject` serves the channel account from
the fixture RPC.

**U3. Offline verify stops before the broadcast.** Vectors judge everything up
to and including the fee payer's co-signature (steps 0 to 7 and the acceptance
policy); settlement readiness (step 8, simulation), the broadcast and the
on-chain rebind (steps 9 and 10) need a validator and are interop scenarios.
Open-slot freshness against the challenged slot is program-enforced (“The open
instruction still enforces the program's slot window.”), so no vector requires
a verifier to pre-check it.

## MPP subscription (Solana)

Pinned as the submodule `external/mpp-specs-solana` at `5c4a528`
(solana-foundation/mpp-specs `feat/solana-subscriptions`):
`specs/methods/solana/draft-solana-subscription-00.md`.

**SUB1. The subscriber's own idempotent ATA creation is tolerated; no other
ATA creation is.** The client list says the activation must “contain no
instructions other than those above plus optional compute-budget and memo
instructions.”, while the server's scope check forbids only “no other
subscriptions-program, system-program, or token-program instructions;
compute-budget and memo instructions are permitted.” Neither names the
Associated Token program. Both SDK clients prepend a `CreateIdempotent` of the
subscriber's own ATA so a first-time wallet can activate; it moves no tokens.
Until the draft lists it, vectors accept that one instruction and reject any
other ATA creation (the recipient's, a third party's) as
`unexpected-instruction`: “MUST NOT reference writable accounts that could
redirect funds away from recipient.” Upstream: list the subscriber's
idempotent ATA creation explicitly.

**SUB2. Activation is `type="transaction"` only.** “Solana subscription
activation uses type="transaction".” and “Solana transactions containing
standalone SPL Token Approve instructions and push-mode hash credentials do
not provide the per-period enforcement required for this intent.” A
`type="signature"` (push-mode) activation is rejected (`invalid-payload`).

**SUB3. Expiry boundaries are inclusive at `now`.** “The activation
challenge's expires auth-param limits creation of the binding” and “Servers
MUST NOT treat activation as successful if subscriptionExpires is present and
the activation transaction settles at or after that timestamp.” Vectors pin
`nowSeconds`: an `expires` or `subscriptionExpires` equal to it rejects
(`challenge-expired`, `subscription-expired`), one second later accepts. A
cancellation (`delegation.expires_at_ts`) equal to `now` has taken effect:
“a non-zero timestamp only blocks renewal once the current time is at or
after that timestamp.”

## x402 batch-settlement on SVM

Pinned `scheme_batch_settlement_svm.md` (x402 @03b3919b); transaction-version
rules from the x402-txv1 draft (`external/x402-txv1` @3d723dd).

**B1. A client-mode voucher steps the server's watermark by exactly the
amount.** Phase 3: “In client mode, require `maxClaimableAmount ==
chargedCumulativeAmount + PaymentRequirements.amount` and `maxClaimableAmount
<= channel.deposit`.” The verify vectors take the verifying party's role as
the resource server that owns `chargedCumulativeAmount` (the store record is
the vector's `batchServerChannel`), so `charged + amount + 1` is rejected
with `cumulative-amount-mismatch`. A stateless facilitator cannot apply this
rule: it sees only onchain `settled`, and the txv1 draft gives it a floor
instead (“the facilitator MUST require `maxClaimableAmount >= Channel.settled +
PaymentRequirements.amount`”). An SDK whose only verify entry point is a
facilitator therefore fails the above-amount vectors; that is a known
failure of the facilitator-only testee, not a reading of the server rule.

**B2. A client-mode refund carries the voucher.** “| `voucher` | `BatchVoucher`
| REQUIRED in client mode.” The `request_close` transaction is the retry path
after `invalid_batch_settlement_svm_receiver_binding_unavailable`. A
single-shot verifier holds no receiver binding, so the refund vectors pin
that retry (voucher plus transaction) and judge the `request_close` policy.

**B3. Codes the spec does not name.** An `accepted` that differs from the
requirements is `accepted-mismatch` and a non-v2 envelope `unsupported-version`
(the x402 `exact` vocabulary); a client refusing an offer it may not act on
(untrusted server-mode operator, `extra.operator` in client mode, a malformed
requirement) is `invalid-challenge`; wire objects that do not parse are
`invalid-payload`.

## Transaction versions (SIMD-0385)

Pinned drafts: `external/mpp-specs-txv1` (solana-foundation/mpp-specs
feat/solana-transaction-versions `77aa6a1`, charge and session) and
`external/x402-txv1` (x402-foundation/x402 PR 3473, solana-foundation/x402
`3d723dd`, scheme_exact_svm.md §1.5).

**T1. `transactionVersions` is an array of the integers 0 and 1, read as a
set.** MPP: “Each entry is the integer `0` or `1`, the Wallet Standard
`supportedTransactionVersions` vocabulary without `"legacy"`.” x402: “Entries
are the integers `0` and `1`”. Neither text allows a string entry, a bare
integer or another version, so an MPP charge or session request carrying one
is malformed and the SDK's request type refuses it (`invalid-payload` in the
wire vectors). A repeated entry names the same version: `[1, 1]` advertises
{1}, and a client builds version 1. x402 clients intersect the advertisement
with what they can build, so an unknown entry in an x402 offer is not by
itself a reason to refuse; the vectors pin no x402 verdict for one.

**T2. Present and empty is not absent.** Only an omitted field defaults:
MPP “Defaults to `[0]` when omitted”, x402 “When the field is absent, the
accepted set is `[0]`.” An empty array advertises nothing. MPP: “Clients MUST
build one of the advertised versions”, which no build satisfies; x402: “It
MUST fail with `unsupported_transaction_version` when the intersection is
empty.” A client refuses (`unsupported-version`).

**T3. Legacy.** MPP charge and session: “servers MUST NOT advertise
`"legacy"` and MUST reject a legacy message.” x402: “A facilitator MAY keep
accepting legacy messages from existing clients for backward compatibility”,
so the x402 vectors pin no legacy verify verdict; clients of both protocols
never build legacy.

**T4. Reject codes.** A version the server does not accept is
`unsupported-version` for both protocols (MPP: the `malformed-credential`
problem type “before inspecting any instruction”; x402
`unsupported_transaction_version`), as is a client that can build no
advertised version. A lookup table, a size over the version's limit, or a
version-1 header without `computeUnitLimit` or `loadedAccountsDataSizeLimit`
is `invalid-payload`. A ComputeBudget instruction in a version-1 message is
`unexpected-instruction` for MPP charge (“Any unexpected instructions MUST
cause rejection.”) and `invalid-payload` for x402 (the static layout
mismatch). A charge or session server accepts exactly the versions its
challenge's `methodDetails.transactionVersions` lists; an x402 sponsor its
own configured set (`input.x402ServerTransactionVersions`), since “The
sponsor enforces its own accepted set; it does not read
`PaymentRequirements.extra.transactionVersions`.”

## Signatures (both protocols)

**SIG1. A server verifies every client signature over the message before it
claims, co-signs or sends it.** Neither text says so in one sentence, but both
assume it. MPP charge pull-mode verification lists “the transfer authority is
signed by the client;” before the server signs, and x402 requires that
“Settlement success MUST reflect actual on-chain effects, not simulation
alone.” A signature that does not verify over this message names some other
transaction: a server that claims it as the payment's id, keeps it as pending
when the send fails without preflight data (the node's signature-failure
reply), and later reconciles it by its on-chain status serves the resource for
a payment that never happened. So the signature list must have exactly
`num_required_signatures` entries, every slot but the server's own must verify,
and a failure is a definite refusal: nothing is claimed, nothing is sent.
Vectors: `charge-verify-forged-client-signature-reject`,
`charge-verify-sponsored-forged-client-signature-reject`,
`charge-verify-sponsored-truncated-signatures-reject`,
`x402-exact-verify-forged-client-signature-reject`,
`x402-exact-verify-truncated-signatures-reject`. Upstream: state the check in
both specs' verification steps.

## Harness consequences

- Vectors encode these rulings. Runners pass chain state through the fixture
  RPC (`input.rpcUrl`) and MUST NOT inject defaults, resolve token programs or
  apply field precedence themselves.
- Every verify vector carries a real transaction filled by `pkc fill`
  (`rust/crates/conformance`): charge verify vectors pin the Rust kit's
  build, x402 verify vectors the §3.1 static layout. Build vectors carry no
  pinned transaction.
