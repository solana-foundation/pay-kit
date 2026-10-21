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
clients ignore what they do not understand.

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

## Harness consequences

- Vectors encode these rulings. Runners pass chain state through the fixture
  RPC (`input.rpcUrl`) and MUST NOT inject defaults, resolve token programs or
  apply field precedence themselves.
- Every verify vector carries a real transaction filled by `pkc fill`
  (`rust/crates/conformance`): charge verify vectors pin the Rust kit's
  build, x402 verify vectors the §3.1 static layout. Build vectors carry no
  pinned transaction.
