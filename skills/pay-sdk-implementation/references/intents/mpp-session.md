# `mpp/session`

**Session intent**: open a Solana payment channel, authorize incremental
off-chain usage, and settle on-chain only at open, top-up, and close.

Spec: `mpp-specs/specs/methods/solana/session.md` on the branch containing
PR #309. Treat that specification as the wire-format authority. Do not add
aliases for fields from earlier drafts.

Reference implementations:

- Rust: `rust/crates/kit/src/mpp/protocol/intents/session.rs`,
  `rust/crates/kit/src/mpp/server/session.rs`, and the session modules under
  `rust/crates/kit/src/mpp/client/`.
- TypeScript: `typescript/packages/mpp/src/Methods.ts`,
  `typescript/packages/mpp/src/server/Session.ts`, and the session modules
  under `typescript/packages/mpp/src/{client,server/session,shared}/`.
- Python: `python/src/solana_pay_kit/protocols/mpp/intents/session.py` and the
  session modules under `python/src/solana_pay_kit/protocols/mpp/{client,server}/`.

## Required components

### Shared protocol layer

1. Exact challenge and action types.
2. Canonical voucher-byte encoder shared by client and server.
3. Generated payment-channels program client and PDA helpers.
4. Reusable payer-authentication proof helpers for operator voucher mode.

### Client

1. Generate or load the session signer.
2. Fetch a confirmed slot and recent blockhash, derive the channel PDA, build
   the exact open instruction, and sign the transaction.
3. In operator voucher mode, sign the reusable authentication proof before
   opening and attach the same proof to later `use` and operator `close`
   actions.
4. In client voucher mode, prepare a cumulative voucher, send it, and only
   advance the local watermark after acceptance.
5. Handle metering directives and idempotent delivery commits.
6. Keep all local state scoped by channel ID; reopening a channel must not
   inherit another channel's cumulative watermark.

### Server

1. Issue exact challenges and HMAC-bind every challenge field.
2. Enforce challenge expiry when processing `open`.
3. Decode, submit, confirm, and verify the exact open and top-up transactions
   before mutating local state. Missing RPC configuration fails closed.
4. Persist the opening challenge binding, payer, voucher signer, reusable
   authentication proof, negotiated idle timeout, and verified on-chain facts.
5. Make `open`, operator `use`, and delivery commit idempotent.
6. Verify client vouchers atomically against the cumulative watermark and
   deposit.
7. Authenticate operator-mode `close` with the stored proof.
8. Recheck activity atomically before idle close, and reconstruct timers from
   persistent state after restart.
9. Settle and distribute the highest accepted voucher on close.

## Wire format

### Challenge request

```json
{
  "amount": "1000",
  "currency": "USDC",
  "recipient": "<base58>",
  "unitType": "request",
  "suggestedDeposit": "10000000",
  "minimumDeposit": "1000000",
  "description": "...",
  "externalId": "...",
  "methodDetails": {
    "network": "mainnet|devnet|localnet",
    "channelProgram": "<base58>",
    "channelId": "<base58>",
    "recentBlockhash": "<base58>",
    "recentSlot": "<u64 decimal>",
    "decimals": 6,
    "tokenProgram": "<base58>",
    "feePayer": true,
    "feePayerKey": "<base58>",
    "voucherSigner": "client|operator",
    "operator": "<base58>",
    "minVoucherDelta": "1000",
    "ttlSeconds": 300,
    "idleTimeoutOptionsSeconds": [60, 300, 900],
    "idleTimeoutSeconds": 300,
    "gracePeriodSeconds": 900,
    "distributionSplits": [
      { "recipient": "<base58>", "shareBps": 1000 }
    ]
  }
}
```

Required fields are `amount`, `currency`, `recipient`, and
`methodDetails.{network,channelProgram}`. Every other field shown above is
optional and must be omitted when unset, with one conditional pair:
`methodDetails.{recentBlockhash,recentSlot}` are REQUIRED when `channelId`
is absent (a new-channel challenge) and MUST be absent when resuming an
existing channel. Both come from one `getLatestBlockhash` call —
`recentBlockhash` from `result.value`, `recentSlot` from
`result.context.slot` — and the server MUST fail the challenge rather than
issue one without them. The client MUST use the challenged
`recentBlockhash` as the open transaction's blockhash and defaults
`openSlot = recentSlot` (an earlier `openSlot` is allowed, a later one is
rejected). At open time the server MUST verify `openSlot <= recentSlot`,
`recentSlot - openSlot <= OPEN_SLOT_WINDOW` (1500 slots), and that the
compiled open transaction uses the challenged `recentBlockhash`.

### Credential actions

The action discriminator is exactly `open`, `voucher`, `use`, `topUp`, or
`close`.

`open`:

```json
{
  "action": "open",
  "channelId": "<base58>",
  "payer": "<base58>",
  "payee": "<base58>",
  "mint": "<base58>",
  "authorizedSigner": "<base58>",
  "salt": "<u64 decimal>",
  "depositAmount": "<u64 decimal>",
  "gracePeriodSeconds": 900,
  "idleTimeoutSeconds": 300,
  "openSlot": "<u64 decimal>",
  "distributionSplits": [
    { "recipient": "<base58>", "shareBps": 1000 }
  ],
  "authentication": {
    "type": "proof",
    "challengeId": "<opening challenge id>",
    "payer": "<base58>",
    "signature": "<base58>"
  },
  "transaction": "<base64 signed transaction>"
}
```

`authentication` is required when `voucherSigner` is `operator` and omitted
when it is `client`. `idleTimeoutSeconds`, `distributionSplits`,
`authorizationPolicy`, and `capabilities` are optional. The transaction is
always required.

The remaining actions are:

```json
{ "action": "voucher", "voucher": { "data": {}, "signer": "<base58>", "signature": "<base58>", "signatureType": "ed25519" } }
{ "action": "use", "channelId": "<base58>", "authentication": { "type": "proof", "challengeId": "<opening challenge id>", "payer": "<base58>", "signature": "<base58>" } }
{ "action": "topUp", "channelId": "<base58>", "additionalAmount": "<u64 decimal>", "transaction": "<base64 signed transaction>" }
{ "action": "close", "channelId": "<base58>", "voucher": {}, "authentication": {} }
```

For `close`, a client-signed channel may include a final `voucher`; an
operator-signed channel must include `authentication`. Do not accept an
unauthenticated operator close.

### Voucher signing

`SignedVoucher` contains `data`, `signer`, `signature`, and
`signatureType: "ed25519"`. `data` contains `channelId`,
`cumulativeAmount`, and optional `expiresAt`.

The Ed25519 signature covers exactly:

```text
[0x56, 0x01]
|| channel_id (32 bytes)
|| cumulative_amount (u64 little-endian)
|| expires_at (i64 little-endian; zero when omitted)
```

This is 50 bytes. The magic/version prefix is part of the signed bytes, not
the JSON. `cumulativeAmount` is a decimal string. `expiresAt` is a JSON number
and JavaScript implementations must reject values outside the safe-integer
range rather than rounding them.

### Authentication proof

The reusable proof signs canonical JSON containing:

```json
{
  "channelId": "<base58>",
  "domain": "mpp-session-auth-v1",
  "payer": "<base58>",
  "sessionChallengeId": "<opening challenge id>"
}
```

The proof is bound to the opening challenge and channel. Store the verified
proof at open and compare later credentials to the stored values; never trust
a proof's self-declared challenge ID without checking the opening challenge.

The proof has no separate expiry field. The standard challenge `expires`
limits opening the channel. Once the channel is open, the stored proof remains
valid until idle timeout or channel closure. Framework integrations must not
apply the opening challenge's expiry to `voucher`, `use`, `topUp`, or `close`.

## Exact transaction verification

For an open transaction, verify all of the following before persistence:

- exactly one payment-channels open instruction, with only explicitly allowed
  compute-budget instructions alongside it;
- transaction fee-payer policy and every required signature;
- channel program, payer, rent payer, payee, mint, authorized signer, token
  program, token accounts, and channel PDA;
- salt, deposit amount, grace period, open slot, and distribution splits;
- deposit is positive and satisfies the advertised minimum;
- submitted signature is the transaction's actual fee-payer signature;
- confirmation succeeded; and
- the resulting channel account matches the expected state.

Reject address lookup tables unless every loaded address is resolved and
verified. A verifier that only sees static account keys must fail closed.

For top-up, bind the transaction to `channelId` and `additionalAmount`, require
an actual increase, confirm it, and verify the resulting on-chain deposit is at
least `previousDeposit + additionalAmount` before updating local state.

## State and atomicity

Store at least:

- verified channel identities and deposit;
- cumulative high-water mark and highest voucher;
- payer, voucher signer, opening challenge ID, and authentication proof;
- negotiated idle timeout and last activity time;
- pending/committed deliveries;
- processed HTTP idempotency keys and cached operator-use results;
- close/seal/settlement state; and
- open slot and rent payer needed for settlement/reclaim.

All state transitions are per-channel atomic read-modify-write operations.
Open replay must not reset a watermark. A repeated operator `use` with the same
non-empty `Idempotency-Key` returns the cached result without incrementing the
cumulative amount again. Empty idempotency keys are rejected for operator use.

Voucher checks must be repeated inside the atomic mutation: channel open,
monotonic cumulative amount, deposit bound, minimum delta, exact signer,
signature validity, and optional voucher expiry.

Idle timers are advisory wakeups. When a timer fires, atomically re-read the
stored channel and compare `lastActivityAt + idleTimeoutSeconds` before
closing. Recreate timers for persisted open channels on startup.

A committed delivery is channel activity: the commit's atomic mutation must
refresh `lastActivityAt` alongside the watermark advance, exactly like
accepted vouchers, operator uses, and top-ups. Delivery reservations and
idempotent commit replays leave `lastActivityAt` unchanged.

## Test plan

- Exact challenge serialization and rejection of every removed draft field.
- Exact action parsing for all five actions.
- Challenge expiry rejects open but not later authenticated actions.
- Authentication proof binding, signature validation, and operator close.
- Open and top-up fail closed without RPC.
- Transaction/account verification for payer, payee, mint, signer, program,
  token accounts, amount, slots, splits, signatures, confirmation, and
  resulting account state.
- Voucher signer metadata and 50-byte golden message vectors.
- Open, use, and delivery-commit idempotency.
- Concurrent voucher/use/top-up/close mutations.
- Idle timeout activity races and timer reconstruction after restart.
- Full lifecycle: open, vouchers or uses, top-up, more usage, close, settle,
  distribute, and reclaim.
