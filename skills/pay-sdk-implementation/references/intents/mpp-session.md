# `mpp/session`

**Session intent**: open a payment channel between a client and server so
the client can pay incrementally with off-chain signed vouchers, settled
on-chain only at open / top-up / close. Backed by the on-chain
payment-channels program (`rust/src/program/payment_channels.rs`) and,
for operated pull-mode, the multi-delegate program
(`rust/src/program/multi_delegator.rs`).

Spec: <https://paymentauth.org>, session intent.
Rust reference: `rust/src/protocol/intents/session.rs`,
`rust/src/server/session.rs`, `rust/src/client/session.rs`.

## When to implement

Session is **optional** for a new SDK. Implement it only when:

- The user explicitly asks for `mpp/session` support.
- The Solana toolchain available in the language can serialize Anchor /
  Borsh instructions to the payment-channels program (or you re-export
  pre-signed transactions from the Rust client).
- You have an HTTP transport that supports streaming
  (`rust/src/client/http_stream.rs` is the SSE/chunked reference).

If any of these is missing, leave session unimplemented and put `—` in
the README matrix.

## Wire format

### Challenge — `SessionRequest`

```json
{
  "cap": "10000000",
  "currency": "USDC|<mint>",
  "decimals": 6,
  "network": "mainnet-beta|devnet|localnet",
  "operator": "<base58>",
  "recipient": "<base58>",
  "splits": [{"recipient": "<base58>", "bps": 1000}],
  "programId": "<base58>",
  "description": "...",
  "externalId": "...",
  "minVoucherDelta": "1000",
  "modes": ["push", "pull"],
  "pullVoucherStrategy": "clientVoucher|operatedVoucher",
  "recentBlockhash": "<base58>"
}
```

See `rust/src/protocol/intents/session.rs:101-167`.

### Client `Authorization` — `SessionAction` (tagged)

Discriminated by `"action": "open" | "voucher" | "commit" | "topup" | "close"`.

- `open` — `OpenPayload`. Shape varies by `mode`:
  - **Push (payment channel)** — `channelId`, `deposit`, `payer`,
    `payee`, `mint`, `salt`, `gracePeriod`, `authorizedSigner`,
    `signature`. Optional `transaction` for operator-broadcast.
  - **Pull (operated voucher)** — `tokenAccount`, `approvedAmount`,
    `owner`, `authorizedSigner`, `signature`, optional
    `initMultiDelegateTx` + `updateDelegationTx`.
- `voucher` — `VoucherPayload { voucher: SignedVoucher }`.
- `commit` — `CommitPayload { deliveryId, voucher }`.
- `topup` — `TopUpPayload { channelId, newDeposit, signature }`.
- `close` — `ClosePayload { channelId, voucher? }`.

See `rust/src/protocol/intents/session.rs:185-647`.

### Voucher signing

`SignedVoucher.signature` is **Ed25519** over the on-chain
`VoucherArgs` byte layout: `channel_id (32) || cumulative_amount_le
(8) || expires_at_le (8)`. See `VoucherData::message_bytes`
(`rust/src/protocol/intents/session.rs:692-705`) which delegates to
`program::payment_channels::voucher_message_bytes`. The base64url JSON
representation of `VoucherData` carries `channelId` as base58,
`cumulativeAmount` (also aliased to `cumulative`) as a base-units
**string**, and `expiresAt` as a Unix timestamp **i64**.

## Server obligations

The session server tracks lifecycle state — not stateless like charge.
Mirror `rust/src/server/session.rs`:

1. **Issue session challenge.** Advertise `modes` (push and/or pull) and,
   if pull is offered, the `pullVoucherStrategy`. Pre-fetch
   `recentBlockhash` so the client can build server-broadcast
   transactions without an extra RPC.
2. **Open handler.** Validate the `SessionAction::Open` payload:
   - `mode` matches one advertised.
   - For push: verify the on-chain channel exists (or the
     `transaction` is valid and broadcastable), deposit ≥ first
     voucher's `cumulative`, signer matches `authorizedSigner`.
   - For pull `operatedVoucher`: submit `initMultiDelegateTx` and/or
     `updateDelegationTx` only if PDA does not yet exist or cap is
     too low (idempotent).
3. **Store channel state.** `ChannelStore.put` keyed by `session_id()`
   (channel PDA for push; token account for pull). The state holds the
   highest-seen `cumulative`, the authorized signer pubkey, and
   pending deliveries.
4. **Voucher handler.** Verify Ed25519 signature against
   `authorized_signer`, parse `VoucherData`, ensure:
   - `cumulative` > previous high-water mark.
   - `cumulative - previous >= minVoucherDelta` (anti-spam).
   - `cumulative <= cap`.
   - `expiresAt` > now.
   - `channelId` matches the session's id.
   Then update state and respond.
5. **Metered delivery flow.** Server issues a `MeteringDirective` with
   `deliveryId`, `sessionId`, `amount`, `sequence`, `expiresAt`; client
   responds with `commit` carrying a voucher whose `cumulative` covers
   the new amount; server records `CommitReceipt` (idempotent on
   `deliveryId` — returns `replayed` on re-submission).
6. **Top-up.** Verify the on-chain top-up signature and raise the
   stored deposit cap.
7. **Close.** Apply the final voucher (if any), then settle on-chain.
   For push: submit the close instruction. For operated pull: the
   delegate finalizes via the multi-delegator program.

## Client obligations

Mirror `rust/src/client/session.rs` + `rust/src/client/session_consumer.rs`:

1. Receive the session challenge (e.g. via the 402 challenge stream).
2. Generate an ephemeral `authorizedSigner` keypair.
3. Build the open transaction:
   - **Push** — payment-channels program `OpenChannel` instruction;
     client broadcasts, signs the resulting signature.
   - **Pull operated** — pre-sign `InitMultiDelegate` and
     `CreateFixedDelegation` transactions (use the server's
     `recentBlockhash`); send them as `initMultiDelegateTx` /
     `updateDelegationTx`.
4. Send `SessionAction::Open` with the resulting signature(s) and
   ephemeral signer's pubkey.
5. For each metered API call: receive `MeteringDirective`, sign a new
   voucher (`cumulative += directive.amount`) using the ephemeral
   key, send `SessionAction::Commit`.
6. On done: send `SessionAction::Close` with the final voucher.

## Things to pay attention to

- **`salt` is a `u64` serialized as a string.** JSON numbers > 2^53 are
  unsafe in JS intermediaries. See the custom serde adapters
  `serialize_optional_u64_as_string` /
  `deserialize_optional_u64_from_string_or_number`
  (`rust/src/protocol/intents/session.rs:15-49`). The deserializer
  accepts both numbers and strings (for ecosystem compatibility) but
  the serializer always emits a string.
- **`DEFAULT_SESSION_EXPIRES_AT == 4_102_444_800`** (2100-01-01 UTC).
  This is *below* `Number.MAX_SAFE_INTEGER` deliberately — pick the
  same default in the new SDK.
- **`pullVoucherStrategy` separates "how the session opens" from "who
  signs vouchers".** `clientVoucher`: client signs vouchers, operator
  uses them as receipts. `operatedVoucher`: operator signs vouchers
  after metering, multi-delegate setup is required. See
  `rust/src/protocol/intents/session.rs:80-96`.
- **Voucher bytes are Borsh, not JSON.** The wire JSON carries
  `channelId` (base58), `cumulativeAmount` (string), `expiresAt`
  (i64), but the **signed** bytes are `channel_id (32-byte pubkey)
  || cumulative (u64-le) || expires_at (i64-le)`. Get this wrong and
  signatures will not verify against the on-chain program.
- **`cumulativeAmount` is serde-renamed.** The field is `cumulative` in
  Rust (`rust/src/protocol/intents/session.rs:679`) but the wire name
  is `cumulativeAmount`. The alias accepts both names on deserialize
  for backwards compatibility; serialize only as `cumulativeAmount`.
- **Cumulative, not incremental.** Each voucher carries the
  monotonically-increasing total — *not* the per-request delta. The
  server stores the high-water mark and computes the delta itself.
- **`MeteringDirective.deliveryId` is the idempotency key.** A
  duplicate `commit` for the same `deliveryId` returns
  `CommitStatus::Replayed` with the cached receipt, not a new
  settlement. Implement this carefully — interop tests exercise
  duplicate sends.
- **Streaming requires real async.** SSE / chunked transfer for
  metered streams is reference-implemented in
  `rust/src/client/http_stream.rs`. The new SDK needs an async
  runtime that supports streaming reads to consume metered responses.

## Test plan

Unit tests (mirror `rust/src/protocol/intents/session.rs::tests`):

- `SessionMode` serde — push/pull camelCase.
- `SessionPullVoucherStrategy` roundtrip.
- `SessionRequest` omits empty splits/modes/None fields.
- `OpenPayload::push`/`pull`/`payment_channel` builders.
- `session_id()` returns channelId for push, tokenAccount for pull-no-channel.
- `salt` serializes as string, deserializes from both string and number.
- `VoucherData::message_bytes` round-trips against
  `program::payment_channels::voucher_message_bytes`.
- Ed25519 signature verification against `authorized_signer`.
- Voucher monotonicity — strictly increasing `cumulative` required.
- Cap enforcement — `cumulative > cap` rejects.
- Min-delta enforcement.
- Metering idempotency — `commit` with same `deliveryId` returns
  `Replayed`.

Integration:

- Surfpool-backed session lifecycle: open → 3 vouchers → topup → 2 more
  vouchers → close. Verify final on-chain settlement matches the
  cumulative voucher.

Interop:

- The harness does not have session scenarios shipped today. Add one
  to `harness/src/contracts.ts` (intent `session`) before
  enabling the cell. Pattern after `charge-basic`; reuse the same
  Surfpool fixtures.
