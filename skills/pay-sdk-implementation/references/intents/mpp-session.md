# `mpp/session`

**Session intent**: open a payment channel between a client and server so
the client can pay incrementally with off-chain signed vouchers, settled
on-chain only at open / top-up / close. Backed by the on-chain
payment-channels program and, for operated pull-mode, the multi-delegate
program.

Spec: `mpp-specs` repo, **branch `feat/solana-sessions`**,
`specs/methods/solana/draft-solana-session-00.md`. The draft is not on
`main` yet — fetch the branch before reading.

Reference implementations (cite both when porting):

- **Rust (canonical)** — `rust/crates/mpp/src/protocol/intents/session.rs`
  (types), `rust/crates/mpp/src/server/session.rs`,
  `rust/crates/mpp/src/client/{session,session_consumer,payment_channels,multi_delegate,http_stream}.rs`,
  `rust/crates/mpp/src/program/payment_channels.rs` (voucher bytes, PDA).
- **TypeScript (second reference)** —
  `typescript/packages/mpp/src/shared/{session-types,voucher}.ts`,
  `typescript/packages/mpp/src/server/Session.ts` +
  `server/session/{store,voucher,on-chain,wire-tx,lifecycle}.ts`,
  `typescript/packages/mpp/src/client/{Session,SessionFetch,PaymentChannels,SessionConsumer,HttpStream,ChallengeSelection}.ts`,
  generated payment-channels client under
  `typescript/packages/mpp/src/generated/`.

> **Spec vs wire truth.** The shipped Rust and TS wire format deliberately
> diverges from the draft spec in known ways (see "Spec divergences"
> below). The Rust crate is the wire truth for harness; do **not**
> "fix" a port toward the draft unilaterally — that breaks harness with
> every shipped SDK. Raise spec mismatches on the mpp-specs branch
> instead.

## When to implement

Session is **optional** for a new SDK. Implement it only when:

- The user explicitly asks for `mpp/session` support.
- You can generate a payment-channels program client via Codama (see
  `references/codegen.md` and
  `codegen/generate-payment-channels-client.ts` next to this skill) —
  do not hand-write the instruction encoders.
- You have an HTTP transport that supports streaming
  (`rust/crates/mpp/src/client/http_stream.rs` and
  `typescript/packages/mpp/src/client/HttpStream.ts` are the SSE/chunked
  references).

If any of these is missing, leave session unimplemented and put `—` in
the README matrix.

## Component inventory — everything a port needs

The TS port is the template for what actually has to be built. Plan all
of these before starting; each maps to a concrete Rust + TS file pair.

**Shared / protocol layer**

1. Session wire types: `SessionRequest`, `SessionAction` tagged union,
   `OpenPayload`, `VoucherPayload`, `CommitPayload`, `TopUpPayload`,
   `ClosePayload`, `SignedVoucher`/`VoucherData`, `MeteringDirective`,
   `CommitReceipt` (Rust `protocol/intents/session.rs`; TS spreads them
   across `shared/session-types.ts`, `client/Session.ts`, `Methods.ts`
   schemas).
2. Voucher byte encoder: the 50-byte signed payload (see "Voucher
   signing"). Keep it in one shared module
   (`typescript/.../shared/voucher.ts`) — the TS port ended up with a
   duplicate in `server/session/on-chain.ts`; avoid that.
3. Codama-generated payment-channels client (instruction builders,
   PDA helpers). Add a `payment-channels-generate-<lang>` recipe.

**Client side**

4. Challenge parsing + mode selection (push vs pull,
   `pullVoucherStrategy` gating, `modes` defaulting — empty/omitted
   means push-only).
5. Ephemeral `authorizedSigner` keypair generation.
6. Push open builder: `OpenChannel` instruction + transaction assembly
   (fee payer = challenge `operator`, payer partial-signs, pending
   server signature placeholder = 64 ones, random u64 salt, grace
   default 900 s, deposit defaults to `cap`, the program's `openSlot`
   taken from the challenge's `recentSlot` — it is both an `open` arg
   and the last channel-PDA seed, and the program rejects it outside
   `[clock.slot - 1500, clock.slot]`; the client never fetches it via
   RPC). Rust `client/payment_channels.rs`; TS
   `client/PaymentChannels.ts`.
7. Pull open builders (operated voucher): `InitMultiDelegate` +
   `CreateFixedDelegation` transactions pre-signed against the
   server-provided `recentBlockhash`. Rust `client/multi_delegate.rs`;
   TS `client/MultiDelegate.ts` (golden-bytes-tested against the Rust
   layouts). Include these or explicitly scope pull out.
8. Session state object with a **prepare/record split**: build the
   voucher for `watermark + amount` first, advance the local watermark
   only after the server accepts. This is what makes failed commits
   retryable with the same cumulative. Rust `client/session.rs`; TS
   `client/Session.ts` (`ActiveSession`).
9. Metered consumer: parse `MeteringDirective`, sign voucher, send
   `commit` with the directive's `deliveryId`, handle `replayed`.
   Rust `client/session_consumer.rs`; TS `client/SessionConsumer.ts`.
10. Streaming consumption: SSE event names `mpp.metering`/`metering`,
    `mpp.usage`/`usage`, `done`, `[DONE]`; validate that a usage
    event's `deliveryId` matches the live directive and let usage
    override only the amount, never the deliveryId (both references
    enforce this).
11. Fetch/request wrapper that handles 402 → open → retry and queues
    voucher commits (`SessionFetch.ts`). If you build one, keep the
    commit watermark **per channel** and reset it when a re-open swaps
    the session underneath — carrying an absolute cumulative from an
    old channel onto a new one over-authorizes spend. A failed commit
    must stay retryable (do not advance the queued watermark before
    the commit succeeds, and do not latch a permanent failure).

**Server side**

12. Challenge issuance: `cap` (clamped), `currency`, `decimals`,
    `network`, `operator`, `recipient`, `splits`, `programId`,
    `minVoucherDelta` (only when > 0), `modes` (omit when push-only),
    `pullVoucherStrategy` (only when pull offered), optional
    `recentBlockhash` pre-fetch so clients can pre-sign transactions,
    and `recentSlot` (server-fetched via `getSlot` at challenge time,
    same pattern as the blockhash pre-fetch — clients must not fetch
    it themselves; it becomes the program's `openSlot`).
13. Channel store with **atomic read-modify-write** per channel
    (Rust mutex `update_channel`; TS per-channel promise-chain lock in
    `server/session/store.ts`). State: deposit, cumulative high-water
    mark, highest voucher signature + expiry, authorized signer,
    pending/committed deliveries, next sequence, closeRequestedAt,
    sealed, openSlot (needed to re-derive the channel PDA and for
    `reclaim`).
14. Open handler: mode advertised check, deposit > 0 and ≤ cap; for
    push with a `transaction`, decode and validate it (see "Open
    transaction validation"); store keyed by `session_id()` —
    **`channelId` first, falling back to `tokenAccount`** (both
    references agree; an open carrying both fields must key the same
    way everywhere). Open MUST be idempotent — see "Things to pay
    attention to".
15. Voucher handler: the exact check sequence under "Server
    obligations" — order and operators matter for harness tests.
16. Metered delivery: reservation (`cumulative + pendingTotal + amount
    <= deposit`), sequence assignment, default
    `deliveryId = "<sessionId>:<sequence>"`, directive expiry, commit
    idempotency on `deliveryId` (`replayed` returns the cached
    receipt).
17. Top-up handler: `newDeposit > current` and ≤ cap, raise stored
    deposit.
18. Close handler: apply final voucher, block further
    vouchers/deliveries once `closeRequestedAt` is set, settle
    on-chain (settle_and_seal + ed25519 precompile instruction
    immediately preceding it, distribute bundled in the same tx),
    mark sealed. A non-monotonic final voucher is a **hard error**
    (Rust behavior) — do not silently fall back to the watermark.
19. On-chain helpers: open-tx decode/verify, settle/seal builders,
    ed25519 precompile encoder (offsets 16/48/112, `0xffff`
    current-instruction markers). Rust `program/payment_channels.rs` +
    `server/session.rs`; TS `server/session/on-chain.ts`.
20. Optional host wiring: HTTP routes for the reserve/commit side
    channel (`/__402/session/deliveries` + commit endpoint) — this is
    a TS-server extension, not in the spec or the Rust crate; ship it
    if your fetch wrapper depends on it, and document the mount path.

## Wire format

### Challenge — `SessionRequest`

```json
{
  "cap": "10000000",
  "currency": "USDC|<mint>",
  "decimals": 6,
  "network": "mainnet|devnet|localnet",
  "operator": "<base58>",
  "recipient": "<base58>",
  "splits": [{"recipient": "<base58>", "bps": 1000}],
  "programId": "<base58>",
  "description": "...",
  "externalId": "...",
  "minVoucherDelta": "1000",
  "modes": ["push", "pull"],
  "pullVoucherStrategy": "clientVoucher|operatedVoucher",
  "recentBlockhash": "<base58>",
  "recentSlot": "<u64 as string>"
}
```

See `rust/crates/mpp/src/protocol/intents/session.rs:102` and the zod
schema in `typescript/packages/mpp/src/client/Session.ts`.

### Client `Authorization` — `SessionAction` (tagged)

Discriminated by `"action": "open" | "voucher" | "commit" | "topUp" |
"close"` (note the camelCase `topUp`).

- `open` — `OpenPayload`. Shape varies by required `mode`:
  - **Push (payment channel)** — `channelId`, `deposit`, `payer`,
    `payee`, `mint`, `salt`, `gracePeriod`, `recentSlot`,
    `authorizedSigner`, `signature`. Optional `transaction` for
    operator-broadcast. `recentSlot` follows the same
    u64-as-string convention as `salt` (serialize string, accept
    string or number) and carries the program's `openSlot` value.
  - **Pull (operated voucher)** — `tokenAccount`, `approvedAmount`,
    `owner`, `authorizedSigner`, `signature`, optional
    `initMultiDelegateTx` + `updateDelegationTx`.
- `voucher` — `VoucherPayload { voucher: SignedVoucher }`.
- `commit` — `CommitPayload { deliveryId, voucher }`.
- `topUp` — `TopUpPayload { channelId, newDeposit, signature }`
  (`newDeposit` is the new **total**, not a delta).
- `close` — `ClosePayload { channelId, voucher? }`.

See `rust/crates/mpp/src/protocol/intents/session.rs:187`.

### Voucher signing

`SignedVoucher` is `{ data, signature }`; `signature` is **Ed25519**
over the on-chain `VoucherArgs` byte layout: `magic ([0x56, 0x01],
2 bytes, constant) || channel_id (32 bytes, base58-decoded) ||
cumulative_amount (u64 LE) || expires_at (i64 LE)` — 50 bytes, no
other prefix or domain separator. The magic (voucher tag `0x56` +
version `0x01`) lives only in the signed bytes — the wire JSON does
**not** carry it. See
`VoucherData::message_bytes`
(`rust/crates/mpp/src/protocol/intents/session.rs:693`) which delegates
to `program::payment_channels::voucher_message_bytes`
(`program/payment_channels.rs:182`); TS equivalent
`shared/voucher.ts`. The wire JSON carries `channelId` as base58,
`cumulativeAmount` as a base-units **string**, and `expiresAt` as a
Unix-timestamp number (i64 in Rust).

## Server obligations

Mirror `rust/crates/mpp/src/server/session.rs` and
`typescript/packages/mpp/src/server/Session.ts`:

1. **Issue session challenge** (item 12 above).
2. **Open handler** (item 14). Open MUST NOT carry an initial voucher.
3. **Voucher handler.** Exact sequence (order and operators are
   harness-tested): parse u64 → reject if sealed → reject if close
   pending → idempotent replay (same cumulative AND same signature,
   signature re-verified) → `cumulative > watermark` strictly →
   `cumulative <= deposit` → `cumulative - watermark >=
   minVoucherDelta` → Ed25519 verify against stored
   `authorizedSigner` → `expiresAt > now`. Preflight outside the
   store lock, then re-check everything inside the atomic mutator.
4. **Metered delivery flow** (item 16).
5. **Top-up** (item 17), **Close** (item 18).

### Open transaction validation

When a push open carries `transaction`, decode it and check, against
the challenge: open discriminator, payee == recipient, mint,
authorizedSigner, deposit > 0 and ≤ cap, channel PDA re-derivation
from seeds — `["channel", payer, payee, mint, authorizedSigner,
salt u64 LE, openSlot u64 LE]`. Bind the submitted confirmation `signature` to the
decoded transaction's actual fee-payer signature before trusting it
(the TS server does; never accept an arbitrary confirmed signature
paired with an unrelated transaction). The spec additionally
requires (neither reference fully implements these yet — a new port
should): escrow ATA derivation, gracePeriod ≥ challenge policy,
distribution-splits preimage vs the challenged splits, and no
unrelated instructions. Accept **both legacy and v0** transaction
encodings — the Rust client emits legacy, the TS client emits v0.

## Client obligations

Items 4–11 above; the canonical flow:

1. Receive the session challenge (402).
2. Generate an ephemeral `authorizedSigner` keypair.
3. Build and send `SessionAction::Open` (push: client or operator
   broadcasts the open tx; pull operated: attach the pre-signed
   delegation txs built against the server's `recentBlockhash`).
4. For each metered call: receive `MeteringDirective`, sign a voucher
   for `watermark + directive.amount` (prepare), send
   `commit` with the directive's `deliveryId`, record the watermark on
   success only.
5. On done: `SessionAction::Close` with the final voucher (omit when
   nothing was metered).

## Things to pay attention to

- **`salt` and `recentSlot` are `u64`s serialized as strings.** The
  deserializer must accept both string and number; the serializer
  always emits a string. Rust: `serialize_optional_u64_as_string`
  adapters (`protocol/intents/session.rs:15`); TS: zod
  `z.union([z.string(), z.number()])`.
- **`openSlot` is per-incarnation identity, and it flows from the
  challenge as `recentSlot`.** It is the last channel PDA seed, so
  re-opening with the same payer/payee/mint/signer/salt at a different
  slot yields a *different* address. The server fetches it (`getSlot`)
  at challenge time and puts it in the challenge as `recentSlot`; the
  client uses it for PDA derivation + openArgs and echoes it in the
  OpenPayload `recentSlot`; the server persists it with the channel
  state — it is required to re-derive the PDA and to run `reclaim`
  (allowed only when status = distributed and
  `clock.slot > openSlot + 1500`). Clients never call `getSlot`.
  Naming rule: the field is `recentSlot` wherever it crosses HTTP,
  `openSlot`/`open_slot` wherever it names the program concept.
- **`DEFAULT_SESSION_EXPIRES_AT == 4_102_444_800`** (2100-01-01 UTC),
  deliberately below `Number.MAX_SAFE_INTEGER`. Same default in every
  SDK. But `expiresAt` is an **i64** on the wire — in languages with
  double-only JSON numbers, values above 2^53 will not round-trip;
  reject them explicitly rather than rounding (a rounded value breaks
  the Ed25519 signature, which covers `expires_at`).
- **`cumulativeAmount` is serde-renamed with an alias.** Rust field
  `cumulative` serializes as `cumulativeAmount` and accepts **both**
  names on deserialize. A port must accept the `cumulative` alias on
  every inbound voucher path and serialize only `cumulativeAmount`
  (both references do; harness tests exercise the alias).
- **Cumulative, not incremental.** Each voucher carries the
  monotonically-increasing total; the server computes deltas.
- **Token program comes from the currency.** PYUSD/USDG/CASH are
  Token-2022 mints; resolve the token program from the challenge
  currency (Rust `default_token_program_for_currency`) when deriving
  ATAs and building the open instruction. Hardcoding SPL Token breaks
  Token-2022 sessions on-chain (the channel PDA itself is unaffected —
  token program is not a seed).
- **`pullVoucherStrategy` separates "how the session opens" from "who
  signs vouchers".** `clientVoucher`: client signs vouchers.
  `operatedVoucher`: operator signs after metering; multi-delegate
  setup required. See `protocol/intents/session.rs:91`.
- **`modes` omitted or empty means push-only.** Handle the explicit
  `[]` case, not just `undefined`/missing.
- **`MeteringDirective.deliveryId` is the idempotency key.** Duplicate
  `commit` returns `replayed` with the cached receipt. Harness tests
  exercise duplicate sends.
- **Open is idempotent; replay must not reset the watermark.** The
  spec forbids replays changing channel state. Both references
  implement these exact semantics — mirror them: if the session id
  already exists and is sealed → error; if the payload's
  `authorizedSigner` differs from the stored one → error; otherwise
  return success without mutating state (watermark, highest voucher
  signature, and deposit all preserved). Do the check-and-insert
  atomically inside the store lock.
- **Top-up is gated like open.** Reject top-up on sealed or
  close-pending channels, and when an RPC endpoint is configured,
  verify the top-up `signature` is a confirmed transaction before
  raising the deposit (both references do; without RPC the deposit is
  trusted and the trust assumption is documented). Full spec
  conformance additionally wants the on-chain deposit increase
  confirmed — neither reference decodes the top-up transaction yet.
- **Encoding boundaries.** Credential envelope and `request` field:
  canonical JSON (RFC 8785) → base64url no-pad. Transactions
  (`transaction`, `initMultiDelegateTx`, `updateDelegationTx`):
  standard-alphabet base64 **with** padding. Signatures, pubkeys,
  blockhashes: base58.
- **Streaming requires real async.** SSE / chunked transfer for
  metered streams; validate usage `deliveryId` against the directive.

## Spec divergences (shipped wire ≠ draft spec)

Known, deliberate divergences shared by Rust and TS. Match the
implementations, and track the spec branch for convergence:

- Challenge schema: implementations use flat
  `cap`/`operator`/`programId`/`modes`/`pullVoucherStrategy`/`recentBlockhash`;
  the draft specifies
  `amount`/`suggestedDeposit`/`minimumDeposit`/`channelProgram`/`feePayer`/`gracePeriodSeconds`
  under `methodDetails`.
- `SignedVoucher` is `{data, signature}`; draft requires
  `{voucher, signer, signature, signatureType}`.
- Open payload: `deposit`/`gracePeriod`/required `mode`+`signature`;
  draft: `depositAmount`/`gracePeriodSeconds`/required `transaction`.
- `topUp`: `newDeposit` (new total) vs draft `additionalAmount`
  (delta) + transaction bytes.
- The `commit` action, `MeteringDirective`, and the reserve/commit
  side channel are implementation extensions absent from the draft.
- Network value: implementations emit `"mainnet"`; draft says
  `"mainnet-beta"`. Accept both on input.
- Voucher `expiresAt`: required and `0` = already expired in the
  implementations; optional and `0` = no expiry in the draft.

## Test plan

Unit tests (mirror `rust/crates/mpp/src/protocol/intents/session.rs::tests`
and `typescript/packages/mpp/src/__tests__/session-*.test.ts`):

- `SessionMode` / `SessionPullVoucherStrategy` serde roundtrips.
- `SessionRequest` omits empty splits/modes/None fields.
- `OpenPayload` builders; `session_id()` returns channelId first,
  tokenAccount fallback.
- `salt` serializes as string, deserializes from string and number.
- `VoucherData` byte encoding round-trips against
  `voucher_message_bytes`; Ed25519 verify against `authorizedSigner`.
- Voucher check sequence: monotonicity (`<=` rejects), deposit cap,
  min-delta, expiry, replay (same cumulative + same signature →
  replayed; same cumulative + different signature → rejected).
- Metering idempotency: duplicate `deliveryId` → `replayed` with the
  cached receipt; reservation math against deposit.
- Store concurrency: parallel `updateChannel` mutations serialize; a
  throwing mutator leaves state unchanged (see
  `session-store.test.ts`).
- **Golden instruction bytes**: assert the generated open instruction
  is byte-identical to the Rust builder output (see
  `payment-channels-open-ix.test.ts` — copy the golden hex).
- Close: blocks vouchers/deliveries after `closeRequestedAt`;
  non-monotonic final voucher errors; double-close rejected.

Integration:

- Surfpool-backed session lifecycle: open → vouchers → topUp → more
  vouchers → close; final on-chain settlement matches the cumulative.
  Keep e2e files out of the default vitest config (exclude
  `**/*-e2e.test.ts`; include them in the surfpool config) and make
  unreachable-sandbox a **skip**, not a silent pass.

Harness:

- The harness does not ship session scenarios yet. Add one to
  `harness/src/contracts.ts` (intent `session`) before enabling the
  cell. Pattern after `charge-basic`; reuse the Surfpool fixtures.
  Exercise: duplicate commit, voucher with `cumulative` alias,
  legacy- and v0-encoded open transactions, Token-2022 currency.
