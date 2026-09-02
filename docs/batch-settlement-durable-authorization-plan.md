# Batch settlement durable authorization plan

## Goal

Make the Axum `batch-settlement` gate provide one safe outcome for each payment authorization:

- A handler failure releases the authorization, so the client can retry it.
- A successful handler runs at most once.
- A retry after a lost response returns the stored settlement result without re-running the handler.
- A process crash never turns a successful handler execution into a fresh authorization.

This replaces the current commit-order tradeoff. Committing before the handler charges a failed request; committing after the handler can replay a successful request when persistence fails.

## Existing building blocks

Reuse the current store primitives rather than adding a parallel database:

| Existing piece | Use in batch settlement |
| --- | --- |
| `ChannelStore::update_channel` | Atomic state transitions per channel |
| `pending_deliveries` | Reservation identity and lease tracking |
| `committed_deliveries` | Durable completed authorization record |
| `ProcessedUse` | Pattern for exact retry lookups |
| `ChargeReplayStore` | Reservation state and expired-lease behavior |

Batch settlement needs one additional persisted stage because a reservation alone cannot distinguish a crash before handler execution from a crash after successful handler execution.

## Persisted model

Add a batch-specific record to `ChannelState` with `#[serde(default)]` so existing records decode safely.

```rust
enum BatchAuthorizationState {
    Reserved,
    HandlerSucceeded,
    Committed,
    Released,
}

struct BatchAuthorization {
    voucher_signature: String,
    max_claimable: u64,
    expires_at: i64,
    request_fingerprint: String,
    state: BatchAuthorizationState,
    reservation_expires_at: i64,
    settlement_response: Option<BatchSettlementResponse>,
}
```

Use the voucher signature plus the normalized accepted requirements as the request fingerprint. Reject a different request that attempts to reuse a reservation.

Store the serialized payment response only after commitment. Persisting the exact response gives clients a conformant retry result even when the original HTTP response was lost.

## State transitions

### 1. Verify and reserve

`verify_payment` validates the voucher, channel, accepted requirements, and deposit cap. It then atomically transitions:

```text
no record                 → Reserved
same Reserved, lease live → in progress; do not run handler
same Reserved, lease dead → Reserved (new owner)
same HandlerSucceeded     → resume commit only; do not run handler
same Committed            → replay stored response; do not run handler
different voucher/request → reject
```

The reservation must happen before the gate invokes the handler and must be store-backed; the current in-memory `InFlight` guard remains only an optimization.

### 2. Handler failure

After a non-success HTTP response, atomically remove the matching `Reserved` record. Do not change the voucher watermark. The client can submit the same authorization again.

If release fails, return 502 and leave the reservation until its lease expires. Do not serve a second request while the reservation remains live.

### 3. Handler success

Before committing the voucher, atomically mark the matching record `HandlerSucceeded`. This is the crash boundary: retries at this point must finish commitment and must never invoke the handler.

Commit the voucher watermark and record the resulting `BatchSettlementResponse` in one `update_channel` transition when possible. The transition must remove the pending record and create a `Committed` record.

If the voucher commit fails, return 502. A retry sees `HandlerSucceeded`, retries commitment, and never executes the handler again.

### 4. Replay

When a `Committed` record matches the voucher signature and request fingerprint, return its stored `PAYMENT-RESPONSE` and bypass the handler. Do not synthesize `chargedAmount: "0"`; return the original result.

## Deposit and open payloads

Initial deposits have no on-chain channel record before their setup transaction is confirmed. Add a store-owned pending-open record keyed by the derived channel ID and payer transaction signature.

1. Validate the signed open transaction and voucher.
2. Atomically create `PendingOpen` before the handler.
3. On handler failure, delete `PendingOpen` without broadcasting the setup transaction.
4. On handler success, mark `HandlerSucceeded`, broadcast or recover the signed setup transaction, then atomically create/update `ChannelState` and mark the authorization committed.
5. A retry of an already-confirmed setup transaction uses its signature status and the observed on-chain channel, never a fresh `openSlot` validation.

Use the same record for top-ups, keyed by the payer transaction signature, so one signed setup transaction cannot be credited twice.

## Gate changes

Refactor `batch_gate_middleware` into explicit phases:

1. `verify_and_reserve_payment`
2. If `Committed`, return the stored response.
3. If `HandlerSucceeded`, call `finish_commit` and return its response; do not invoke `next`.
4. Invoke `next` only for a newly reserved authorization.
5. On handler failure, call `release_authorization`.
6. On handler success, call `mark_handler_succeeded`, then `finish_commit`.

Return `409` only for a live reservation owned by another request. Attach a retryable error code and never use 409 for a committed replay.

## Lifecycle reconciliation

Implement these alongside the state machine because they determine whether an authorization remains valid:

- Before reserving a voucher for an existing channel, fetch and persist on-chain close state. Reject `Closing`, sealed, and terminal channels.
- Treat a classified missing PDA as terminal in `claim`, `settle`, `finalize_close`, and `reclaim`; delete only after confirming absence, not for transient RPC/decode errors.
- Skip non-Open channels in `settle` before packing transactions.
- Check historical transaction status and confirmed channel state before validating a retrying open transaction's `openSlot`.
- Decode settlement ATAs and require initialized, unfrozen accounts with the expected mint and token program.
- Require a non-empty x402 v2 resource URL at batch handler construction, or derive it from the routed request before building the challenge.

## Migration and compatibility

- Add all new `ChannelState` fields with serde defaults.
- Bump `CHANNEL_STATE_SCHEMA_VERSION` only if writers must reject older semantics; otherwise retain version 1 and preserve unknown fields through `extra`.
- Give pending records a 120-second lease, matching `CHARGE_RESERVATION_LEASE`.
- Retain committed records until voucher expiry plus the server settlement window, with a bounded maximum record count per channel.
- Document channel affinity only as a deployment optimization after store-backed reservations enforce cross-replica safety.

## Tests

Add deterministic store-backed tests, using a controllable handler and failing store wrapper:

1. Voucher handler returns 500: reservation is removed; same voucher invokes handler again.
2. Voucher handler succeeds: watermark and committed response persist; same voucher returns cached result and does not invoke handler.
3. Store fails after handler success: retry calls `finish_commit` and does not invoke handler.
4. Process-local guard is absent: two replicas contend; exactly one owns `Reserved`.
5. Initial deposit handler fails: no setup transaction is broadcast and retry remains valid.
6. Initial deposit succeeds then commit fails: retry observes/reuses the confirmed setup transaction and does not invoke handler.
7. Retry after lost HTTP response: return the original charged amount and payment response.
8. Payer directly requests close: subsequent voucher verification rejects after reconciliation.
9. Missing terminal PDA: lifecycle worker removes the durable record; transient RPC failure preserves it.
10. Frozen, wrong-mint, and uninitialized settlement ATAs are rejected before escrow.

Run:

```sh
cargo fmt --check
cargo test -p solana-pay-kit --features "axum,client" batch_settlement
cargo test -p solana-pay-kit --features "axum,client" gate
```

## Delivery order

1. Add state types, reservation helpers, and unit tests.
2. Refactor voucher gate path and replay response storage.
3. Add pending-open/top-up handling.
4. Add lifecycle, ATA, historical retry, and resource conformance fixes.
5. Run the full Rust and integration suites, then update the PR description and reply to Efe and Greptile with test evidence.
