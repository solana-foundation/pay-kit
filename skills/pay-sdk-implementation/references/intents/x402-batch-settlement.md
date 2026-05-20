# `x402/batch-settlement`

**Status: scaffold only.** Reference implementation is
`~/Coding/x402-kit` on the user's local machine. Don't implement from
spec text alone.

Spec: <https://docs.x402.org/introduction>
Reference (local-only): `~/Coding/x402-kit`.

## Scheme

`x402/batch-settlement` is the "accumulate small charges, settle on
chain less often" scheme. Closest MPP analog is the **session intent**:
both batch off-chain authorizations and settle on chain at intervals.

The wire shape is likely:

- Server-signed accumulator state (last-settled cumulative, next-expected sequence).
- Client-signed authorizations (per-request signed amounts).
- Periodic settlement (every N authorizations, or on time elapsed, or
  on session close).

## Relationship to MPP `session`

The MPP session intent already does on-chain batching: the
payment-channels program holds funds; vouchers authorize cumulative
spend; close settles. The biggest implementation overlap with
`x402/batch-settlement` is voucher / cumulative semantics — see
`rust/src/protocol/intents/session.rs::SignedVoucher`
(lines 656-705) and the cumulative monotonicity rule.

When the x402-kit reference is available, much of the voucher logic
can be re-used; only the wire-format names and the on-chain settlement
program differ.

## When to implement

Last in the x402 sequence — after `exact` and `upto` are interop-green.
Batch settlement is the most complex of the three because it requires:

- Lifecycle state in the server (open / accumulate / settle / close).
- A persistent store for partially-accumulated authorizations
  (`store.<ext>` already exists; add new key prefixes).
- Coordination with the on-chain settlement contract (whatever x402
  picks for Solana).

## Hooks for future implementation

1. **Wire format** — to be defined from x402-kit. Expect a tagged
   `action: "open" | "authorize" | "settle" | "close"` similar to MPP
   `SessionAction`.
2. **Server obligations** — accumulator state, replay protection per
   `(channelId, sequence)`, settlement transaction submission.
3. **Client obligations** — sign each authorization, hand the latest
   cumulative back on every API call, request settlement when the
   session ends.
4. **Things to pay attention to**:
   - Replay key includes both channel and sequence.
   - Cumulative monotonicity (same rule as MPP session vouchers).
   - Settle is **idempotent** — multiple settle requests on the same
     cumulative return a cached receipt.
   - Cross-protocol replay: settlement signatures must use a
     namespaced key so an x402 signature cannot be replayed as MPP
     charge or vice versa. Suggested prefixes —
     `x402-batch:consumed:<sig>`, `solana-charge:consumed:<sig>`
     (already used by MPP charge).
5. **Test plan** — unit (sequence monotonicity, replay,
   settle-idempotency), integration (Surfpool full lifecycle), interop.

## README matrix row

```md
| `x402/batch-settlement` | — |
```

Position: third row in both client and server matrices (immediately
above `mpp/charge/pull`).
