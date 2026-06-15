# `x402/upto`

**Status: scaffold only.** Same caveat as `x402-exact.md`: reference
implementation is `~/Coding/x402-kit` on the user's local machine.
Don't implement from spec text alone.

Spec: <https://docs.x402.org/introduction>
Reference (local-only): `~/Coding/x402-kit`.

## Scheme

`x402/upto` is the "pay any amount up to the advertised ceiling"
scheme — the discretionary/tip variant. The challenge advertises a
maximum; the credential carries the chosen amount and the server
settles for the chosen amount, verifying it does not exceed the cap.

## Relationship to MPP

- The MPP charge intent has a single fixed `amount`. The MPP
  `ChargeRequest.validate_max_amount` helper exists for ad-hoc max
  checks (`rust/crates/mpp/src/protocol/intents/charge.rs:61`) — that pattern
  is the closest in-tree analog, but it is not on the wire format
  the way x402/upto is.
- Solana settlement reuses the same instruction whitelist + replay
  store as charge.

## When to implement

After `x402/exact` is shipped and harness-green. The "upto" semantics
add a single check (amount-from-credential ≤ amount-from-challenge)
on top of the exact flow. Don't ship `upto` before `exact`.

## Hooks for future implementation

This file should be expanded after the x402-kit reference is available:

1. **Wire format** — exactly what differs from `exact` (likely the
   challenge's amount field becomes a `maxAmount`, the credential
   echoes the chosen amount, the server checks `<=`).
2. **Server obligations** — same as `exact` plus the cap check.
   Receipt must reference the **actual** amount paid, not the cap.
3. **Client obligations** — UI / API decides the chosen amount up to
   the ceiling; the credential payload carries it.
4. **Things to pay attention to**:
   - Replay key must include the actual amount (or the signature),
     not the cap.
   - Cross-route protection still pins `currency`/`recipient`; the
     amount is bounded by the route's cap, not pinned exactly.
   - Same canonical-JSON / base64 / base58 rules as MPP.
5. **Test plan** — unit (cap enforcement at boundary, below, above),
   integration (Surfpool), harness.

## README matrix row

```md
| `x402/upto` | — |
```

Position: second row in both client and server matrices (between
`x402/exact` and `x402/batch-settlement`).
