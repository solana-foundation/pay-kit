# `x402/exact`

**Status: scaffold only.** The Solana MPP SDK does not yet ship x402
support. The reference implementation lives in `~/Coding/x402-kit` on
the user's local machine; it is **not** in this remote container. Do
not implement x402 from spec text alone — ask the user to share the
kit's source first.

Spec: <https://docs.x402.org/introduction>
Reference (local-only): `~/Coding/x402-kit` (ask the user for access).

## Scheme

`x402/exact` is the "pay the advertised amount, no more, no less"
scheme. The challenge advertises a single amount; the credential
carries a settlement payload of exactly that amount. This is the
closest analog to `mpp/charge` and the easiest x402 scheme to ship
first.

## When to implement

Wait for the user to confirm:

1. They have a stable x402-kit reference to copy from.
2. The MPP `charge` cells are already passing harness in the new SDK
   (x402 reuses much of the same Solana primitives — splits, fee
   payer, replay store — so MPP-first is the correct order).
3. The x402 scheme strings in `harness/src/implementations.ts`
   have been agreed (likely `"x402:exact"` or similar; do not invent).

If any are missing, leave the row at `—` in the README matrix and
ask the user before proceeding.

## What we know

From the user's notes: the matrix cell name is `x402/exact`. The
intended wire shape is HTTP-402-aligned (same status code as MPP, same
header style). Solana settlement reuses the on-chain transfer
primitives already implemented for `mpp/charge`.

## Hooks for future implementation

When the user supplies the x402-kit reference, this file should be
expanded into a full intent leaf (matching the depth of
`mpp-charge-pull.md`):

1. **Wire format** — challenge header, credential payload, receipt.
2. **Server obligations** — challenge issuance, settlement, replay.
3. **Client obligations** — challenge selection (`extract_payment_scheme`
   should be extended to recognize the x402 scheme), credential build.
4. **Things to pay attention to** — base64 alphabet rules, canonical
   JSON, replay-key namespacing (`x402-exact:consumed:<sig>` vs
   `solana-charge:consumed:<sig>` — they must not collide), how
   `methodDetails` differs from MPP's.
5. **Test plan** — unit + harness. The harness will need a
   new `intent: "x402-exact"` scenario.

## README matrix row

```md
| `x402/exact` | — |
```

Position: top of both client and server matrices (x402 cells before
MPP cells, in spec order — `exact`, `upto`, `batch-settlement`).
