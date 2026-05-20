# `mpp/subscription`

**Status: not yet implemented in any SDK.** No spec PR has merged; no
Rust reference exists. Include the row in the README compatibility matrix
as `—`, but do not implement.

Spec — to be added at <https://github.com/tempoxyz/mpp-specs> when
proposed. Watch the PR queue for the title `subscription intent`.

## Why this file exists

The compatibility matrix in every SDK's README must list this row so the
matrix is diff-able across languages. Without this leaf, a new SDK might
quietly drop the row and break the cross-language `README.md` table.

## If a user asks to implement it

1. Stop and confirm with the user: *"There is no spec PR for
   `mpp/subscription` yet. Do you have a draft you can share?"*
2. If yes, ask for the spec text and the canonical TS implementation
   (when one exists). The user mentions an `~/Coding/x402-kit` directory
   for x402 work; a parallel `~/Coding/mpp-subscription` or similar
   would be the expected location for a subscription draft.
3. Do **not** invent semantics. Subscriptions are likely to be a
   composition of session + recurring vouchers + automated top-up,
   but the exact wire format, cap-renewal policy, and cancellation
   flow are not yet decided.
4. Until the spec lands, keep the row at `—` in the SDK's README. Do
   not stub out types in code.

## README matrix row

The row must appear in both Client and Server matrices, with the cell
content `—`:

```md
| `mpp/subscription` | — |
```

Order matters: subscription is the last MPP row, immediately under
`mpp/session`. See `references/readme-template.md`.
