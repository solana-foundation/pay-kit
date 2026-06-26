# Payment-channel rent & voucher modes

A payment-channel `open` instruction binds two **independent** roles. Conflating
them is a recurring bug source, so they are tracked separately everywhere the
open is built, validated, or settled.

| Account slot | Role | Recorded as | Enforced at |
|---|---|---|---|
| `[1] rentPayer` | Funds the channel PDA + escrow-ATA rent and co-signs as the transaction fee payer. | `channel.rent_payer` | Must be supplied (matching the recorded value) at `distribute`/`finalize` to receive the rent refund. |
| `[4] authorizedSigner` | The key whose Ed25519 signatures authorize the channel's cumulative vouchers. | `channel.authorized_signer` | Vouchers must be signed by this key. |

These are **orthogonal**. Two axes produce four combinations:

- **Rent / fee funding** — *gasless* (operator funds rent + pays the tx fee) vs
  *self-pay* (the payer funds its own rent + fee).
- **Voucher authority** — *delegated* (the operator signs vouchers) vs *client*
  (a payer-controlled key — e.g. an ephemeral session key — signs vouchers).

## The matrix

| # | Rent/fee funder | Voucher signer | `rentPayer` (slot 1) | `authorizedSigner` (slot 4) | Where it shows up |
|---|---|---|---|---|---|
| 1 | operator (gasless) | operator (delegated) | `operator` | `operator` | `upto`; mpp-session *delegated* strategy |
| 2 | operator (gasless) | payer (client) | `operator` | `payer` | `batch`; mpp-session *client-voucher* strategy |
| 3 | payer (self-pay) | operator (delegated) | `payer` | `operator` | self-pay delegated — **not yet wired** |
| 4 | payer (self-pay) | payer (client) | `payer` | `payer` | self-pay client — **not yet wired** |

## The invariant

The open validator/verifier must check `rentPayer` (slot 1) and
`authorizedSigner` (slot 4) **against their own expected keys** — never a single
conflated key, and never a hardcoded "must be the operator".

Conflating the two slots only works on the **diagonal** (combos 1 and 4, where
the funder and the voucher signer happen to be the same party) and silently
breaks the **mixed** combos:

- **Combo 2** (gasless + client) — the most common one: this is the mpp-session
  client-voucher flow and the `batch` scheme. A validator that expects
  `rentPayer == authorizedSigner` rejects it (`rentPayer = operator` but
  `authorizedSigner = payer`).
- **Combo 3** (self-pay + delegated) — breaks symmetrically once self-pay lands.

The expected `rentPayer` is **the fee payer** (the operator while gasless, the
payer under self-pay), and the expected `authorizedSigner` is **the voucher
signer** (the operator when delegated, the payer in client mode). They must be
passed/validated independently so a future non-gasless (self-pay) mode can pin
`rentPayer = payer` without another refactor.

## Reference implementations

- **mpp sessions** — `verifyOpenTx` (`typescript .../session/on-chain.ts`,
  `go .../server/session_onchain.go`, `rust crates/mpp/src/server/session.rs`)
  checks slot 1 and slot 4 against separate expected keys.
- **x402 schemes** — `validate_open_instruction`
  (`rust/crates/x402/src/server/upto.rs`) takes `rent_payer` and
  `authorized_signer` as separate expected keys: `upto` passes
  `(operator, operator)`; `batch` passes `(operator, authorized_signer)`.

## Settlement

`distribute`/`finalize` must supply the channel's **recorded** `rentPayer` (the
funder). While gasless that is the operator; under self-pay it would be the
payer — so prefer reading `channel.rent_payer` from on-chain state over assuming
the operator, to stay correct across all four combos.
