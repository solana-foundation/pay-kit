# Musebook Unlimited — subscription plan

**Status: devnet-only. This plan is not live and no billing exists today.**
The plan activates only when the Musebook credit provider is accepted by the
pay-kit maintainers for the reviewed scope (see PR #411 / PR #414 and the
stacked parity branches). Nothing in this document is a claim of mainnet or
production support.

## The plan

| | |
|---|---|
| Name | **Musebook Unlimited** |
| Price | **$19.99 / month** |
| Includes | Unlimited AI and services on Musebook, subject to the provider's reviewed scope and fair-use terms set at activation |
| Cycle | Monthly, charged through a Musebook credit-provider session |
| Payment | USDC on Solana, **or** $CLAWD at the USD-equivalent amount priced at charge time |

## Paying in USDC

- Amount: **19.99 USDC** (USDC has 6 decimals → `19_990_000` base units).
- The subscriber deposits USDC into their Musebook credit ledger; credits are
  issued 1:1 in base units. The monthly charge is drawn through the credit
  session flow below.

## Paying in $CLAWD

- Token: **$CLAWD**, mint `8cHzQHUS2s2h8TzCmfqPKYiM4dSt4roa3n7MyRLApump`.
- Amount: the **USD-equivalent of $19.99 at charge time** — a dynamic
  conversion, never a hard-coded token count. The price is read at the moment
  of the charge; the token amount is `19.99 / CLAWD_USD_price`, converted to
  base units using the decimals read from the mint account at charge time.
- Price sources: Jupiter price API (primary) and DexScreener (cross-check),
  the same public price sources used elsewhere in the Musebook stack. If the
  two sources disagree beyond a small tolerance, or no fresh price is
  available, the charge is refused rather than guessed (fail closed).
- The provider custodies classic SPL Token mints only; $CLAWD is a classic
  SPL mint, so it is depositable under the same rule as USDC.

## How a monthly charge runs (credit-provider session flow)

1. **Deposit** — the subscriber deposits the backing token (USDC or $CLAWD)
   into their provider ledger; credits are issued 1:1 in base units.
2. **Authorize** — owner + issuer bind one channel incarnation with a cap at
   least the monthly amount (`credit_max_cap` server-side bounds what the
   issuer co-signs) and an expiry inside the issuer window
   (≤ 9,000 slots past the open slot).
3. **Open session** — the subscriber opens a V2 payment channel whose
   `pre_fund` / `post_distribute` hooks are the provider's per-payer hooks;
   the challenge advertises `methodDetails.creditProvider: "musebook"` and
   `creditIssuer`. Devnet only; pinned channel program; SPL Token only; no
   static hooks; no sponsored (fee-payer) opens.
4. **Charge** — the monthly amount is vouchered/settled against the session
   up to the authorized cap. Hooked instructions request the 400k CU ceiling.
5. **Close / settle / distribute** — at cycle end (or cancellation) the
   channel closes and distributes.
6. **Refunds** — refunds restore credits **only from actually recovered
   refunds**: the amount that returns to the ledger vault on distribution is
   what re-credits the subscriber. A zero refund restores zero credits. This
   is the provider's standing rule and is not negotiable per-plan.

## Availability

- Devnet only today (provider program `97F68uhs…`, Squads 2-of-3 governed).
- The `musebook` provider name validates in `PayKit` only where a reviewed
  deployment is pinned; everywhere else it returns `Unavailable`.
- Plan activation, pricing-page publication, and any mainnet scope each
  require maintainer acceptance of the corresponding reviewed deployment —
  none of that is claimed here.
