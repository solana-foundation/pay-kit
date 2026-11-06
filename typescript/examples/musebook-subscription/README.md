# Musebook Unlimited — devnet subscription charge example

A worked example of a monthly subscription charged through the **Musebook
credit provider** (pay-kit PRs #411/#414 and the stacked parity branches),
implementing the plan in
[`docs/musebook-subscription-plan.md`](../../../docs/musebook-subscription-plan.md):
**$19.99/month**, unlimited AI and services, payable in USDC on Solana or in
$CLAWD at the USD-equivalent amount priced at charge time.

> **Devnet only.** The Musebook provider has a reviewed deployment on
> devnet only. This example refuses to run against any other cluster (it
> checks the RPC genesis hash), and the plan is not live billing — it
> activates only when the maintainers accept the provider for a reviewed
> scope.

## Why it lives here

`typescript/examples/` is where this repo keeps runnable TypeScript
examples (`playground-api` is the other one). `playground/` at the repo
root is a browser app, and `harness/` is the cross-language conformance
rig — neither is a home for a single-flow SDK example. This example is a
standalone workspace (own `package.json`, like `playground-api`) that
depends on `@solana/mpp` by relative path.

## What it does

1. **Gate** — reads `MUSEBOOK_DEVNET_PAYER` / `MUSEBOOK_DEVNET_ISSUER`
   keypair files (same env-gating as the Rust devnet test,
   `rust/crates/kit/tests/musebook_devnet.rs`). Without them it prints
   `SKIPPED` and exits. With them, it verifies the RPC genesis hash is
   devnet's and fails closed otherwise.
2. **Price** — USDC: the fixed `19_990_000` base units. $CLAWD: a live
   price from Jupiter cross-checked against DexScreener (disagreement
   beyond 5% or no quote → refuse), converted with the decimals read
   from the mint account at charge time. The token count is never
   hard-coded.
3. **Challenge** — builds the merchant session server in-process with
   `creditProvider: 'musebook'`, the pinned V2 channel program, the
   issuer signer, and `creditMaxCap` = one monthly amount; the issued
   challenge advertises `creditProvider`, `creditIssuer`,
   `channelVersion: 2`.
4. **Derive** — the client derives the channel and the provider's exact
   per-payer hooks from the challenge (SDK parity surface), refusing
   every degraded variant.
5. **Authorize** — builds `[Approve(cap), authorize]` with the SDK and
   submits it: payer signs, issuer co-signs, 400k CU limit.
6. **Open** — assembles the base open instruction and transforms it to
   **OpenWithHooks** with `v2-hooks.ts`, a local port of the Rust V2
   builders (`rust/crates/kit/src/core/payment_channel/v2.rs`). This
   port exists because the SDK's generated TypeScript client targets
   the V1 channel program; when a generated V2 client lands, this file
   should be deleted in favor of it.
7. **Charge** — the session key vouchers the full monthly amount; the
   merchant side verifies the voucher against the channel terms with
   the SDK's `verifyVoucherForChannel`.
8. **Close / settle / refund** — settlement must wait out the channel's
   grace period (900s in the example), so the example stops after
   printing the operator sequence: request close → wait → settle_and_seal
   → `DistributeWithHooks` → `WithdrawPayerWithHooks` (transforms for
   the last two are in `v2-hooks.ts`). **Refunds restore credits only
   from actually recovered refunds**: the amount the hooked
   distribution/withdraw returns to the provider ledger vault is what
   re-credits the subscriber; a zero recovery restores zero credits.

## Run

```sh
cd typescript/examples/musebook-subscription
pnpm install
MUSEBOOK_DEVNET_PAYER=/path/payer.json \
MUSEBOOK_DEVNET_ISSUER=/path/issuer.json \
pnpm start
```

Optional env: `MUSEBOOK_DEVNET_RPC_URL`, `MUSEBOOK_DEVNET_PROGRAM`
(devnet-only provider override), `MUSEBOOK_SUBSCRIPTION_ASSET=usdc|clawd`,
`MUSEBOOK_DEVNET_CLAWD_MINT` (required for `asset=clawd` — the mainnet
$CLAWD mint does not exist on devnet), `MUSEBOOK_DEVNET_MERCHANT`.

The payer needs devnet SOL for fees/rent and devnet USDC (or the
configured asset) for the deposit.
