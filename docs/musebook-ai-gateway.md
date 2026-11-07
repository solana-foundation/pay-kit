# Musebook AI Gateway as a credit-provider merchant

Off by default, devnet-only, availability disabled — exactly like the
subscriptions merchant in this PR. This adds the Musebook AI Gateway
(`https://infer.musebook.trade`, catalog at
`https://musebook.trade/ai-gateway`) as a second merchant that can be
paid from a customer's Musebook credit balance once the provider
integration is accepted. Nothing in this change publishes an on-chain
plan, enables the provider on any new network, or touches the
gateway's live per-call x402 path on mainnet.

## What the gateway sells, and the tier in the spec

The gateway is an OpenAI-compatible inference API priced per call in
USDC: Flash $0.005, Standard $0.01, Premium $0.05, Embeddings $0.002.
It publishes no subscription tier. The paywall spec
(`docs/musebook-ai-gateway.paywall.yml`) therefore declares one
constructed tier, grounded in those published prices:

| Tier | Period | Price | Basis |
|---|---|---|---|
| AI Gateway access | `30d` | 9.99 USDC | ~999 Standard calls at the published $0.01 rate |

`period` uses the spec's fixed elapsed-time units (`d`/`w` only;
`month` is rejected by the parser). This is a devnet integration
price, not a live product price.

## Flow choice

Per the merchant guide: one fixed-price response → channel-backed MPP
charge; multiple metered deliveries → MPP session. The gateway sells
metered deliveries, so it uses the **MPP session** flow — the same
flow this PR's subscriptions merchant uses. The spec's
`subscription:` endpoint rides that flow: a caller that has not
activated gets a 402 with `intent="subscription"`; the first call
settles one period's charge from the customer's credit-backed
channel; calls inside the period pass without a new payment.
`subscription:` and `metering:` are mutually exclusive on an endpoint;
the gateway's existing per-call sales stay on its separate x402 path,
not on this spec.

## Plan publication (operator step, not done by this PR)

The YAML alone does not serve traffic: the gateway refuses a
subscription endpoint until the corresponding on-chain Plan PDA
exists. On first launch the sandbox flow publishes it and writes the
plan address back into the spec:

```
pay --sandbox gate api docs/musebook-ai-gateway.paywall.yml
```

It derives the deterministic Plan PDA, prompts to broadcast
`create_plan` (sandbox covers rent in the sandbox flow), and writes
`plan_id`, `plan_id_numeric`, `plan_bump` and `plan_created_at` into
the YAML; commit the updated file. For a non-interactive derive-only
check: `pay server plans publish --dry-run --owner <pubkey>`. The
`plan_id` in the committed spec stays empty until an operator runs
this — deliberately.

## Merchant policy and Rust configuration

Operator policy sits beside the accepted currencies; an empty list
enables no credit providers and preserves ordinary payment behavior:

```yaml
operator:
  currencies:
    usd: [USDC, USDT]
  credit_providers: [musebook]
  network: 'devnet'
```

The same selection in pay-kit is a policy value:

```rust
use solana_pay_kit::{CreditProvider, PayKitConfig};

fn merchant_config(recipient: impl Into<String>) -> PayKitConfig {
    PayKitConfig {
        recipient: recipient.into(),
        currency: "USDC".into(),
        network: "devnet".into(),
        credit_providers: vec![CreditProvider::Musebook],
        // Supply RPC, signer, and challenge secret through service
        // setup. Never embed production keys or secrets in source.
        ..Default::default()
    }
}
```

Two honest boundaries, both enforced in code on this branch:

- `validate_credit_providers_for_network` passes `Musebook` only
  where a deployment is pinned (devnet); it is `Unavailable` on
  mainnet and every other network, and `Coinflow` is unavailable
  everywhere.
- The unified `PayKit` gate still fails closed for *any*
  `credit_providers` selection: its charge/x402 handlers cannot accept
  credit payments. The working surface is the MPP **session server**,
  configured the way the in-crate Musebook tests configure it:

```rust
use solana_pay_kit::mpp::server::session::SessionConfig;
use solana_pay_kit::{musebook, CreditProvider};

// On top of the merchant's ordinary session fields (operator,
// recipient, currency, voucher signer, RPC, ...):
cfg.network = "devnet".into();
cfg.channel_program = Some(musebook::DEVNET.channel_program()); // pinned V2 program
cfg.channel_version = Some(2);                                  // hooked ABI
cfg.credit_provider = Some(CreditProvider::Musebook);
cfg.credit_issuer_signer = Some(issuer_signer); // required: co-signs `authorize`
cfg.credit_max_cap = Some(9_990_000);           // one period: 9.99 USDC, 6 decimals

// Fails closed on any mismatch — wrong network, V1 program/ABI,
// static hooks alongside the provider, Token-2022, a sponsor, or a
// missing issuer signer. A credit session never degrades to an
// unhooked channel:
let deployment = cfg.credit_deployment()?;
```

## Failures and restarts

- **Durable storage.** Hooked-session state must be durable (the
  Redis-backed store); the memory-backed session path does not
  support hooked sessions. Charge submission and receipt records need
  the same durability.
- **Keep the original configuration.** Recovery uses the channel's
  saved provider policy and hook commitment — the pinned deployment
  above — not whatever defaults are configured after a restart.
- **Callbacks are an availability dependency.** A failing mandatory
  provider callback can block funding or distribution; failed
  transactions roll back transfers but can still cost fees.
- **Transaction size.** Credit opens carry the hook accounts and the
  `[Approve, authorize]` pair; this branch requests the pinned
  400,000 CU ceiling for credit opens. Confirm wallet/client support
  for the complete transaction before relying on it.

## Scope

Networks: devnet only. Tokens: USDC (classic SPL) through the pinned
provider deployment `97F68uhs5fmvddJxH1LrKytbBXrhx6ZBZwuZAdUdP7QA`.
x402 credit-provider support is not part of this implementation; the
gateway's x402 per-call path is unchanged. Availability stays disabled
in production builds until the provider integration is accepted.
