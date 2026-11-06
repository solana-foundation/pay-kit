# Musebook credit provider on devnet

Off by default. `PayKitConfig.credit_providers = [CreditProvider::Musebook]` passes
validation only on `devnet`, where `musebook::DEVNET` pins provider
`97F68uhs5fmvddJxH1LrKytbBXrhx6ZBZwuZAdUdP7QA` and channel `CHNLxBt…`.
Every other network returns `CreditProviderError::Unavailable`.

`musebook::devnet_with_program(id)` builds a devnet-only `Deployment` for another
instance of the same provider code (the channel program stays pinned). The e2e
library resolves it via `musebook::resolve(network, program)`, fed by two explicit fields that must agree: `SessionConfig::credit_program` (server) and `PaymentChannelOpenOptions::credit_program` (client). Both default to `None` (pinned deployment); a non-pinned program on any network other than devnet fails closed. The e2e test sets both from `MUSEBOOK_DEVNET_PROGRAM` (test-only env):

    MUSEBOOK_DEVNET_PAYER=/workspace/secure/mbcp-fresh/deployer.json \
    MUSEBOOK_DEVNET_ISSUER=/workspace/secure/mbcp-fresh/deployer.json \
    MUSEBOOK_DEVNET_PROGRAM=Df3GbKUy4mTUdsMVBtzRHnQatZfyAefFvjCtAvQZLWvH \
    cargo test -p solana-pay-kit --test musebook_devnet -- --ignored --nocapture

## Upgrade authority: decision pending

| Option | Effect |
|---|---|
| Single devnet key (current for the throwaway instance) | Fast iteration. One key can replace the code and, because issuer = upgrade authority at `initialize`, co-sign credit. Devnet only. |
| Squads v4 multisig (what `97F68…` uses: 2-of-3 vault `2jBif…`) | Upgrades and `set_issuer` need M-of-N approvals. Recommended for anything user-facing. |
| Immutable (`solana program set-upgrade-authority --final`) | No future fixes, ever. Issuer must then come from `set_issuer` set before finalizing. Only after an audit. |
