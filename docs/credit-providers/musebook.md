# Musebook credit provider (proposed, unavailable)

`CreditProvider::Musebook` (`"musebook"`) is a recognized name. It is **not available**:
`validate_credit_providers` rejects it on every network, currency and intent, the
same way it rejects `coinflow`. Recognizing the name is not a registration, a
security certification, or an endorsement.

The name stands for one reviewed configuration. It does not accept hook JSON
from customers. That configuration is the program in
[Solizardking/musebook-credit-provider](https://github.com/Solizardking/musebook-credit-provider),
adapted from `solana-foundation/payment-channels@23193ab` `examples/credit-provider`:

- Hooks: `preFund` (phase 0) and `postDistribute` (phase 3) only, entrypoint `b"musebook"`.
- Account resolver: `hook_state(program, owner, mint)`, with four fixed accounts
  (the ledger PDA `[b"musebook-credit", owner, mint]`, the vault ATA, the payer ATA
  and SPL Token). The caller cannot supply any extra accounts.
- Token: original SPL Token only. Token-2022 and wrapped SOL are not supported.

## Requirements for enabling it

- [ ] A deployed program ID for each network (none exists today).
- [ ] A verifiable build hash for each deployment.
- [ ] An upgrade authority and governance decision.
- [ ] A recovery and pause policy (the program has no pause instruction).
- [ ] pay-kit emits the `openWithHooks`, `topUpWithHooks`, `distributeWithHooks` and `withdrawPayerWithHooks` instructions, with the fixed resolver.
- [ ] Payment verification that is independent of the hook-provided state.
- [ ] Maintainer acceptance. Availability stays disabled until then.
