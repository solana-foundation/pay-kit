# Codex Review — Ruby x402 (Round 5, fee-payer drain fix)

PR: pay-kit#127 — Ruby x402 exact (client + server)
Branch tip: `pr/ruby-x402-port` (after fee-payer ATA-drain fix)

## Scope of this round

Close the inherited P1 fee-payer ATA drain at
`ruby/lib/x402/exact.rb`. Rename the existing in-instruction-accounts
guard to `reject_fee_payer_in_instruction_accounts!`, add an explicit
carve-out for the legitimate `AssociatedTokenAccount::Create` /
`CreateIdempotent` funding-payer slot (account-position 0), and add
attack regression tests for the canonical drain shapes.

## Codex findings

### P1 (must-fix)

None.

The previously inherited P1 (fee-payer ATA drain at
`ruby/lib/x402/exact.rb`) is closed. Codex confirmed:

1. `reject_fee_payer_in_instruction_accounts!` sweeps every instruction
   and every account index via `instructions.each` plus
   `accounts.each_with_index`.
2. The only carve-out is ATA program plus `Create` / `CreateIdempotent`
   data, and only `position.zero?` is skipped. `ata_create_data?`
   accepts only empty data, `0x00`, or `0x01`.
3. The three attack regressions assert exactly
   `invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts`:
   extra SPL `TransferChecked`, `SystemProgram::Transfer`, and fee
   payer at instruction-account slot 1. The clean-envelope positive
   control correctly asserts successful settlement.

### P2 (should-fix follow-up, pre-existing scope)

1. **Harness adapter paths use the pre-rename `tests/interop` depth.**
   From `harness/`, `../../rust/Cargo.toml` and `cd ../../ruby` resolve
   outside the repo. Carried forward from the original r5 review.
2. **Ruby x402 server hardcodes `/protected` and
   `x-fixture-settlement`.** Should honor `X402_INTEROP_RESOURCE_PATH`
   and `X402_INTEROP_SETTLEMENT_HEADER` for cross-spine parity.
   Already tracked in the original r5 follow-up list.
3. **Ruby x402 success responses omit `PAYMENT-RESPONSE`.** Rust and
   TS interop servers return it on settlement success; Ruby does not.
   Protocol-parity follow-up, out of scope for the drain fix.

### Looks OK

- Sweep ordering: runs before the optional-program allowlist loop, so
  the canonical reject token is the fee-payer reason rather than the
  generic "unknown N-th instruction".
- Carve-out scope: only `AssociatedTokenAccount::Create` /
  `CreateIdempotent` accept fee payer at slot 0; every other position
  and every other program rejects.
- Strict base64 decoding and sign-then-verify ordering unchanged.

## Verdict

- **0 P1** (inherited fee-payer ATA drain closed; no new P1
  introduced).
- **3 P2** carried over from the original r5 follow-up list — all
  pre-existing, none introduced by the drain fix.
- Confidence: **medium-high** static (Ruby static-only review;
  full suite executed locally with all 208 tests passing).

## Local test summary

`bundle exec rake test` — 208 runs, 718 assertions, 0 failures, 0
errors, 0 skips. The four new attack regression tests
(`test_settlement_rejects_extra_token_transfer_naming_fee_payer`,
`test_settlement_rejects_extra_system_transfer_from_fee_payer`,
`test_settlement_rejects_fee_payer_at_instruction_slot_one`,
`test_settlement_accepts_clean_envelope_positive_control`) all pass.
