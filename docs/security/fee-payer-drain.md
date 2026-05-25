# Fee-Payer Drain Attack Pattern (Cross-SDK Invariant)

This document is the canonical security reference for the fee-payer co-sign threat model in the MPP server SDKs. Every language port that supports fee-payer co-sign MUST enforce the four invariants in [Cross-SDK Invariant](#cross-sdk-invariant) below, and MUST ship regression tests that exercise every attack shape in [Attack Shapes](#attack-shapes).

Sibling follow-up: cross-language compute-budget audit ([#109](https://github.com/solana-foundation/mpp-sdk/issues/109)).

## Background

When a route advertises `methodDetails.feePayer = true`, the server signs the client's raw transaction with the server's fee-payer keypair before broadcasting. The server's signature is unconditional with respect to instruction content unless the server explicitly inspects every instruction. Any instruction the server signs is paid for (lamports) and authorized (signer-as side effects) by the server's fee-payer key.

A malicious client can therefore craft a transaction that contains both the required payment instruction (so the verifier's "I see a transferChecked to recipient for the expected amount" check passes) AND an extra instruction that drains the fee-payer. Without an instruction allowlist plus a source-account guard, the server signs the entire transaction and the drain succeeds.

## Attack Shapes

### 1. SOL Drain via Extra SystemProgram::Transfer

Client constructs an SPL payment transaction (or a SOL payment transaction with a small required amount) and appends one extra `SystemProgram::Transfer { source: FEE_PAYER, destination: ATTACKER, lamports: <large> }` instruction.

Why it works without hardening: the payment-matching code finds the required transferChecked / SOL transfer to the configured recipient and marks the payment as satisfied. The extra system transfer is from the fee-payer (server-controlled key) to an attacker address, which the server's signature is sufficient to authorize.

### 2. SPL Drain via transferChecked Sourced From Fee-Payer ATA

Client appends an SPL `transferChecked` whose source account is the fee-payer's ATA for some mint the fee-payer holds, with the fee-payer pubkey as the authority. The server signs, the SPL transfer is authorized by the fee-payer's signature, attacker receives the fee-payer's tokens.

### 3. Slot-Index Attack (Fee-Payer at Non-Zero Signer Slot)

Client crafts a transaction where the fee-payer is placed at a non-canonical signer slot (e.g. slot 1) alongside an attacker-controlled signer at slot 0 (or vice versa, depending on the SDK's convention). Solana's fee-payer is the first account in `account_keys`; placing the server's pubkey at the wrong slot can confuse a naive verifier into checking the wrong signature slot, or into co-signing on behalf of a transaction whose nominal fee-payer is the attacker.

### 4. Tampered-Details Attack (Client-Supplied `methodDetails.feePayerKey`)

The MPP charge request carries `methodDetails.feePayerKey` (string, base58 pubkey; this is the canonical wire field across all SDKs, see [`typescript/packages/mpp/src/Methods.ts`](../../typescript/packages/mpp/src/Methods.ts) L62, [`go/protocol/solana.go`](../../go/protocol/solana.go) L115, [`python/src/solana_mpp/protocol/solana.py`](../../python/src/solana_mpp/protocol/solana.py) L120, [`rust/src/protocol/solana.rs`](../../rust/src/protocol/solana.rs) L394, [`php/src/Server/SolanaChargeTransactionVerifier.php`](../../php/src/Server/SolanaChargeTransactionVerifier.php) L304, [`ruby/lib/mpp/methods/solana/verifier.rb`](../../ruby/lib/mpp/methods/solana/verifier.rb), [`lua/mpp/server/init.lua`](../../lua/mpp/server/init.lua) L85). A malicious client supplies `methodDetails.feePayerKey = ATTACKER_PUBKEY` while the server's actual signing key is `SERVER_PUBKEY`. If the verifier trusts the client-supplied details field as the source of truth for "who is the fee-payer", it will validate guards (source != fee-payer, slot, etc.) against `ATTACKER_PUBKEY`. The real `SERVER_PUBKEY` then signs a transaction that drains itself.

Source of truth MUST be the server-context fee-payer pubkey (the public key of the server's signer keypair), never a client-controlled field.

## Threat Model

Fee-payer co-sign is the highest-trust operation a charge server performs. The server attaches its signature to a transaction it did not construct. Unlike pull-mode (`PaymentAccept` from a wallet-signed payload), the server here is the second signer on a raw transaction whose every byte came from the client.

Trust boundaries:

| Field                            | Source            | Trust              |
| -------------------------------- | ----------------- | ------------------ |
| Transaction bytes (instructions, account keys, signers) | Client (wire) | Untrusted |
| `methodDetails.feePayer = true`  | Route config (server) | Trusted (declares whether co-sign is enabled for this route) |
| `methodDetails.feePayerKey`      | Client (wire) | Untrusted: it is the client's claim about which pubkey should pay fees. The server MUST NOT use it as the source of truth for guards (2) and (3); it MUST be reconciled with the server-context fee-payer pubkey and rejected on mismatch. |
| Server fee-payer pubkey (e.g. Rust `Config.fee_payer_signer.pubkey()`, PHP `SolanaChargeTransactionVerifier` server-context pubkey, Go server config) | Server context (process memory) | Trusted: this is the only authoritative source for "who is the fee-payer" in guards (2) and (3). |
| Server fee-payer keypair         | Server context (process memory) | Trusted (signing key, never leaves the server) |

Without an instruction allowlist and source-account guard, signing is equivalent to "the server will sign anything the client puts in front of it". With the four invariants below, the server signs only transactions whose instructions match the canonical safe shape and whose drainable sources are not the fee-payer.

## Cross-SDK Invariant

Every server SDK that supports fee-payer co-sign MUST enforce:

1. **Instruction allowlist.** Reject any instruction whose program ID is not on the canonical safe list (SystemProgram for SOL routes, Token / Token-2022 for SPL routes, ComputeBudget for cap-bounded compute instructions, Memo for the memo discriminator on memo routes, AssociatedToken for declared split-recipient ATA creation). Any unknown program ID is a hard reject.
2. **Source-account check on transfer instructions.** Every `SystemProgram::Transfer` and SPL `transfer` / `transferChecked` instruction MUST have its source account compared to the fee-payer pubkey. If `source == fee_payer` (or `source == ATA(fee_payer, mint)` for SPL), reject. This blocks attack shapes (1) and (2).
3. **Signer-slot enforcement.** The fee-payer MUST occupy the canonical signer slot. Solana requires fee-payer at `account_keys[0]`; SDKs MUST verify the configured fee-payer pubkey equals `account_keys[0]` and that the corresponding signature slot is the one the server will populate. This blocks attack shape (3).
4. **Server-context fee-payer pubkey.** The "fee-payer pubkey" used by guards (2) and (3) MUST be derived from the server's signer (the public key of the server-held keypair), not from any client-supplied field. Client-supplied `methodDetails.feePayerKey`, when present, MUST be reconciled with the server's signer pubkey and rejected on mismatch. This blocks attack shape (4).

A passing fee-payer co-sign path is the conjunction of all four. Missing any one re-opens the corresponding attack shape.

## Where Each SDK Enforces

| Language | Allowlist + source-account + slot + server-context fee-payer |
| -------- | ------------------------------------------------------------ |
| Rust     | [`rust/src/server/charge.rs`](../../rust/src/server/charge.rs): `validate_instruction_allowlist` (L1284), `validate_parsed_instruction_allowlist` (L1860), `expected_fee_payer` (L1227) |
| PHP      | [`php/src/Server/SolanaChargeTransactionVerifier.php`](../../php/src/Server/SolanaChargeTransactionVerifier.php): `validateInstructionAllowlist` (L454), invoked from both push (L169) and pull (L216) paths in the same file |
| Ruby     | [`ruby/lib/mpp/methods/solana/verifier.rb`](../../ruby/lib/mpp/methods/solana/verifier.rb): `validate_allowlist` (L191), `expected_fee_payer` (L100), source-vs-fee-payer guards at L128, L156, L158 |
| Lua      | [`lua/mpp/server/solana_verify.lua`](../../lua/mpp/server/solana_verify.lua): `verify_instruction_allowlist` (L330), invoked from the main verify path at L140 |
| Python   | `python/src/solana_mpp/server/mpp.py`: `_validate_instruction_allowlist` (lands with [#106](https://github.com/solana-foundation/mpp-sdk/pull/106)) |
| Go       | `go/server/server.go`: allowlist branch inside `verifyTransaction` (lands with [#101](https://github.com/solana-foundation/mpp-sdk/pull/101)) |

The Rust path is the spine. PHP, Ruby, Lua, Python, and Go port the same four invariants with language-idiomatic surfaces.

## Attack Regression Tests

Every SDK ships regression tests that fail closed when the corresponding invariant is removed.

| Language | Tests | Location |
| -------- | ----- | -------- |
| Python   | `TestInstructionAllowlist` + `TestFeePayerSourceDrainProtection` + `TestFeePayerPubkeySourceOfTruth` (approximately 12 cases covering SOL drain, SPL drain, slot index, tampered details, positive controls) | `python/tests/test_charge_server.py` (lands with [#106](https://github.com/solana-foundation/mpp-sdk/pull/106)) |
| Lua      | `SECURITY: rejects extra SystemProgram transfer sourced from fee-payer on SPL route` (L787), `SECURITY: rejects SPL transferChecked authorized by fee-payer on SPL route` (L855), `SECURITY: accepts SPL payment + ComputeBudget on fee-payer route` (L913) | [`lua/tests/solana_verify_spec.lua`](../../lua/tests/solana_verify_spec.lua) |
| Rust     | `fee_payer_must_be_transaction_fee_payer` (L2884), `fee_payer_cannot_fund_sol_payment_transfer` (L2906), `parsed_allowlist_rejects_extra_spl_transfer_after_required_transfer` (L4906), `spl_fee_payer_rejects_top_level_ata_creation` (L3138), `b34_rejects_push_credential_on_fee_payer_route` (L4136) | [`rust/src/server/charge.rs`](../../rust/src/server/charge.rs) (in-crate `#[cfg(test)]` module) |
| Ruby     | `test_rejects_fee_payer_funding_sol_transfer` (L258), `test_rejects_fee_payer_missing_key_and_mismatch` (L339), `test_rejects_spl_wrong_destination_and_fee_payer_authority` (L569) | [`ruby/test/server_test.rb`](../../ruby/test/server_test.rb) |
| PHP      | `testRejectsFeePayerFundingNativeSolPayment` (L148), `testRejectsFeePayerMismatch` (L209), `testRejectsMissingFeePayerKey` (L220), `testRejectsFeePayerAuthorizingSplTransfer` (L266), `testRejectsFeePayerTokenAccountFundingSplTransfer` (L281) | [`php/tests/SolanaChargeTransactionVerifierTest.php`](../../php/tests/SolanaChargeTransactionVerifierTest.php) |
| Go       | Drain regression suite (lands with [#101](https://github.com/solana-foundation/mpp-sdk/pull/101)) | `go/server/server_test.go` |

Python is the reference suite for new ports because it exercises all four attack shapes plus positive controls. Other languages MAY ship a smaller suite as long as every one of the four attack shapes is covered by at least one negative test, with at least one positive control proving the legitimate payment still passes.

## How to Extend for a New SDK

When porting MPP server support to a new language:

1. Implement the four invariants in [Cross-SDK Invariant](#cross-sdk-invariant) above. Use the Rust spine (`rust/src/server/charge.rs`) as the reference implementation; the function names there (`expected_fee_payer`, `validate_instruction_allowlist`, `validate_parsed_instruction_allowlist`) map one-to-one onto what the new SDK needs.
2. Write attack regression tests that cover every one of the four attack shapes:
   - SOL drain (extra `SystemProgram::Transfer` sourced from fee-payer)
   - SPL drain (`transferChecked` sourced from fee-payer's ATA, or authorized by fee-payer)
   - Slot-index attack (fee-payer at a non-canonical signer slot)
   - Tampered-details attack (`methodDetails.feePayerKey` mismatched with server signer pubkey)
   Each test must assert that the verifier rejects the transaction AND that the server does not broadcast it (no signature attached, no RPC `sendTransaction` call observed). Add at least one positive control that exercises a legitimate payment with fee-payer co-sign and asserts it succeeds.
3. Cite this document from the new SDK's README security section, with a link to the language-specific file:line where each invariant is enforced.
4. Add a row to the two tables above (Where Each SDK Enforces, Attack Regression Tests) when the new SDK lands on `main`.

The cross-language compute-budget audit ([#109](https://github.com/solana-foundation/mpp-sdk/issues/109)) is the sibling follow-up: compute-budget instructions are on the allowlist, but the per-language cap-enforcement logic is audited separately.
