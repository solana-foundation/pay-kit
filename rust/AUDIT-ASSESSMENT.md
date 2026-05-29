# Audit Assessment — Solana MPP (Rust)

Source: `Solana - MPP-findings-export-2026-05-26.json` (45 findings)
Code reviewed at branch: `fix/rust-audit`
Assessor: Ludo + Claude

Legend for **Decision**:
- ✅ accept — fix as recommended
- 🟡 partial — fix differs from audit recommendation
- ❌ reject — won't fix (with rationale)
- ⏳ pending — not yet reviewed

---

## Medium severity

### #38 — Primary recipient of challenge can be in list of splits
**ID:** `b4dfcf0b` · **File:** `crates/mpp/src/{server,client}/charge.rs`

**Audit claim:** Spec §9.5 forbids ATA-creation for the top-level recipient. Server/client never reject a split whose `recipient` equals the top-level `recipient`, so a fee-sponsored challenge could pay to (re)create the primary recipient's ATA — exploitable as a slow drain by closing/recreating.

**Current code:** Still as described.
- `server/charge.rs:307` `validate_charge_options` — no check.
- `server/charge.rs:1185` `expected_ata_creation_policy` — primary recipient not excluded.
- `client/charge.rs:113` — client signs whatever it gets.

**Decision:** 🟡 **partial — reject the strict ban, add a misconfig guard. Fixed.**

**Rationale:** Having the primary recipient appear in `splits` is a legitimate use case we want to support (e.g., the merchant takes part of the funds as a split alongside other splits). Forbidding the recipient in splits would over-constrain the protocol. The actual drain shape is the *combination* primary-in-splits + `ataCreationRequired: true` in fee-sponsored mode, so we narrow the check to that combination.

**Threat model framing:** this is a server misconfig (the only party harmed is the server's own fee-payer wallet — a malicious recipient can only trigger the loop if the server already authored a challenge with this shape). So the gate belongs server-side, before HMAC; no client guard, no verify-side defense-in-depth.

**Action taken:**
- Added an early loop in `validate_charge_options` (`server/charge.rs:396`) that rejects with `Error::InvalidConfig` when any `split.recipient == self.recipient` AND `split.ata_creation_required == Some(true)`. Runs before the existing SPL-gating checks so the message points at the actual misconfig rather than a downstream consequence.
- The lower-level `charge_challenge_with_options` path (and its `validate_charge_request`) is intentionally *not* tightened — that path is the "trusted construction escape hatch" documented for callers who need to issue challenges for a different route. Audit #19's HMAC validation already pins network/currency/recipient/token program on that path.
- New tests:
  - `charge_with_options_rejects_primary_recipient_with_ata_creation_required` — negative case.
  - `charge_with_options_allows_primary_recipient_in_splits_without_ata_creation` — positive case (the legitimate use the strict ban would have over-blocked).

---

### #32 — Missing checks in `find_sol_transfer`
**ID:** `923a9c9b` · **File:** `crates/mpp/src/server/charge.rs:1710`

**Audit claim:** `find_sol_transfer` matched on `parsed.type == "transfer"` + `info.lamports` + `info.destination` only — no `programId` check and no `source` check. Defense-in-depth gap (parsed format is System-Program-specific in practice) plus a real risk that in fee-sponsored mode the server (fee payer) could end up bankrolling the value transfer.

**Decision:** ✅ **accepted — fixed.**

**Action taken:**
- Added `programId == System Program` check via the existing `parsed_program_id()` helper.
- Read `info.source` and reject when `source == fee_payer` (matches the policy of the lower-level `verify_sol_transfer_instructions:1485` — separation of duties: fee payer covers gas, not value).
- Threaded `fee_payer: Option<&str>` through `verify_sol_transfers` and the parsed-credential caller (passes `expected_ata_payer`, which is `Some(fee_payer_key)` only in fee-sponsored mode).
- Updated all 6 existing parsed-instruction tests to carry `program: "system"` + `info.source`. Added 2 new tests:
  - `find_sol_transfer_rejects_non_system_program`
  - `find_sol_transfer_rejects_source_equals_fee_payer`

**Note on "source = expected payer":** the audit suggested checking source against the expected payer. The lower-level path's policy is asymmetric (forbid `source == fee_payer`, allow anything else). We mirrored that policy rather than tightening, so the two verification paths behave identically.

---

### #29 — Push-mode SPL verification ignores the source ATA
**ID:** `45c6d39f` · **File:** `crates/mpp/src/server/charge.rs:1801`

**Audit claim:** `find_spl_transfer` matched `transferChecked` instructions on `info.mint`, `info.tokenAmount.amount`, and derived destination ATA only. It never read `info.source` or `info.authority`, so in fee-sponsored mode the server's fee-payer signature could be re-used to fund the value transfer via its own ATA — same drain shape as #32, but on the SPL side.

**Decision:** ✅ **accepted — fixed.**

**Action taken:** mirror the lower-level path (`verify_spl_transfer_instructions:1586`):
- Read `info.authority` and reject when `authority == fee_payer`.
- Read `info.source` and reject when `source == fee_payer's ATA` (PDA derived from `[fee_payer, token_program, mint]` against the ATA program). Required even when the authority is a delegate.
- Threaded `fee_payer: Option<&str>` through `verify_spl_transfers` and the parsed-credential caller.
- Updated the 4 existing SPL parsed tests to take the new arg (`None`). Added 2 new tests:
  - `find_spl_transfer_rejects_authority_equals_fee_payer`
  - `find_spl_transfer_rejects_source_equals_fee_payer_ata`

**Note on alternative recommendation:** the audit also suggested deriving the *expected source ATA* (from the signer/payer) and rejecting anything else, gating arbitrary sources behind a flag. We didn't take this route because the model already accepts delegate/multisig flows by design, and forcing source = signer's ATA would break that. The fee-payer exclusion is the narrower, sufficient fix.

---

### #28 — Incorrect default fallback resolving mint to token program
**ID:** `048bfd43` · **Files:** `crates/mpp/src/protocol/solana.rs`, `crates/mpp/src/server/charge.rs`

**Audit claim, two parts:**
1. `default_token_program_for_currency` only recognized `CASH` as Token-2022; PYUSD (also Token-2022) fell back to legacy Token.
2. Server falls back to the same guess instead of fetching the mint owner on-chain (spec §7.2), so a challenge generated for an arbitrary Token-2022 mint will go out with the wrong `tokenProgram`.

**Status when reviewed:**
- Part 1: **already fixed in prior work.** `stablecoin_uses_token_2022` now covers PYUSD/USDG (mainnet+devnet) and CASH.
- Part 2: still valid for arbitrary mint addresses outside the known list.

**Decision:** ✅ **accepted — fixed, resolved at boot rather than per-challenge.**

**Action taken:**
- Added `is_known_stablecoin_mint()` helper in `protocol/solana.rs` to distinguish the static-table path from arbitrary mints.
- Added `resolve_server_token_program(rpc, currency, network)` in `server/charge.rs`:
  - `SOL` → `None`.
  - Known stablecoin symbol/mint → answer from the static table.
  - Arbitrary mint address → parse as `Pubkey`, fetch the mint account, return its owner. Reject if the owner is not the Token Program or the Token-2022 Program. Reject if the currency parses as neither a known symbol nor a valid pubkey.
- Resolution runs once in `Mpp::new` and the result is cached on `Mpp.token_program: Option<&'static str>`. No per-challenge RPC fan-out; servers fail fast at boot if the mint is unreachable or has an unexpected owner.
- Challenge generation now emits `tokenProgram` straight from `self.token_program` (omits it for SOL).
- The parsed-credential verifier no longer falls back to `default_token_program_for_currency` when `methodDetails.tokenProgram` is missing — it prefers the embedded value, then `self.token_program`, then errors out.
- Updated the docstring on `default_token_program_for_currency` to warn that it is the static-table path only and callers handling arbitrary mints MUST go through the RPC-backed resolver.
- New tests: `new_resolves_token_program_for_sol_currency`, `_for_usdc`, `_for_pyusd_token_2022` (regression for part 1), `new_rejects_unparseable_currency_without_rpc`. RPC-backed arbitrary-mint path is exercised by integration tests in `tests/charge_integration.rs` against the localnet.

---

### #26 — Client signs arbitrary mint-address currencies (Token-2022 hook risk)
**ID:** `5e1a1d39` · **Files:** `crates/mpp/src/client/charge.rs`, `crates/mpp/src/protocol/solana.rs`

**Audit claim:** Spec §13.3 requires clients, if `currency` is a mint address, to verify it is a known token. Today the client passes any mint through and only checks the owner is `TOKEN_PROGRAM` or `TOKEN_2022_PROGRAM`. An arbitrary Token-2022 mint can ship **transfer hooks** that execute arbitrary code on every transfer; the server's pre-broadcast checks don't simulate inner instructions in pull mode.

**Decision:** ✅ **accepted — two-tier gate, with opt-in.**

**Rationale:** A pure allowlist breaks the "arbitrary mints first-class" story we just leaned into for #28 (server-side). But transfer hooks are the actual hostile surface, and they only exist on Token-2022. The vanilla Token Program has no hooks, so arbitrary mints there stay first-class.

**Action taken:**
- Added `BuildChargeTransactionOptions::allow_unknown_token_2022` and `SelectChargeChallengeOptions::allow_unknown_token_2022` (both `bool`, default `false`).
- In `build_spl_instructions`: after `resolve_token_program`, if the token program is Token-2022 AND the mint is not in `is_known_stablecoin_mint`, refuse to sign unless the caller opted in.
- In `select_charge_challenge`: a new `challenge_is_unknown_token_2022` helper rejects candidates whose currency is an unknown mint when `methodDetails.tokenProgram` is either Token-2022 or missing (we cannot prove it isn't Token-2022). Vanilla `Token Program` hint allows the candidate through.
- Added `build_credential_header_with_options` so callers can opt in without dropping to the lower-level builder.
- New tests:
  - `build_spl_refuses_unknown_token_2022_without_opt_in`
  - `build_spl_allows_unknown_token_2022_with_opt_in`
  - `build_spl_allows_unknown_vanilla_token_mint`
  - `build_spl_does_not_gate_known_token_2022_stablecoin`
  - `select_charge_challenge_skips_unknown_token_2022_by_default`
  - `select_charge_challenge_skips_unknown_mint_with_no_token_program_hint`
  - `select_charge_challenge_accepts_unknown_vanilla_token_mint`
  - `select_charge_challenge_allows_unknown_token_2022_with_opt_in`
  - `select_charge_challenge_does_not_gate_known_token_2022_stablecoin`

**Note on departing from the audit recommendation:** the audit asked for a plain allowlist with opt-in. We split it on the actual threat axis (Token-2022 vs. Token) so unknown plain-Token mints don't need an opt-in dance. The opt-in still exists for the unsafe case.

---

### #25 — Fee-sponsored pull mode lets clients inflate priority fees
**ID:** `b6791d00` · **Files:** `crates/mpp/src/server/charge.rs:42` (caps), `:1388` (caller), `:1448` (validator)

**Audit claim:** Client builder emits `compute_unit_price=1, limit=200_000`. Server caps at `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS=5_000_000`. In fee-sponsored pull mode the server signs *before* broadcast, so an attacker can pick a price up to the cap and the merchant pays the priority fee. Per spec math `priority_fee_lamports = ceil(price × limit / 1_000_000)`, that's up to `1_000_000` lamports (0.001 SOL) per "valid" charge — ≈200× the base fee, run in a loop = drain.

**Decision:** ✅ **accepted — tight cap in fee-sponsored mode, general cap untouched.**

**Action taken:**
- Added `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS_FEE_SPONSORED = 10_000` (worst-case priority fee `ceil(10_000 × 200_000 / 1_000_000) = 2_000 lamports`, ≈20% of the per-signature base fee — enough room for honest clients to bump priority during congestion).
- `validate_compute_budget_instruction` now takes a `fee_sponsored: bool` and applies the tight cap when set.
- `validate_instruction_allowlist` passes `fee_payer.is_some()` — `fee_payer` is `Some` precisely when the server is acting as the fee payer.
- Client-paid mode (fee_payer not configured) keeps the 5_000_000 ceiling; the client is paying its own gas, no merchant risk.
- New tests:
  - `compute_unit_price_fee_sponsored_under_tight_cap_passes`
  - `compute_unit_price_fee_sponsored_above_tight_cap_rejected`
  - `compute_unit_price_client_paid_above_tight_cap_passes` (regression: tight cap MUST NOT apply when the client is paying).

**Note on alternative (b):** the audit also suggested locking to exact `price=1, limit=200_000` (the client builder's values). We chose the tight-cap shape so non-default-tooling clients can still tune priority during congestion without lockstep changes to the server.

---

### #24 — Weak secret key accepted
**ID:** `b7c1edc5` · **File:** `crates/mpp/src/server/charge.rs` (`Mpp::new` / `detect_secret_key`)

**Audit claim:** Both the `Config.secret_key` path and the `MPP_SECRET_KEY` env-var path accepted any string — empty, `"key"`, etc. That string is the HMAC-SHA256 key binding challenge IDs, so a weak key lets an attacker forge challenges.

**Decision:** ✅ **accepted — fixed, strict 32-byte minimum.**

**Action taken:**
- Added `MIN_SECRET_KEY_BYTES = 32`, matching NIST SP 800-107 guidance for HMAC-SHA256 (key ≥ hash output length).
- New `validate_secret_key()` runs in `Mpp::new` after the value is resolved from either `Config.secret_key` or the env var — both paths share the same gate.
- Updated the `Config.secret_key` docstring to require ≥ 32 bytes of cryptographically-random data and reference `openssl rand -base64 32`.
- Updated test secrets across `src/server/{charge,axum}.rs` and `tests/charge_integration.rs` to ≥ 32-byte strings; `"key"` literals in unit tests now use the existing `TEST_SECRET` constant.
- New tests: `new_rejects_empty_secret_key`, `new_rejects_short_secret_key`, `new_accepts_secret_key_at_minimum_length`, `new_rejects_short_env_secret_key` (regression: the env-var path must apply the same gate).

**Note on threshold choice:** the audit asked for "a documented minimum size" without a number. 32 bytes is the cryptographically right answer for HMAC-SHA256; a permissive 16-byte minimum would have spared a few test churn but locks in an under-strength default for years.

---

### #20 — Implicit client-funded split ATA creation
**ID:** `8d8dab0e` · **File:** `crates/mpp/src/client/charge.rs:498`

**Audit claim:** In client-paid mode the client builder auto-created ATAs for every split, ignoring `ataCreationRequired`. A hostile server could attach N dust splits to a challenge and force the client to pay N × ~0.002 SOL of ATA rent.

**Spec position (re-verified against draft-solana-charge-00):**
- §7.2 — "When `ataCreationRequired` is `true`, the client MUST include an idempotent ATA-create instruction…"
- §9.5 — "Clients MUST NOT include **fee-payer-funded** ATA creation instructions for the top-level `recipient`, unmarked split recipients, or arbitrary owners."

So the spec mandates creation only when flagged; the §9.5 ban is narrower than the audit suggested (it only restricts fee-payer-funded creation), but the *threat* — silent rent drain on the client — is real regardless of mode.

**Decision:** ✅ **accepted, client-only fix.**

**Action taken:** changed the create-ATA gate at `client/charge.rs:498` from
```
create_ata = fee_payer.is_none() || split.ata_creation_required == Some(true)
```
to
```
create_ata = split.ata_creation_required == Some(true)
```
Same flag, both modes. Updated `build_spl_with_splits` and `build_spl_with_split_memo` to reflect the new behaviour (no auto-create, fewer ixs); added `build_spl_creates_split_ata_only_when_flagged` to lock in the positive case.

**Why client-only:** Server-side `expected_ata_creation_policy` is permissive in client-paid mode (`allowed_owners = all split owners`), which is consistent with the spec (it only forbids *fee-payer-funded* ATA creation). Tightening the server would break integrators with legitimate auto-create flows on their own clients. The drain attack the audit identified is closed once *our* SDK client refuses to emit unflagged ATA-creates.

**Honest-flow impact:** servers that need clients to fund split ATAs MUST now set `ataCreationRequired: true` per split. Servers that forget the flag will see the receiving transfer fail on-chain instead of silently charging the client — clearer failure mode.

---

### #19 — Full `ChargeRequest` signed without validation
**ID:** `0fe8cced` · **File:** `crates/mpp/src/server/charge.rs:432`

**Audit claim:** `charge_challenge_with_options` HMAC-signed a caller-supplied `ChargeRequest` directly. Nothing checked `amount`, `currency`, `recipient`, `network`, `decimals`, `feePayer`, `tokenProgram`, or `splits`, so a buggy or hostile caller could produce a *cryptographically-valid* challenge with malformed or off-route contents.

**Decision:** ✅ **accepted — validate, both internally and against `self`.**

**Action taken:** added `Mpp::validate_charge_request` and call it at the top of `charge_challenge_with_options`. The check enforces:
- `amount` parses as `u64` (reuses `ChargeRequest::parse_amount`).
- `currency` matches `self.currency` (case-insensitive).
- `recipient` is `Some(..)` and parses as a `Pubkey`.
- `methodDetails` (if present) deserializes as `MethodDetails` and each pinned field matches `self`: `network`, `decimals`, `tokenProgram` (against the boot-resolved `self.token_program`).
- Each `split` carries a parseable recipient `Pubkey` and a `u64` amount.

`fee_payer`/`feePayerKey` are left untouched — the high-level path already accepts a per-request fee-payer override (`options.fee_payer || self.fee_payer`), and audit #11 (`#1335d2de`) handles the orthogonal `feePayer=true` with no signer case.

Callers who legitimately need to issue challenges for a *different* route still have `PaymentChallenge::with_secret_key_full` as a public escape hatch — the trusted construction path the audit's recommendation refers to.

**New tests:** `charge_challenge_rejects_mismatched_currency`, `_missing_recipient`, `_invalid_recipient`, `_unparseable_amount`, `_mismatched_network_in_method_details`, `_mismatched_token_program`, `_invalid_split_recipient`.

---

### #10 — Client signs untrusted charge challenges
**ID:** `ad99fed8` · **File:** `crates/mpp/src/client/charge.rs`

**Audit claim:** `build_credential_header` / `build_charge_transaction` decode the challenge and produce a signed transaction with no client-side policy enforcement (max amount, expected recipient/currency/network, expiry, split shape). Safe only when the caller has already validated the challenge; *unsafe* for auto-pay integrations where the server effectively controls what gets signed against the user's wallet.

**Decision:** ✅ **accepted — narrow opt-in gates, plus always-on expiry.**

**Rationale:** The protocol's working trust model assumes a human reviews the challenge before signing. Auto-pay agents break that, and that's the case the audit is calling out. We give the auto-pay caller a way to bind what we'll sign, without forcing the UI caller to plumb anything (all gates default to "no constraint"). Scope kept tight: amount cap, network pin, and an always-on expiry refusal. Recipient/currency match and split-shape policies are not in scope for this finding — auto-pay callers already control those values when they call our `select_charge_challenge` helper, so duplicating them in the builder didn't pull its weight.

**Action taken:**
- Added two opt-in fields to `BuildChargeTransactionOptions`:
  - `max_amount_base_units: Option<u64>` — reject when `request.amount > cap` (parsed as base units, matches how the server reasons about it).
  - `expected_network: Option<String>` — reject when `methodDetails.network` does not match.
  - Both checks run at the top of `build_charge_transaction_with_options`, before any signing or instruction building.
- Always-on expiry refusal in `build_credential_header_with_options`: if `challenge.is_expired()` returns `true`, refuse to sign. Reuses the existing fail-closed RFC3339 parser. Challenges with `expires == None` are still accepted (the protocol allows omitting it; we have no client-side anchor to check against).
- Expiry lives on `PaymentChallenge` (not in the decoded `ChargeRequest`), so the gate is in the `build_credential_header` path. Lower-level callers who construct a transaction directly from `MethodDetails` without a challenge skip this check — there's no challenge to check.

**Note on what we didn't add:**
- No `expected_recipient` / `expected_currency` options. The auto-pay caller selects the challenge via `select_charge_challenge` (or by hand); the builder doesn't need to re-check fields the caller just picked.
- No split policy options. Splits are bounded by the existing `Error::TooManySplits` gate (`splits.len() > 8`), and the spec already constrains amounts to be a subset of the total. Adding per-recipient allowlists felt like over-policy for what the auto-pay threat model actually needs.
- No client-side check that the recipient is *a* valid pubkey beyond what `build_charge_transaction_with_options` already does (it parses on its own).

**New tests:**
- `build_charge_transaction_rejects_amount_above_max`
- `build_charge_transaction_accepts_amount_at_max` (equal-to-cap is allowed)
- `build_charge_transaction_rejects_unexpected_network`
- `build_charge_transaction_accepts_matching_network`
- `build_credential_header_rejects_expired_challenge`
- `build_credential_header_accepts_future_expiry`

---

### #3 — Replay state recorded after broadcast
**ID:** `91c89aa6` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `verify_pull` waits for confirmation before recording the signature in the replay store. On confirmation timeout, the verifier bails with a network error and the consumed signature is never inserted, leaving a confirmed payment without a successful receipt and without replay state.

**Status when reviewed:** the *ordering* half of the claim is **already mitigated** (PR #85 / audit gap G05). `server/charge.rs:728-755` reserves the signature *between* broadcast and confirmation polling:
```rust
let signature = self.broadcast_pull(...).await?;
self.consume_signature(&signature).await?;
self.await_pull_confirmation(&signature)?;
```
So the replay-state side of the bug is closed.

**What was still live:** `await_pull_confirmation` exits with a network_error after 30 polls × 200 ms = 6 s. If the polling RPC is lagging or load-balanced and hasn't observed the signature yet, but the tx is actually on-chain, the verifier reports a timeout. The signature is reserved, so retrying the same credential fails with "already consumed" — user pays, never gets the resource, and can't recover.

**Decision:** ✅ **accepted — narrow fix only.**

**Rationale:** The pre-broadcast / two-phase / challenge-id-keyed reservation refactor the audit suggested as a Cadillac fix would touch the Store trait and the verify state machine for a marginal extra mitigation. The user-visible bug is the false-negative timeout, and a one-shot definitive status check after the poll loop closes it without churn.

**Action taken:**
- After the 30-poll loop in `await_pull_confirmation`, call `rpc.get_signature_status(&signature)` once. Interpret the four possible outcomes:
  - `Ok(Some(Ok(())))` — tx landed cleanly: return `Ok(())` and log `confirmed_via_status_recovery`.
  - `Ok(Some(Err(e)))` — tx landed but failed on-chain: return `VerificationError::transaction_failed("Transaction landed on-chain but failed: …")`. Distinct from a polling timeout — we now know the payment didn't go through.
  - `Ok(None)` — definitively not on-chain: keep the original `"Transaction not confirmed within timeout"` network_error.
  - `Err(_)` — the recovery RPC itself failed: still network_error, but include the RPC failure detail for ops triage.
- Pulled the four-case interpretation into a free function `interpret_post_timeout_status` so the cases are unit-testable without a live RPC. The RPC call site does `.map(|opt| opt.map(|inner| inner.map_err(|e| e.to_string())))` so the helper stays free of `solana-rpc-client` types.
- No `Store` trait change, no key-shape change, no two-phase commit. The signature is still reserved before confirmation polling; this just rescues the recovery path.

**Note on retry idempotency (Medium-shape we didn't take):** if a caller retries the same credential after a successful recovery, `consume_signature` still returns `signature_consumed`. We treat that as the correct outcome — the SDK doesn't store receipts indexed by signature, so we can't replay one. Adding that capability is a separate change, and a well-behaved caller does the recovery on the first attempt now that the status check rescues it.

**New tests** (against the pure helper):
- `interpret_post_timeout_status_landed_returns_ok`
- `interpret_post_timeout_status_landed_with_onchain_err_returns_failed`
- `interpret_post_timeout_status_not_found_returns_timeout`
- `interpret_post_timeout_status_rpc_error_returns_timeout_with_detail`

---

### #2 — Credential verification uses echoed request
**ID:** `2a3fd1f3` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `verify_credential` decodes `ChargeRequest` from `credential.challenge.request` and verifies the payment against *that*. The HMAC tier confirms the challenge was issued by this server, and `verify_pinned_fields` pins currency/recipient against `self`, but **nothing pins the amount or other per-route economics**. A server that issues challenges for multiple priced routes (the common case for any non-trivial API) will see `verify_credential` accept a $1 credential against a $100 route.

**Decision:** ✅ **accepted — delete the unsafe method outright. Breaking change accepted.**

**Rationale:** The simple `verify_credential` API is safe only for servers that serve exactly one priced resource. The audit's recommendation was "reserve `verify_credential` for flows where the echoed challenge fully defines the payable resource," but pure documentation is a soft control — the footgun stays available. With breaking changes permitted at this stage, the strongest enforcement is removing the method so every caller is forced through `verify_credential_with_expected` with an explicit expected `ChargeRequest`.

**Action taken:**
- Deleted `Mpp::verify_credential` from `server/charge.rs`.
- Updated `verify_credential_with_expected`'s rustdoc to be the canonical entry point and to call out audit #2 explicitly.
- Updated the rustdoc examples in `src/lib.rs` and the top of `src/server/charge.rs` to construct an `expected: ChargeRequest` from a route's static configuration.
- Migrated 6 unit tests (1 HMAC tier-1 + 5 tier-2 pinned-field tests) to call `verify(&cred, &request)` directly — that's the lowest-level public API and exercises the same layers the deleted method used.
- Migrated 9 integration test callsites in `tests/charge_integration.rs` to construct `expected` from the test's known configuration and call `verify_credential_with_expected`. Added a tiny `expected_charge(amount, currency, recipient)` helper that mirrors how SDK consumers should build the expected request from their own static config (not from the credential).
- No production callsite changed — `axum.rs` already used `verify_credential_with_expected`.

**Note on `verify` still being public:** the lowest-level `verify(&self, &credential, &request)` remains public. A caller who really wants "trust the echoed request" can still write `let req = cred.challenge.request.decode()?; mpp.verify(&cred, &req).await`. We keep that escape hatch because `verify` takes an *explicit* request — the caller is now visibly choosing what to verify against, which is what the audit's spirit asks for.

**Note on the future rename:** `verify_credential_with_expected` is wordy. After audit #1 tightens its internals (it still uses the credential-decoded request to populate most fields during settlement), I'd like to rename it back to `verify_credential`. Not done in this commit so the long name keeps signalling "expected required" while #1 is open.

**Tests** (no new tests authored — the existing security boundary tests were migrated to the surviving APIs without loss of coverage):
- HMAC: `verify_rejects_tampered_id` (renamed from `verify_credential_rejects_tampered_id`)
- Tier-2 pinned-field: `tier2_rejects_tampered_realm`, `_currency`, `_recipient`, `_method`, `_non_charge_intent` (all migrated to `verify`)
- The pre-existing `verify_credential_with_expected_*` tests still cover the expected-comparison layer.

---

### #1 — Partial expected charge validation
**ID:** `4e2a4d2d` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim, two parts:**
1. `verify_credential_with_expected` compared only `amount`, `currency`, `recipient` between the credential's decoded request and the expected request — leaving `externalId`, `description`, `methodDetails.splits`, `feePayer`, `feePayerKey`, `tokenProgram`, `network`, `decimals`, `recentBlockhash` unchecked.
2. After the partial comparison, the function called `verify` with the credential's decoded request rather than the expected request, so unchecked fields flowed into on-chain settlement.

**Status when reviewed:**
- Part 2 was **already fixed**. The current code passes `expected` (not the credential's request) into `verify`, as proven by the existing `verify_credential_with_expected_routes_expected_into_verify` test. The marketplace-route attack the audit describes is already closed at on-chain verification.
- Part 1 was still live.

**Decision:** ✅ **accepted — exhaustive up-front comparison, with one principled exception.**

**Rationale:** Adding the up-front comparison gives earlier, clearer failure (`splits mismatch` beats `no matching SPL transferChecked instruction` for operators chasing a bug), and provides defense-in-depth: any field added to `ChargeRequest` or `MethodDetails` in the future is forced through this layer, so a divergence cannot silently slip past the settlement check.

**Action taken:**
- Extracted a new helper `compare_expected_to_request(&request, &expected)` at module level. The helper compares every payment-constraining field exhaustively. Called from `verify_credential_with_expected` right after the credential's request is decoded.
- Fields compared:
  - top level: `amount`, `currency`, `recipient`, `external_id`, `description`
  - `method_details`: `network`, `decimals`, `token_program`, `fee_payer`, `fee_payer_key`, `splits`
- Splits compared element-wise (order-sensitive). A route that pins `[A, B]` will reject a credential carrying `[B, A]`.
- `method_details` parsing reuses `MethodDetails`; if either side has malformed `methodDetails` we return `credential_mismatch` with the source labeled (`"Invalid credential methodDetails: …"` vs `"Invalid expected methodDetails: …"`).
- The pre-existing `_routes_expected_into_verify` test had to update its assertion text — my new comparison catches the malformed `expected.method_details` *before* `verify` is called, so the failure surface moved from settlement to comparison. The test's intent (proving `expected` is the source of truth) is preserved.

**Note on `recent_blockhash`:** deliberately *not* compared. It's per-challenge state (fresh from the RPC at challenge generation time), not per-route policy. Routes build `expected` from static config and have no blockhash to pin. Strict comparison would break the normal happy path. Added a regression test `verify_credential_with_expected_ignores_recent_blockhash` to lock this in.

**Note on `description`:** the audit lists `description` as a payment-constraining field even though it has no on-chain effect. We compare it strictly for consistency with the audit's recommendation. This surfaced a latent bug in the `payment_link_server` example: it issued challenges with `description = Some("Open a fortune cookie")` but built `expected` with no description, so every honest credential would have been rejected after this change. Fixed the example to use a `ROUTE_DESCRIPTION` constant in both places. (Audit value: this finding's strict comparison catches integrator drift between "what challenges we issue" and "what we expect to verify against" — exactly the audit's defense-in-depth intent.)

**Note on alternative ("soft default") we did not take:** an "if `expected.<field>.is_none()` accept anything" variant would have made the comparison friendlier for routes that don't pin every field, but it's exactly the soft-default that lets the audit's attack through — routes that *meant* to pin a field but forgot would silently accept any value. Strict comparison forces the route to fully describe its accepted charge shape.

**New tests** (added to the existing `verify_credential_with_expected_*` suite):
- `_external_id_mismatch`
- `_description_mismatch`
- `_network_mismatch`
- `_decimals_mismatch`
- `_token_program_mismatch`
- `_fee_payer_mismatch`
- `_fee_payer_key_mismatch`
- `_splits_mismatch`
- `_ignores_recent_blockhash` (regression: blockhash divergence must NOT fail comparison)

---

## Low severity

### #39 — `parse_units` can overflow
**ID:** `4f8d51a3` · **File:** `crates/mpp/src/protocol/intents/mod.rs:18`

**Audit claim:** the integer branch of `parse_units` computes `10u128.pow(decimals) * value` with neither input bound and neither operation checked. Depending on build mode that's a panic or a silent wrap.

**Decision:** ✅ **accepted — cap + checked arithmetic.**

**Action taken:**
- Added `MAX_DECIMALS: u8 = 18`. Solana SPL convention is 0–9 per the protocol spec; 18 gives ERC-20-style headroom while staying well below the 39-where-`10.pow`-overflows cliff. Single rejection site so any callsite that hasn't validated upstream gets a clear error.
- `parse_units` rejects `decimals > MAX_DECIMALS` up-front.
- `10u128.pow(decimals)` → `checked_pow(...)` with explicit overflow error.
- `value * factor` → `checked_mul(...)` with explicit overflow error.
- Decimal-branch (`"1.5"` etc.) is string concatenation — no arithmetic to overflow; the cap still applies for consistency.

**Note on scope:** the `Mpp::Config.decimals: u32` → `as u8` truncation at the callsite is a latent boot-time issue but belongs with the audit #16 batch (boot-time footgun guards). Not bundled here to keep this fix surgical.

**New tests:**
- `parse_units_rejects_decimals_above_max`
- `parse_units_at_max_decimals_succeeds`
- `parse_units_rejects_value_times_factor_overflow`
- `parse_units_huge_value_zero_decimals_no_overflow` (boundary at `u128::MAX`)

---

### #30 — Summing split amounts exposed to overflows
**ID:** `7e2b1c5e` · **Files:** `crates/mpp/src/{protocol/solana.rs,server/charge.rs,client/charge.rs,error.rs}`

**Audit claim:** three callsites (`build_charge_transaction_with_options`, `verify_on_chain`, `verify_versioned_transaction_pre_broadcast`) summed split amounts via `.sum::<u64>()` which panics on overflow in debug and wraps in release. Spec: `sum(splits) ≤ amount`.

**Decision:** ✅ **accepted — extract helper, use checked arithmetic, centralize the count cap.**

**Action taken:**
- Added `checked_sum_split_amounts(splits: &[Split]) -> Option<u64>` in `protocol/solana.rs` (next to `Split`). Uses `try_fold` + `checked_add`. Unparseable amounts treated as `0` for now — strict parseability is audit #21's concern.
- Migrated all 3 callsites to the helper, mapping `None` to the existing error type at each callsite (client `Error::SplitsExceedAmount`, server `VerificationError::invalid_amount`).
- **Bonus centralization (per Ludo): added `pub const MAX_SPLITS: usize = 8`** in `protocol/solana.rs` and replaced the two hardcoded `8`s (client `splits.len() > 8`, server `verify_versioned_transaction_pre_broadcast`). The `thiserror`-generated `Error::TooManySplits` message now interpolates `MAX_SPLITS` so the displayed count stays in sync if the cap ever changes. The `MethodDetails::splits` rustdoc now references the constant rather than the literal.

**New tests:**
- `checked_sum_split_amounts_within_u64_sums_correctly`
- `checked_sum_split_amounts_overflows_returns_none`
- `checked_sum_split_amounts_unparseable_treated_as_zero`
- `checked_sum_split_amounts_empty_is_zero`

---

### #8 — Balance diagnostics decimal overflow
**ID:** `6c8a7d18` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `diagnose_balances` computed `10u64.pow(methodDetails.decimals)` to build a UI-amount divisor. `decimals` is `Option<u8>` bounded only by the type — values ≥ 20 panic (debug) or wrap (release). The function runs *after* settlement already failed and is best-effort.

**Decision:** ✅ **accepted — extract a checked helper, silently omit the token-balance hint when the divisor doesn't fit.**

**Action taken:**
- Extracted `to_ui_amount(amount_base_units: u64, decimals: u8) -> Option<f64>` next to `diagnose_balances`. Uses `checked_pow` and returns `None` when the divisor can't be represented.
- `diagnose_balances` now early-skips the token-balance diagnostic via `if let Some(needed) = ...`. The fee-payer SOL diagnostic below still runs.
- No new `MAX_DECIMALS` cap needed at this site — the checked_pow returning None is the cap.

**New tests** (against the helper):
- `to_ui_amount_typical_decimals` (6-decimal USDC case)
- `to_ui_amount_zero_decimals` (divisor = 1)
- `to_ui_amount_returns_none_when_divisor_overflows_u64` (decimals = 20, 255)
- `to_ui_amount_safe_high_decimals_succeed` (boundary: 19 fits, 20 doesn't)

---

### #13 — Hardcoded token program in `diagnose_balances`
**ID:** `b1f6e3a4` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `diagnose_balances` derived the payer's ATA with a hardcoded `programs::TOKEN_PROGRAM`. For Token-2022 mints (PYUSD, USDG on Token-2022, CASH) this produced the wrong ATA, so the diagnostic could silently lie about the payer's balance.

**Decision:** ✅ **accepted — use the value already resolved at boot.**

**Rationale:** Audit #28 resolves the token program once in `Mpp::new` (static table for known stablecoins, on-chain mint-owner lookup for arbitrary mints) and embeds it on every SPL challenge as `methodDetails.tokenProgram`. The diagnostic just needs to use that value instead of guessing. No runtime RPC call needed — the resolution already happened at boot.

**Action taken:**
- Read `method_details.token_program` and parse to `Pubkey`. If `Some` and parseable → use for ATA derivation.
- If `None` (or unparseable, which would be a separate validation failure upstream) → silently skip the token-balance diagnostic. The fee-payer SOL diagnostic below still runs.
- No `default_token_program_for_currency` fallback — that's exactly the wrong-for-Token-2022 path the audit flagged.

**Note on no new tests:** the fix is a one-spot value-swap inside a private, RPC-bound, best-effort diagnostic. The arithmetic helpers in #8 cover the testable surface; the change here is "use the right input." Covered by the existing integration tests that exercise the token-2022 challenge paths.

---

### #9 — Challenge parser missing max size cap
**ID:** `2f9c8d1e` · **File:** `crates/mpp/src/protocol/core/headers.rs`

**Audit claim:** `parse_www_authenticate` decoded the `request` parameter (base64url) and parsed it as JSON without the `MAX_TOKEN_LEN = 16 * 1024` cap that `parse_authorization` and `parse_receipt` already enforced. A large `WWW-Authenticate` value drove proportionally larger decode + JSON parse work than the credential/receipt parsers allowed.

**Decision:** ✅ **accepted — cap the `request` parameter at `MAX_TOKEN_LEN`.**

**Rationale:** The audit asks for "consistent limits across challenge, credential, and receipt parsers." The credential parser caps the `token` (the data after the scheme); the receipt parser caps the `token` value. For the challenge parser, the only field that gets both base64-decoded and JSON-parsed is `request` — every other parameter (id/realm/method/intent/expires/digest) is a short pass-through string. Capping `request` matches the *kind* of work the other parsers cap.

**Action taken:** added a `request_b64.len() > MAX_TOKEN_LEN` check immediately after `request` is read from the parameters and before `base64url_decode`/`serde_json::from_slice` run. Error message matches the parse_authorization/parse_receipt style for ops grep-ability.

**What I didn't do:**
- Didn't cap the full header alongside the param cap — redundant once the param is capped, since the request param is the only field that drives O(n) decode/parse cost.
- Didn't cap `opaque` here — at parse time it's only stored raw via `Base64UrlJson::from_raw`. Any decode is lazy at the consumer site.

**New tests:**
- `parse_www_authenticate_rejects_oversized_request_param`
- `parse_www_authenticate_accepts_at_max_request_size` (regression: at-cap shouldn't fire the size gate)

---

### #42 — Decimal management contradicts the specs
**ID:** `7a1c2e4f` · **Files:** `crates/mpp/src/client/charge.rs`, `server/charge.rs`

**Audit claim:** spec §7.2 marks `decimals` as conditionally required (MUST be present for SPL, MUST be absent for SOL). Two callsites used `method_details.decimals.unwrap_or(6)`, silently defaulting non-6-decimal SPL flows to a wrong divisor.

**Decision:** ✅ **accepted — asymmetric fix.**

**Rationale:** The two callsites have different audiences. The client builder is user-facing and produces signed transactions — silent wrong-decimals output is the worst possible failure mode, error out. The server's `diagnose_balances` is a post-failure best-effort hint — falsely confident output is worse than no output, silently skip (same shape as the audits #8 and #13 fixes for the same function).

**Action taken:**
- **Client `build_spl_instructions`:** `unwrap_or(6)` → `ok_or(Error::Other("methodDetails.decimals is required for SPL charges (spec §7.2)"))?`. Path only runs when `currency` resolves to a mint (we're inside the SPL branch), so the spec's "MUST be present for mint" is the active rule.
- **Server `diagnose_balances`:** wrapped the token-balance diagnostic in `if let Some(needed) = method_details.decimals.and_then(|d| to_ui_amount(...))` — missing decimals now silently omits the line rather than guessing 6. Fee-payer SOL diagnostic still runs.

**Note on `Mpp::charge` (server challenge issuer):** unchanged — it already populates `decimals` from `self.decimals` for every challenge this server issues. The `None` path in `diagnose_balances` is the lower-level-construction edge case.

**New tests:**
- Client: `build_spl_rejects_missing_decimals`.
- Server: no new test — diagnose_balances is private + RPC-bound; the silent-skip branch is the same shape proven by the #8 tests.

---

### #16 — `PaymentChallenge` instances can be created with `feePayer = true` and `fee_payer_signer = None`
**ID:** `9e3b1c47` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** spec §7.2 requires `feePayerKey` to be present when `feePayer = true`. `Mpp::new` accepted `Config { fee_payer: true, fee_payer_signer: None }` without complaint, and `charge_with_options` then emitted a spec-violating challenge (`"feePayer": true` with no `"feePayerKey"`).

**Decision:** ✅ **accepted — two gates, both call paths covered.**

**Action taken:**
- **`Mpp::new`:** reject when `config.fee_payer && config.fee_payer_signer.is_none()`. After this gate the invariant `self.fee_payer` implies `self.fee_payer_signer.is_some()` holds for the server's static config.
- **`validate_charge_options`:** reject when `options.fee_payer && self.fee_payer_signer.is_none()`. Catches the per-call override where `Config.fee_payer == false` but a route sets `ChargeOptions.fee_payer = true`.
- Two pre-existing tests (`charge_with_fee_payer_includes_method_details`, `charge_options_fee_payer_flag`) constructed misconfigured Mpps that fell into the audit's exact shape; updated them to provide `test_fee_payer_signer()` so the assertions now exercise the spec-compliant path.

**Note on alternative:** the type-level refactor (fold `fee_payer` + `fee_payer_signer` into a single `Option<FeePayerConfig>` enum that makes the invariant unrepresentable) is the more durable fix but a bigger ergonomic change. Not bundled — the runtime gates close the audit shape today.

**New tests:**
- `new_rejects_fee_payer_true_without_signer`
- `new_accepts_fee_payer_false_without_signer` (regression: default no-signer config keeps working)
- `charge_options_rejects_fee_payer_without_signer`
- `charge_options_fee_payer_succeeds_when_signer_configured` (happy path; asserts `feePayerKey` is populated)

---

### #15 — Default `realm` shares credential namespace across servers
**ID:** `8d1c4a72` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `DEFAULT_REALM = "MPP Payment"`. Realm is part of the HMAC ID input, so two services that share `MPP_SECRET_KEY` and both keep the default realm participate in one shared credential namespace — a credential paid against service A passes HMAC verification on service B.

**Decision:** ✅ **accepted — derive default from recipient pubkey.**

**Rationale:** The audit gives two options ("require non-empty realm" *or* "derive a unique default from an application identifier/origin"). Requiring an explicit realm would force 41 callsite updates (tests, examples, integration) for marginal gain over a derived default that already differs per-app. The `recipient` is a Solana pubkey, unique per merchant, and already mandatory in `Config` — perfect as the app identity. Two services with the same secret but different recipients now automatically get different realms; HMAC IDs differ; cross-service replay broken.

**Action taken:**
- Removed `const DEFAULT_REALM: &str = "MPP Payment"`.
- Added `fn derive_default_realm(recipient: &str) -> String` that hashes the recipient with SHA-256, takes the first 4 bytes as `u32::from_be_bytes` mod 10^8, and formats as `"App Id - #<digits>"`. Human-friendly and deterministic.
- `Mpp::new` resolves the realm via a small `match` that:
  - rejects explicit `Some("")` with `Error::InvalidConfig` (closes the bypass where an operator could re-introduce the audit threat with a typo),
  - uses the supplied non-empty realm if provided,
  - else derives from `config.recipient`.
- Updated two pre-existing tests that asserted `realm == DEFAULT_REALM` to use `derive_default_realm(TEST_RECIPIENT)`.

**What I didn't do:**
- Didn't fold the realm into the type system (e.g., `enum Realm { Derived, Explicit(String) }`) — the runtime check + derivation is enough to close the audit's threat without an ergonomic refactor.
- Didn't change the realm shape for explicit overrides; operators who set `realm: Some("Acme API")` keep getting `"Acme API"`.

**Note on wire-format impact:** the realm appears in `WWW-Authenticate` headers and binds HMAC IDs. Servers upgrading from the previous SDK release will see in-flight challenges (issued with the old `"MPP Payment"` realm) fail to verify under the new derived realm. Default TTL is 5 minutes; the rollout window closes quickly.

**New tests:**
- `new_default_realm_format` — asserts the `"App Id - #<digits>"` shape with up to 8 digits.
- `new_default_realm_deterministic_for_same_recipient` — restart-safe (same recipient → same realm).
- `new_default_realm_differs_across_recipients` — closes the audit threat shape.
- `new_rejects_empty_realm` — explicit empty string rejected.

---

### #37 — Unconditional default to mainnet, plus naming inconsistency
**ID:** `1d5ea7b2` · **Files:** `crates/mpp/src/{server,client}/charge.rs`, `protocol/solana.rs`, `server/html.rs`

**Audit claim:** the codebase silently treated any network slug other than `"devnet"`/`"localnet"` as mainnet-beta (e.g. in `default_rpc_url`), contradicting the spec's "MUST be one of mainnet/devnet/localnet". Two copies of `default_rpc_url` (one private, one public) drifted independently. The audit also asked us to decide between `"mainnet"` and `"mainnet-beta"` as the canonical slug.

**Decision:** ✅ **accepted — allowlist at server boot, canonicalize on `"mainnet"`, consolidate.**

Ludo's call: `"mainnet"` is the canonical slug. `"mainnet-beta"` is the Solana RPC hostname convention only.

**Action taken:**
- Added `NETWORK_MAINNET`/`NETWORK_DEVNET`/`NETWORK_LOCALNET` constants and `DEFAULT_NETWORK = NETWORK_MAINNET` in `protocol/solana.rs`.
- Added `validate_network(&str) -> Result<(), Error>` in `protocol/solana.rs`. Rejects everything outside the allowlist; explicit empty-string handling for a cleaner error.
- `Mpp::new` calls `validate_network(&config.network)?` next to the other boot-time guards (#16, #15, #24). Misconfig like `Config { network: "mainnet-beta" }` or `"testnet"` fails at boot, before any RPC client is built.
- Removed the private `default_rpc_url` in `server/charge.rs`; the single callsite (`Mpp::new`) now uses `crate::protocol::solana::default_rpc_url`. Tests for the helper live next to the public copy.
- Client `select_charge_challenge` → `matches_network` no longer falls back to `"mainnet-beta"` when `methodDetails.network` is `None`; uses `DEFAULT_NETWORK` (= `"mainnet"`) per spec §7.2.
- Docstrings on `Config.network`, `SelectChargeChallengeOptions::network`, and the `protocol/solana.rs` constants updated to reflect the canonical slug.
- Test fixtures across `client/charge.rs` and `server/html.rs` that used `"mainnet-beta"` as a network slug → `"mainnet"`. (RPC hostname strings like `https://api.mainnet-beta.solana.com` are unchanged — that's a Solana hostname, separate concern.)

**What I didn't bundle in this finding:**
- `server/session.rs` / `protocol/intents/session.rs` still carry `"mainnet-beta"` as a session-flow network slug. Different intent (session, not charge), separate audit scope; consciously skipped to keep the diff tight.
- `x402` crate has its own network handling with `"mainnet-beta"` references — that's a sibling protocol, not in scope for MPP audit #37.
- Didn't refactor `Config.network` to an `enum Network { Mainnet, Devnet, Localnet }`. Cleaner but a larger ergonomic change; the runtime allowlist closes the audit threat as-is.

**New tests:**
- `new_accepts_canonical_networks` — loop over `{mainnet, devnet, localnet}`, all succeed.
- `new_rejects_unknown_network` — `"testnet"` → error.
- `new_rejects_empty_network` — distinct error message for empty input.
- `new_rejects_mainnet_beta_slug` — explicitly locks in the canonicalization decision.

---

### #21 — Incomplete split validation at challenge creation
**ID:** `3a8f7c91` · **Files:** `crates/mpp/src/{protocol/solana.rs,server/charge.rs}`

**Audit claim:** `validate_charge_options` ran additional split checks only when at least one split had `ataCreationRequired = true`. For all other splits, `charge_with_options` embedded them into `methodDetails` with no parseability check, no positive-amount check, no dedup, and no count cap at challenge issuance. Invalid splits then surfaced only at on-chain settlement.

**Decision:** ✅ **accepted — shared helper, both server entry points validate.**

**Action taken:**
- Added `validate_splits(&[Split]) -> Result<(), Error>` in `protocol/solana.rs` next to the existing `checked_sum_split_amounts` and `MAX_SPLITS`. Single source of truth.
- Enforces: count ≤ `MAX_SPLITS`, recipient parses as `Pubkey`, amount parses as `u64` and is `> 0`, aggregate sum doesn't overflow `u64` (reuses `checked_sum_split_amounts`), no duplicate recipients.
- Called from both `validate_charge_options` (per-call path) and `validate_charge_request` (the lower-level `charge_challenge_with_options` path).
- Removed the duplicated per-split loop in `validate_charge_request`; the helper handles it.
- One pre-existing test (`charge_with_options_splits`) used placeholder strings as recipient pubkeys that never parsed as base58 — now uses `Pubkey::new_unique()`. The other pre-existing test (`charge_challenge_rejects_invalid_split_recipient`) had its assertion text updated to match the unified helper's error string.

**What I didn't do:**
- **No application-level recipient allowlist.** The audit's `Consider` for this was a domain-specific policy that doesn't belong in the SDK — applications can wrap.
- **No client-side change.** Splits originate from the server; the client only consumes them via `methodDetails`.

**New tests** (in `protocol::solana::tests`):
- `validate_splits_accepts_valid_set`
- `validate_splits_accepts_empty`
- `validate_splits_rejects_count_above_max`
- `validate_splits_rejects_invalid_recipient`
- `validate_splits_rejects_unparseable_amount`
- `validate_splits_rejects_zero_amount`
- `validate_splits_rejects_overflowing_aggregate`
- `validate_splits_rejects_duplicate_recipient`

**New entry-point regression tests** (in `server::charge::tests`):
- `charge_with_options_rejects_invalid_split_recipient`
- `charge_with_options_rejects_zero_split_amount`
- `charge_with_options_rejects_duplicate_split_recipient`
- `charge_with_options_rejects_too_many_splits`

---

### #33 — No check for minimum remaining SOL balance for signers
**ID:** `c4e9a3d1` · **File:** `crates/mpp/src/client/charge.rs`

**Audit claim:** the client builder constructs SOL `system_instruction::transfer` instructions without verifying the signer retains lamports for fees + rent-exempt minimum. Three risks: drain the signer, leave it below rent (account swept at epoch boundary), or sign a tx that fails on-chain for insufficient funds.

**Decision:** ❌ **rejected — threat does not apply to the product.**

**Rationale:** The product is stablecoin-only. Signers transfer SPL tokens (USDC, USDT, PYUSD, USDG, CASH); the SOL `system_instruction::transfer` code path exists in the SDK but is not the user-facing flow. Walking through the cases:

| Case | Outcome | Who catches it |
|---|---|---|
| Signer = fee_payer, insufficient SOL for fee | tx fails at broadcast/execution | Solana runtime — signer pays nothing |
| Signer ≠ fee_payer (server-cosigned) | signer needs zero SOL | n/a |
| Server fee-payer underfunded | server tx fails | spec §13.6 — server's responsibility, separate concern |
| Signer drained below rent via SOL transfer | account swept silently at epoch | only matters if SOL transfer path is reached, which the product doesn't use |

The "drain below rent" silent-sweep is the only failure mode the chain doesn't catch cleanly, and it requires the SOL transfer path the product doesn't expose to end users.

**Prototype shipped briefly during analysis** (added `MIN_RENT_EXEMPT_LAMPORTS`, `MIN_FEE_RESERVE_LAMPORTS`, `skip_balance_check` opt-out, and a pre-sign `rpc.get_balance` check) but **reverted before commit** once we clarified that the SOL leg isn't a product path. The 11 tests that broke under the prototype confirmed how invasive the change would be relative to a threat that doesn't apply.

**What this leaves on the table:**
- Spec §13.6 (server fee-payer balance monitoring) is a real ask, but it targets the **server side** of fee-sponsored flows, not the client builder. Tracked separately if/when we address it.
- The `build_sol_instructions` function stays public but unprotected. If a future caller starts using the SOL path for end-user-facing flows, the audit's concern becomes live again — revisit at that point.

---

### #22 — Lower-level `verify` request not bound to challenge
**ID:** `e5b8a47f` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** `verify(&credential, &request)` recomputes HMAC from `credential.challenge.request` (confirming the challenge was server-issued) but settles against the caller-supplied `&request`. They can diverge — a direct caller could authenticate "challenge Y was issued" while verifying settlement against "request X". The escape hatch kept public after audit #2.

**Decision:** ✅ **accepted — bind request to credential inside `verify`.**

**Rationale:** The audit gave two options: (1) require `request == credential.request` inside `verify`, or (2) make the low-level API private/rename it. (1) closes the threat for any caller without breaking the API or forcing every caller into `verify_credential_with_expected`. (2) was a half-measure that either (a) only hid the API from external callers via `pub(crate)` while the trust gap remained for internal callers, or (b) needed a full rename (`verify_request_unchecked`) that breaks tests for marginal extra clarity.

**Action taken:**
- After the HMAC tier-1 check, `verify` decodes `credential.challenge.request` and calls `compare_expected_to_request(&decoded_from_credential, request)?` — the same audit #1 helper that `verify_credential_with_expected` uses.
- For `verify_credential_with_expected`: the comparison fires twice (once at the outer entry, once inside `verify`). Cheap, defense-in-depth.
- For direct callers of `verify`: any divergence between the supplied request and the credential's HMAC-authenticated request is rejected at the binding check, with the same per-field mismatch errors operators already see from audit #1.
- Tier-2 unit tests (added in audit #2's migration) construct `request` as-if-decoded-from-the-credential, so they pass the new check naturally — no regression.

**Note on `verify` still being public:** the API is now self-protected. Direct callers are free to use it; they just can't pass a divergent request. Kept public because tests and well-behaved callers (notably `verify_credential_with_expected`) need it as a building block.

**New test:**
- `verify_rejects_request_diverging_from_credential` — HMAC tier passes (credential not tampered), caller passes a different amount than the credential carries; expects the audit #1-style "Amount mismatch" error from the binding check.

---

### #17 — Missing method and intent enforcement on Client and Server
**ID:** `5f3c1d68` · **Files:** `crates/mpp/src/server/charge.rs`, `crates/mpp/src/client/charge.rs`

**Audit claim, two parts:**
1. **Server:** `verify` recomputes HMAC using whatever method/intent the credential echoes; never explicitly checks `method == "solana"` and `intent == "charge"` after HMAC. A challenge issued by the same server secret for another method/intent could reach the Solana charge verification path.
2. **Client:** `build_credential_header` doesn't reject non-`solana`/non-`charge` challenges before signing.

**Status when reviewed:**
- **Server:** **already mitigated.** `verify_pinned_fields` (called unconditionally from `verify`) checks both `method` and `intent` — the `tier2_rejects_tampered_method` and `tier2_rejects_non_charge_intent` tests prove it. No code change needed; documenting in the assessment.
- **Client:** real gap. `select_charge_challenge` filters via `is_solana_charge_challenge_name`, but `build_credential_header_with_options` accepts whatever challenge it's handed.

**Decision:** ✅ **accepted, client-only — close the entry-point gap.**

**Action taken:**
- Added a method/intent gate at the top of `build_credential_header_with_options` (right after the audit #17 comment block, before the audit #10 expiry check). Reuses `is_solana_charge_challenge_name`. Error string surfaces both the unexpected method and intent for operator debugging.
- The lower-level `build_charge_transaction_with_options` doesn't change — it takes already-decoded fields and has no notion of method/intent; the trust boundary belongs at the `PaymentChallenge` entry point.
- Server-side: no code change. The pre-existing `verify_pinned_fields` already enforces the audit's exact recommendation. This entry calls it out so future readers know the check is intentional, not redundant.

**New tests** (client):
- `build_credential_header_rejects_non_solana_method` — `method = "stripe"` → error with both `method=` and `intent=` in the message.
- `build_credential_header_rejects_non_charge_intent` — `intent = "session"` → same shape.

---

### #5 — Push signature not bound to challenge
**ID:** `8b2f1e9c` · **File:** `crates/mpp/src/server/charge.rs`

**Audit claim:** push-mode credentials (`CredentialPayload::Signature`) match on-chain transactions to challenges by shape (recipient, amount, currency, splits) only. Replay protection applies to the signature *after* verification. The on-chain tx carries no unique binding to a specific challenge, so two challenges with identical shape (or any unrelated payment with matching shape) can satisfy each other — "first accepted presentation wins."

**Decision:** 🟡 **partial — spec-aware accept + opt-in gate.**

**Rationale:** This is **acknowledged by the spec.** `draft-solana-charge-00.txt:1247-1268` (§13.5 "Front-running (Push Mode)") explicitly names the same attack model:
> "Push mode does not require the on-chain transaction to carry a challenge-specific marker. It proves that a payment matching the challenged terms was made, but not necessarily that the payment was created for one unique challenge instance. If multiple valid challenges have identical terms, the same confirmed transaction could satisfy any one of them, and the first accepted presentation wins."

The spec also considers and rejects mandating the audit's recommended mitigation (a Memo carrying the challenge id):
> "Requiring an on-chain marker such as a Memo carrying the challenge id would provide stronger binding, but would also reveal extra correlation metadata on chain. This specification does not require such a marker in the base flow, but implementations MAY define a backward-compatible profile that does."

So the base flow we ship is spec-compliant. Mandating the challenge-id memo would impose a privacy cost (each payment correlated to a specific request on-chain) the spec author explicitly declined to bake in. We follow suit.

**What we add anyway:**
- **`Config::accept_push_mode: bool` (default `false`).** Opt-in flag for accepting push-mode credentials. Default-off means servers that don't actively need push mode reduce their attack surface — the §13.5 trade-off only applies to operators who explicitly choose it. Independent of the binding question.
- The new gate runs **before** B34 (the existing fee-payer-route reject). When push mode is off, the rejection message points at the spec section for ops triage; when on, B34 still narrows the fee-sponsored case.

**Action taken:**
- `Config { ..., accept_push_mode: false }` plumbed through to `Mpp` and into the push-mode branch of `verify`.
- One pre-existing test (`b34_rejects_push_credential_on_fee_payer_route`) had to set `accept_push_mode: true` to exercise the B34-specific path in isolation now that the audit #5 gate runs first.
- `interop_server.rs` (the interop harness binary) sets `accept_push_mode: push_mode` so the interop suite still exercises push mode end-to-end when it's the mode under test.

**What we didn't do** (and why):
- **Mandatory challenge-id memo profile** (audit's recommendation). Spec §13.5 explicitly leaves this as MAY, not MUST, citing on-chain correlation metadata as the trade-off. Adding it unilaterally would impose a privacy regression the spec author chose to avoid. If/when the spec evolves to mandate the profile, we adopt.
- **`request.external_id` enforcement for push mode.** Considered as a lower-cost alternative to the memo profile — but it conflates `external_id` (a business identifier integrators control) with a challenge-binding marker, and still imposes the on-chain correlation cost. Skip until the spec moves.
- **Server-side `verify_push` enrichment.** The existing memo verifier already enforces `external_id`-bound memos when integrators choose to use the field. No change there.

**Note on the attacker model** that came up during analysis:
- The attacker doesn't need the victim's challenge id. They request their own challenge (the 402 endpoint is open) for the same resource, then submit the victim's on-chain signature against their own challenge. HMAC validates (their own challenge), shape matches (same recipient/amount/currency), signature points to a real tx — first-accepted-presentation wins, attacker gets service.
- This is exactly the model spec §13.5 names as the accepted base-flow trade-off.

**New tests:**
- `verify_rejects_push_credential_when_accept_push_mode_off` — default Mpp, push credential, expect rejection with both "Push-mode credentials are disabled" and "§13.5" in the message.
- `verify_passes_audit_5_gate_when_accept_push_mode_on` — opt-in Mpp, confirm the audit #5 gate doesn't fire (downstream errors from the fake signature are fine; just not the gate's error).

---

## Informational

### #44, #45, #27, #14, #34 — Input strictness pass
**Commit:** `d015be1`

Five informational findings batched together — input-strictness or docstring fixes.

- **#44 / #45 — `parse_units` edge cases:** previously accepted dotted values missing the integer (`".5"`), the fraction (`"5."`), both (`"."`), or with more than one dot (`"1.2.3"` silently became `123` because `split_once('.')` stopped at the first dot). Now rejects all of those plus any non-ASCII-digit characters on either side. The pre-existing `parse_units_zero_decimals_with_dot` test (which expected `"1." == "1"`) became `parse_units_zero_decimals_with_trailing_dot_rejected`. Five new tests cover the new reject paths.
- **#27 — `resolve_mint` docstring:** previously said "Returns `None` for native SOL, or `Some(mint_address)` for SPL tokens." Now documents the third case: `Some(input passthrough)` for unknown symbols.
- **#14 — `SelectChargeChallengeOptions` precedence:** docstrings on `currency` and `currency_preferences` now state the precedence rule explicitly (`currency_preferences` takes priority when non-empty).
- **#34 — `ataCreationRequired` mint-address check:** both `verify_versioned_transaction_pre_broadcast` and `verify_on_chain` switched from the oblique `request.currency != expected_mint.to_string()` check to a direct `Pubkey::from_str(&request.currency).is_err()`. Same outcome, clearer intent. The same comment block in `verify_on_chain` references the matching block above.

---

### #41, #11, #36 — API hygiene pass
**Commit:** `_<TBD>_`

Three informational findings — small touch-ups that don't change behaviour for honest callers.

- **#41 — Constant-time HMAC id comparison:** `server::charge::verify` used a plain `!=` to compare the credential's challenge id against the recomputed HMAC, even though the existing `constant_time_eq` helper backed `PaymentChallenge::verify`. A timing oracle could in principle leak how many leading bytes of an attacker-controlled id match an actually-issued one. The helper is now `pub(crate)` and called directly. No behaviour change for honest callers; the timing channel closes.
- **#11 — `VerificationError` title alignment:** `invalid_amount`, `invalid_recipient`, and `credential_mismatch` now have titles that match their function names (`"Invalid Amount"`, `"Invalid Recipient"`, `"Credential Mismatch"`) instead of repeating the bucket label. Codes (`verification-failed`, `malformed-credential`) unchanged so consumers grouping by code keep working.
- **#36 — Explicit commitment on client blockhash fetch:** `build_charge_transaction_with_options` previously called `rpc.get_latest_blockhash()` (no explicit commitment), relying on the RPC client's default. Solana's client guidance recommends `confirmed` — a `processed` hash can disappear under reorgs, leaving the client with a signed transaction that fails with `BlockhashNotFound` after broadcast. Now calls `get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())`.

---

### #40 — Push-mode + fee-sponsored already rejected (no code change)
**Existing mitigation:** the B34 reject at `server/charge.rs:837` (just below the audit #5 gate) refuses `CredentialPayload::Signature` when `methodDetails.feePayer == true`. Mirrors the spec §8.3 prohibition. The pre-existing `b34_rejects_push_credential_on_fee_payer_route` test (now in the same `accept_push_mode: true` branch added by audit #5) covers it. No code change needed; this entry documents the alignment.

---

### #23 — Server fee-payer funds split ATA creation (already addressed)
**Existing mitigation:** audit #20 closed the implicit client-funded ATA creation in `build_spl_instructions` (the client now only emits an ATA-creation instruction when `ataCreationRequired: true` is explicitly set on the split). Audit #38 added the misconfig guard rejecting the primary recipient + `ataCreationRequired` combo at challenge issuance. Audit #21 enforces full split validation (positive amounts, dedup, parseable pubkeys) before the policy is computed. Together these cover the audit's "treat `ataCreationRequired` as server-trusted policy only" recommendation — the field is only honored when the server-side challenge-build path explicitly sets it. No additional code change.

---

### #35 — Replay protection scope (already addressed by #3)
**Existing mitigation:** audit #3 reserved the consume_signature slot between broadcast and confirmation polling (PR #85 / G05), and the audit #3 fix also added the post-timeout `get_signature_status` recovery so a tx that landed during a polling timeout isn't lost. The audit #35 description was about the broader "what counts as consumed" model, which we already match: the signature is reserved before the confirmation poll completes and stays reserved on every outcome the server is responsible for. No additional code change.

---
