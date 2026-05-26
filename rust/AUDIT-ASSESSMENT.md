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

**Decision:** 🟡 **partial — reject the strict ban, add a misconfig guard.**

**Rationale:** Having the primary recipient appear in `splits` is a legitimate use case we want to support (e.g., the merchant takes part of the funds as a split alongside other splits). Forbidding the recipient in splits would over-constrain the protocol.

**Action:** Add a narrower server-side check that detects the *misconfiguration* shape — primary recipient in splits **with `ataCreationRequired: true`** — and reject only that combination at challenge build time, since fee-sponsored ATA creation for the top-level recipient is what makes the drain attack possible. Allow the primary recipient in splits otherwise.

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
