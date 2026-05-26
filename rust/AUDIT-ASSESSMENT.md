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
