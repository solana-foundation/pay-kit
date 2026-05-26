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
