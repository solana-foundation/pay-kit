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
