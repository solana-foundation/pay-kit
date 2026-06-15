# Adversarial verification — the 4 "universal client-side gaps"

Goal: try HARD to REFUTE each finding by locating a guard in the two sampled
languages. Default to CONFIRMED only when no guard exists. Each gap is checked
against the Rust fix in `rust/AUDIT-ASSESSMENT.md` as the reference behaviour.

Method: read the full client path (build + sign + auto-pay interceptor) for each
language, plus grep sweeps for the specific guard each finding would require
(`expires`/clock, `maxAmount`, `expectedNetwork`, `allow_unknown_token_2022`,
known-mint gate, decimals-required error). Line numbers are from the files as
read on 2026-06-15.

---

## #10 — Client signs untrusted charge challenges (Kotlin, Swift)

**Required guard (Rust fix):** always-on expiry refusal (`challenge.is_expired()`
→ refuse to sign), plus opt-in `max_amount_base_units` and `expected_network`
checks at the top of the build path, before any signing.

### Kotlin — EXPOSED
- `protocols/mpp/client/Charge.kt`
  - `buildCredentialHeader` (lines 319-343): `requireSolanaCharge()` →
    `chargeRequest()` → `buildChargeTransaction()` → format header. No reference
    to `challenge.expires`, no amount cap, no network pin.
  - `buildChargeTransaction` / `buildUnsignedChargeMessage` (89-312): parses
    amount, splits, recipient; signs. No policy gate.
- `client/ChargeInterceptor.kt` (the auto-pay path, lines 31-55): on a 402 it
  selects the Solana charge challenge and signs it immediately
  (`Charge.buildCredentialHeader`, line 42) with zero policy checks. This is
  exactly the auto-pay threat model #10 calls out.
- Refutation attempts that FAILED:
  - `expires` exists only as a parsed field on the challenge type
    (`core/Types.kt:20,56`, `core/Headers.kt:124`) — never compared to a clock.
  - grep for `Instant|Clock|System.currentTimeMillis|now()` in the client +
    interceptor → **no matches**. There is no time source to enforce expiry.
  - grep for `maxAmount|expectedNetwork` → **no matches**.
- **No guard exists → EXPOSED.**

### Swift — EXPOSED
- `Protocols/Mpp/Client/Charge.swift`
  - `buildPullCredential` (308-327): `requireSolanaCharge()` → `chargeRequest` →
    `buildChargeTransaction` → format header. No expiry, amount, or network check.
  - `buildChargeTransaction` (103-303): parses, builds, signs. `Charge.Options`
    (52-60) carries only `computeUnitLimit` / `computeUnitPrice` — no policy
    fields.
  - `pickChallenge` (72-85): filters on `method=="solana"`/`intent=="charge"` and
    that the request decodes; no expiry/amount/network policy.
- Refutation attempts that FAILED:
  - `expires` exists only as a parsed field (`Core/Models.swift:12,74`,
    `Core/Headers.swift:32`) — never compared.
  - grep for `Date()|.now|isExpired|maxAmount|expectedNetwork` in the client dir
    → **no matches**. No clock read anywhere in the sign path.
- **No guard exists → EXPOSED.**

**#10: both Kotlin and Swift EXPOSED.**

---

## #20 — Implicit client-funded split ATA creation (TypeScript, Go)

**Required guard (Rust fix):** the create-ATA decision must be
`split.ata_creation_required == Some(true)` in BOTH modes. The pre-fix bug was
`fee_payer.is_none() || ata_creation_required` (auto-create for every split in
client-paid mode).

### TypeScript — EXPOSED
- `client/Charge.ts`, split loop line 277-284, decision at **line 281**:
  ```ts
  !useServerFeePayer || split.ataCreationRequired === true
  ```
  In client-paid mode `useServerFeePayer === false`, so `!false === true` →
  the expression short-circuits to `true` and `addSplTransfer(..., createAta=true)`
  fires `getCreateAssociatedTokenIdempotentInstruction` (236-246) for EVERY split
  regardless of the flag. This is the pre-fix Rust shape verbatim.
- Refutation: looked for a flag-only gate or an `ataCreationRequired`-only path —
  none. The `currency !== mint` guard (189-191) only fires when a split *requests*
  ATA creation; it does not stop the unconditional client-paid creation.
- **EXPOSED.**

### Go — EXPOSED
- `client/charge.go`, split loop line 165-185, decision at **line 174**:
  ```go
  createTokenAccount := !useServerFeePayer || (split.AtaCreationRequired != nil && *split.AtaCreationRequired)
  ```
  Same logic: client-paid mode (`useServerFeePayer == false`) → always `true` →
  `BuildCreateAssociatedTokenAccount` appended (142-146) for every split.
- Note: `CreateRecipientATA` in `BuildOptions` (29) gates only the *primary*
  recipient and defaults false — it does not change the split behaviour.
- **EXPOSED.**

**#20: both TypeScript and Go EXPOSED.**

---

## #26 — Client signs unknown Token-2022 mints (Python, Kotlin)

**Required guard (Rust fix):** in `build_spl_instructions`, after resolving the
token program, if program == Token-2022 AND mint not in `is_known_stablecoin_mint`
→ refuse unless `allow_unknown_token_2022` opt-in. Transfer hooks only exist on
Token-2022, so the gate is on that axis.

### Python — EXPOSED
- `client/charge.py`, `_resolve_token_program` (284-303): takes
  `methodDetails.tokenProgram` if present else fetches mint owner via RPC, then
  the ONLY check (line 301) is `token_program not in (TOKEN_PROGRAM,
  TOKEN_2022_PROGRAM) → raise`. A Token-2022 program passes freely.
- SPL build path (194-256) calls it and proceeds to sign with no known-mint
  check and no opt-in parameter. `build_charge_transaction` signature (68-77)
  has no `allow_unknown_token_2022`.
- Refutation: searched for a known-mint allowlist gate or opt-in flag — the only
  allowlist use is `default_token_program_for_currency` as an *offline fallback*
  (298-300), which still ends at Token/Token-2022 and never refuses an unknown
  Token-2022 mint.
- **EXPOSED.**

### Kotlin — EXPOSED
- `client/Charge.kt`, `resolveTokenProgram` (388-421): explicit-program branch
  validates against {Token, Token-2022} only (395); known-stablecoin branch
  answers from table (402-408); arbitrary-mint branch reads owner via
  `MintOwnerResolver` and validates owner ∈ {Token, Token-2022} (415-419) then
  returns it. An unknown mint owned by Token-2022 is accepted and signed.
- `buildSplInstructions` (490-546) and `buildChargeTransaction` (89-116) have no
  `allowUnknownToken2022` parameter and no known-mint refusal.
- Refutation: the docstring at 374-387 explicitly says the resolver validates
  owner against {Token, Token-2022} — i.e. it confirms the *type* but never gates
  on whether the mint is *known*, which is precisely the transfer-hook surface.
- **EXPOSED.**

**#26: both Python and Kotlin EXPOSED.**

---

## #42 — SPL decimals silently default to 6 (Swift, Go)

**Required guard (Rust fix):** client `build_spl_instructions` must error when
`methodDetails.decimals` is missing on the SPL path
(`ok_or(Error::Other("methodDetails.decimals is required for SPL charges"))`),
never `unwrap_or(6)`.

### Swift — EXPOSED
- `client/Charge.swift`, SPL branch **line 181**:
  ```swift
  let rawDecimals = methodDetails.decimals ?? 6
  ```
  Missing decimals silently becomes 6. The bounds check that follows (182-191)
  only rejects values outside [0,255]; it does NOT require presence. A
  non-6-decimal mint with omitted decimals signs a wrong `transferChecked`.
- **EXPOSED.**

### Go — EXPOSED
- `client/charge.go`, SPL branch **lines 121-124**:
  ```go
  decimals := uint8(6)
  if methodDetails.Decimals != nil {
      decimals = *methodDetails.Decimals
  }
  ```
  Nil decimals → default 6, no error. Same silent-wrong-divisor bug.
- **EXPOSED.**

**#42: both Swift and Go EXPOSED.**

---

## Verdict

All four findings survive adversarial refutation in both sampled languages. No
guard was found in any of the eight (lang × finding) cells — every gap is a
genuine, code-level exposure, not a shared first-pass misread. The pattern is
consistent with the SUMMARY thesis that the Rust audit fixes were never ported.

- #10: HOLDS — Kotlin EXPOSED (`Charge.kt:319-343` sign path, `ChargeInterceptor.kt:42` auto-pay, no clock/amount/network guard), Swift EXPOSED (`Charge.swift:308-327`, no guard).
- #20: HOLDS — TypeScript EXPOSED (`Charge.ts:281`), Go EXPOSED (`charge.go:174`).
- #26: HOLDS — Python EXPOSED (`charge.py:284-303`), Kotlin EXPOSED (`Charge.kt:388-421`).
- #42: HOLDS — Swift EXPOSED (`Charge.swift:181`), Go EXPOSED (`charge.go:121-124`).
