# Adversarial verification — Go MPP/charge claimed exposures

Method: for each claim, actively hunted for a guard the first pass may have missed.
Default verdict was "CONFIRMED EXPOSED"; only flipped to "REFUTED (SAFE)" with a cited guard.
Code root: `go/protocols/mpp/`. Line numbers verified against current `server/server.go`,
`paycore/solana.go`, `intents/charge.go`.

---

## #2 — `VerifyCredential` settles against the credential's echoed amount

**Verdict: CONFIRMED EXPOSED.**

Hunt for a guard:
- `VerifyCredential` (`server/server.go:245`) → `verifyChallengeAndDecode` (`:298`) decodes the
  `ChargeRequest` from `credential.Challenge.Request` (`:320`), then `verifyPayload` (`:250`)
  settles against *that* decoded `request`. The settlement amount is `request.ParseAmount()`
  (`:451` pre-broadcast, `:547` on-chain) — i.e. the credential's own echoed amount.
- Tier-2 backstop `verifyPinnedFields` (`:345-371`) pins method (`:347`), intent (`:352`),
  realm (`:356`), currency (`:361`), recipient (`:366`). **It does NOT compare amount** — searched
  the whole function; no `Amount` reference exists in it.
- No expected-request parameter exists on this path. The only amount-pinning entry point is the
  *separate* method `VerifyCredentialWithExpected` (`:259`, compares `credRequest.Amount !=
  expected.Amount` at `:268`). `VerifyCredential` is still public and callable; the doc comment at
  `:232-244` merely *warns* to use the expected variant — a soft control, not a guard.

So a server with >1 priced route on one secret/recipient/currency accepts a cheap credential at an
expensive route via `VerifyCredential`. Rust *deleted* the unsafe method (AUDIT #2); Go kept it.
**No mitigating guard found.**

Deciding location: `server/server.go:345-371` (`verifyPinnedFields` omits amount) + `:245`/`:250`.

---

## #16 — emits `feePayer:true` with empty `feePayerKey`, no gate

**Verdict: CONFIRMED EXPOSED.**

Hunt for a boot/per-call gate:
- `New` (`server/server.go:87-135`): walked every branch — recipient, secretKey, currency,
  decimals, network, realm, rpcURL, store. **No check** of `config.FeePayer` vs
  `config.FeePayerSigner`. (Note `Config` has no `FeePayer bool` field at all — only
  `FeePayerSigner`; the per-call `ChargeOptions.FeePayer` is the toggle.)
- `validateChargeOptions` (`:148-171`): only inspects `Splits[].AtaCreationRequired`. No fee-payer
  check.
- `ChargeWithOptions` (`:191-197`):
  ```go
  if options.FeePayer || m.feePayerSigner != nil {
      enabled := true
      details.FeePayer = &enabled
      if m.feePayerSigner != nil {
          details.FeePayerKey = m.feePayerSigner.PublicKey().String()
      }
  }
  ```
  When `options.FeePayer == true` and `m.feePayerSigner == nil`, `FeePayer` is set true while
  `FeePayerKey` is left empty → spec-violating `feePayer:true` with no `feePayerKey`.

Rust gates both `New` and the per-call override (AUDIT #16). Go gates neither.
**No mitigating guard found.**

Deciding location: `server/server.go:191-197` (no signer guard) + `:87-135` (no boot gate).

---

## #28 — arbitrary mints get no tokenProgram + no on-chain owner lookup; verify defaults to legacy Token

**Verdict: CONFIRMED EXPOSED** (arbitrary mints ARE a supported Go config).

Hunt for a guard / on-chain resolution:
- Issuance `ChargeWithOptions` (`server/server.go:185-190`):
  ```go
  if !isNativeSOL(m.currency) {
      details.Decimals = &m.decimals
      if paycore.StablecoinSymbol(m.currency) != "" {
          details.TokenProgram = paycore.DefaultTokenProgramForCurrency(m.currency, m.network)
      }
  }
  ```
  For an arbitrary mint address, `StablecoinSymbol` (`paycore/solana.go:90-103`) returns `""`
  (not a known symbol, not a known mint) → `details.TokenProgram` is **never set** and **no RPC
  mint-owner lookup** runs. `New` (`:87-135`) does no boot-time resolution either (contrast Rust's
  `resolve_server_token_program` in `Mpp::new`).
- Verify side `verifyTransfersAgainstChallenge` (`:622-629`):
  ```go
  expectedProgram := solana.TokenProgramID            // legacy default
  tokenProgram := details.TokenProgram                 // empty for arbitrary mint
  if tokenProgram == "" && paycore.StablecoinSymbol(currency) != "" {
      tokenProgram = paycore.DefaultTokenProgramForCurrency(...)   // not taken: symbol == ""
  }
  if tokenProgram == paycore.Token2022Program { expectedProgram = ... }
  ```
  For an arbitrary Token-2022 mint: `details.TokenProgram` empty + `StablecoinSymbol` empty →
  `expectedProgram` stays **legacy Token**. The TransferChecked match then runs against the wrong
  program and the wrong (legacy-derived) ATA.

Are arbitrary mints a supported configuration? **Yes.** `ResolveMint` (`paycore/solana.go:74-87`)
returns the input currency unchanged for any value not in `knownMints` — i.e. a raw mint address is
a first-class currency. `validateChargeOptions` (`:164-169`) explicitly supports a raw SPL mint
address as `m.currency` (parses it as a pubkey for the ataCreationRequired path). So a server
configured with an arbitrary Token-2022 mint is a legitimate, reachable config, and it ships
challenges with no/legacy token program. **No mitigating guard found.**

Deciding location: `server/server.go:187` (tokenProgram only for known symbols) + `:622-626`
(verify defaults to legacy Token).

---

## #44/#45 — `parse_units` accepts `.5` / `5.` / `.`

**Verdict: REFUTED (SAFE) — low severity strictness divergence, no value corruption.**

Trace of `ParseUnits` (`intents/charge.go:81-114`):
- `".5"` → `Split(".") = ["","5"]`, `len==2`. `whole==""` → set to `"0"` (`:93-96`). `fractional="5"`.
  value = `"0"+"5"+pad`. Correct: `.5` at 6 decimals → `500000`. **Defined, correct value.**
- `"5."` → `["5",""]`, `whole="5"`, `fractional=""` → `"5"+""+pad` → `5000000`. **Defined, correct.**
- `"."` → `["",""]`, `whole="0"`, `fractional=""` → `"0"` after `TrimLeft` → returns `"0"` (`:106-108`).
  **Defined value (0), no corruption.**
- Multi-dot `"1.2.3"` → `len(parts) > 2` → rejected (`:90-91`). SAFE.
- Garbage digits caught by `big.Int.SetString` `!ok` (`:110`).

The guard the first pass missed for severity: `big.Int` is used throughout, and the empty-side
cases all collapse to *defined, mathematically-correct* values, never a wrapped/corrupted amount.
This is a strictness divergence from Rust (which rejects `.5`/`5.`/`.`), not a security bug. The
amounts that flow downstream are exactly what the literal denotes. **Severity: cosmetic/low.**

Deciding location: `intents/charge.go:93-96` + `:106-108` (empty-side defaults to defined values).

---

## #5 — push mode default-on, no `accept_push_mode` opt-in

**Verdict: CONFIRMED EXPOSED (posture).**

Hunt for an opt-in flag / gate:
- `grep -rn "accept_push_mode|AcceptPushMode|acceptPushMode|PushMode|pushMode"` across `go/`
  returns **only test names** (`parity_test.go:228`, `server_test.go:152`) — no config field,
  no flag in `Config` (`server/server.go:46-59`).
- `verifyPayload` (`:395-405`):
  ```go
  case "signature":
      if details.FeePayer != nil && *details.FeePayer { return ...reject... }   // only gate
      return m.verifySignature(...)
  ```
  `type:"signature"` (push mode) is accepted **unconditionally** except when paired with fee
  sponsorship (AUDIT #40, separate concern). There is no server-side switch to disable push mode.
- `verifySignature` (`:506-537`) verifies the landed tx by shape via `verifyOnChain` →
  `verifyTransfersAgainstChallenge`, with replay protection applied to the signature *after*
  verify. The spec §13.5 "first accepted presentation wins" trade-off is therefore live by default
  with no way to turn it off.

Rust added `Config::accept_push_mode` (default `false`). Go has no equivalent. **No gate found.**

Deciding location: `server/server.go:398-402` (push accepted with only the fee-sponsor exclusion) +
absence of any `accept_push_mode` field in `Config` (`:46-59`).

---

## Summary

| Claim | First-pass | Verdict after adversarial re-check | Deciding file:line |
|---|---|---|---|
| #2 verify echoed amount | EXPOSED | CONFIRMED EXPOSED | `server/server.go:345-371` (no amount pin) + `:245` |
| #16 feePayer:true no key | EXPOSED | CONFIRMED EXPOSED | `server/server.go:191-197` + `:87-135` |
| #28 arbitrary mint token program | UNCLEAR | CONFIRMED EXPOSED (arbitrary mints supported) | `server/server.go:187` + `:622-626` |
| #44/#45 parse_units edge cases | UNCLEAR | REFUTED (SAFE) — defined values, no corruption; low | `intents/charge.go:93-96,106-108` |
| #5 push mode default-on | EXPOSED | CONFIRMED EXPOSED (posture) | `server/server.go:398-402` + `Config` `:46-59` |
</content>
</invoke>
