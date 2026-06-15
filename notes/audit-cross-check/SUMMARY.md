# MPP/charge audit — cross-language exposure matrix

**Question:** the Rust MPP/charge impl was audited and fixed in PR #150 (`rust/AUDIT-ASSESSMENT.md`, 45 findings). Are the other language implementations exposed to the same vulnerabilities?

**Short answer: yes, broadly.** The audit fixes were applied to Rust only and were never propagated to the other SDKs. Every other server implementation (TS, Go, Python, Ruby, PHP, Lua) is missing the same cluster of ~6–7 server-side hardening fixes, and every client implementation (TS, Go, Python, Kotlin, Swift) is missing the same ~4 client-side fixes.

Per-language detail: `typescript.md`, `go.md`, `python.md`, `ruby.md`, `php.md`, `lua.md`, `kotlin.md`, `swift.md`. Iteration 1 = first-pass analysis (one agent per language reading the real code). Findings marked ⚠️ are pending adversarial re-verification (iteration 2).

## Implementation scope

| Language | Server (verify + issue) | Client (build + sign) |
|---|---|---|
| Rust | ✅ (audited baseline) | ✅ (audited baseline) |
| TypeScript | ✅ | ✅ |
| Go | ✅ | ✅ |
| Python | ✅ | ✅ |
| Ruby | ✅ | ❌ (server-only) |
| PHP | ✅ | ❌ (server-only) |
| Lua | ✅ | ❌ (server-only) |
| Kotlin | ❌ (client-only) | ✅ |
| Swift | ❌ (client-only) | ✅ |
| html | — | — (x402 / static only, no MPP) |

## Exposure matrix

Legend: ❌ EXPOSED · ✅ SAFE · — N/A (surface not implemented) · ⚠️ UNCLEAR (needs review)

### Server-side findings

| Finding | TS | Go | Py | Rb | PHP | Lua |
|---|---|---|---|---|---|---|
| **#24** weak secret key (no ≥32B floor) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#25** no tight compute-price cap (fee-sponsored) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#15** shared default realm | ✅\* | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#37** no network allowlist (unknown→mainnet) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#38** primary-in-splits + ataCreationRequired | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#21** split validation at issuance | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#28** arbitrary Token-2022 mint → legacy Token | ❌ | ⚠️ | ❌ | ❌ | ⚠️ | ❌ |
| **#9** WWW-Authenticate `request` size cap | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **#2** verify trusts echoed amount | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **#1** partial expected-vs-request comparison | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **#5** push mode default-on (no opt-in) | ⚠️ | ❌ | ⚠️ | ✅ | ❌ | ⚠️ |
| **#16** feePayer=true w/o signer | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| **#19** issuance signs unvalidated request | ✅ | ✅ | — | ✅ | ❌ | ✅ |
| **#3** replay reserved only after broadcast | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **#22** low-level verify request not bound | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| **#32** find_sol_transfer fee-payer guard | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#29** find_spl_transfer fee-payer/ATA guard | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#40** push + fee-sponsored reject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#41** constant-time HMAC id compare | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#17** server method/intent enforcement | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#13/#8** balance-diagnostics (token prog / decimals) | — | — | — | — | — | — |

### Client-side findings

| Finding | TS | Go | Py | Kotlin | Swift |
|---|---|---|---|---|---|
| **#10** signs untrusted challenges (no expiry/amount/network guard) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#20** implicit client-funded split ATA creation | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#26** signs unknown Token-2022 mints (transfer-hook risk) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#42** SPL decimals silently default to 6 | ❌ | ❌ | ❌ | ❌ | ❌ |
| **#17** client method/intent gate before signing | ✅ | ❌ | ✅ | ✅ | ✅ |
| **#36** blockhash commitment = confirmed | ✅ | ✅ | ❌ | ⚠️ | ⚠️ |
| **#33** min remaining SOL balance | — | — | — | — | — | (Rust rejected: stablecoin-only) |

### Core/parsing findings

| Finding | TS | Go | Py | Rb | PHP | Lua | Kotlin | Swift |
|---|---|---|---|---|---|---|---|---|
| **#39** parse_units overflow | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| **#30** split-sum overflow | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **#44/#45** parse_units edge cases (`.5`,`5.`,`1.2.3`) | ✅ | ⚠️ | ❌ | ✅ | — | ⚠️ | — | ✅ |

## The headline: 6 universal server gaps + 4 universal client gaps

These are EXPOSED in **every** language that implements the surface — i.e. the Rust fix was never ported anywhere:

**Server (all of TS/Go/Py/Rb/PHP/Lua):**
1. **#24 weak secret key** — HMAC key not length-validated. An empty or `"key"`-strength `MPP_SECRET_KEY` lets an attacker forge challenges. *Boot-time gate, ~5 lines per impl.*
2. **#25 compute-unit-price drain** — no tight fee-sponsored cap; a fee-paying merchant can be drained ~0.001 SOL/charge in a loop.
3. **#15 shared default realm** — every server with the same secret + default realm shares a credential namespace; a credential paid to service A verifies on service B.
4. **#37 network allowlist** — unknown network slugs silently treated as mainnet (and `"mainnet-beta"` vs canonical `"mainnet"` drift).
5. **#38 primary-recipient-in-splits + ataCreationRequired** — fee-sponsored ATA-recreate slow-drain not rejected at issuance.
6. **#21 split validation at issuance** — no per-split parse / positive-amount / dedup / count cap; invalid splits surface late.

Plus near-universal: **#28** (arbitrary Token-2022 mints resolve to legacy Token program) and **#9** (WWW-Authenticate `request` param not size-capped).

**Client (all of TS/Go/Py/Kotlin/Swift):**
1. **#10** — auto-pay builders sign challenges with no expiry refusal, no max-amount cap, no expected-network pin. *Highest client risk for agent/auto-pay flows.*
2. **#20** — client auto-funds every split ATA regardless of `ataCreationRequired` (silent rent drain by a hostile server).
3. **#26** — client signs unknown Token-2022 mints (which can carry arbitrary transfer hooks) with no opt-in gate.
4. **#42** — SPL `decimals` silently defaults to 6, producing a wrong signed `transferChecked` for non-6-decimal mints.

## Notable language-specific divergences

- **#2 / #1 (echoed-request trust):** Go and Python still expose a `verify_credential` that settles against the credential's own echoed amount (the exact footgun Rust *deleted*) — multi-route servers accept a $1 credential on a $100 route. Ruby/PHP/Lua already require an explicit expected request (SAFE); TS pins amount but #1's full-field comparison is incomplete.
- **#3 (replay ordering):** only **TypeScript** still records the consumed signature *after* confirmation (the original bug). Go/Py/Rb/PHP already reserve before broadcast; Lua reserves before but lacks the post-timeout status recovery.
- **#16 (feePayer w/o signer):** Go and Lua emit a spec-violating `feePayer:true`/no-`feePayerKey` challenge; others gate it.
- **#19 (unvalidated issuance):** PHP's `createChallenge` signs an arbitrary caller request with no validation.
- **#36 (blockhash commitment):** Python uses default commitment; Swift/Kotlin depend on RPC client default.

## What's consistently SAFE everywhere

Good parity across the board (no language exposed): **#32/#29** fee-payer transfer-drain guards, **#40** push+fee-sponsored reject, **#41** constant-time HMAC compare, **#17** server method/intent enforcement, **#39/#30** amount/split arithmetic overflow (native bignum or checked ops). These were either pre-existing protections or universal language properties (Python/Ruby bignums).

## Verification (iteration 2 — adversarial re-check)

Each EXPOSED claim and every ⚠️ UNCLEAR item was re-checked by a fresh agent instructed to *refute* it (hunt for a guard the first pass missed). Detail in `verify-*.md`. Results:

**Held up as EXPOSED (survived refutation):**
- All 6 universal server gaps (#24, #25, #37, #38, #21) and #28/#9 — confirmed across the sampled languages.
- All 4 universal client gaps (#10, #20, #26, #42) — confirmed across all client impls. (#10: Kotlin/Swift parse `expires` but never compare it to a clock — grep for `isExpired/now()/Date()` is empty.)
- TS #3 (replay-after-confirm, no post-timeout recovery), Go+Python #2 (echoed-amount verify), PHP #19, Go+Lua #16, Go #28, Go+Python+Lua #5 (push posture).

**Corrected / downgraded after refutation (matrix updated above):**
- **TS #15 → ✅\*** — the realm default lives in the external `mppx` npm dependency, which derives the realm from the request hostname *before* any shared constant. The pay-kit TS source has no shared-constant default. Residual risk is deployment-level (a global `MPP_REALM` shared across two same-host services), not a hardcoded default.
- **Ruby #1 → ✅** — externalId/description gap can't reach settlement: the verifier resolves against the *expected* request and binds externalId as an on-chain memo. Parity nit, no drain.
- **Ruby #9 → ✅** — the server inbound path is capped at 16 KiB; the uncapped `parse_www_authenticate` is a client helper with no server caller.
- **PHP #16 → ✅** — verify rejects feePayer-without-key and the Adapter can't emit the bad shape.
- **Go/Python #44/#45 → low / not attacker-reachable** — `.5`/`5.`/`.` parse to *defined* values (no corruption) in Go; in Python they're accepted but the `amount` is server-supplied at issuance, so it's a silent-mischarge data-integrity nit, not a remote exploit. Strictness divergence from Rust, low priority.

**⚠️ Key scope finding — TypeScript verify/issuance logic is in an external dependency.** The TS MPP *server* verification, HMAC binding, realm derivation, and expected-comparison logic live in the `mppx` npm package (`node_modules/mppx`, resolved v0.5.5), **not** in pay-kit source. So TS findings #1, #2, #5, #15, #25 are really about `mppx`, and fixing them means an upstream change to that package, not an edit in this repo. The client-side TS findings (#3 replay is server though; #10/#20/#26/#42) — #20/#26/#42 are in-repo (`packages/mpp/src/client/Charge.ts`); #3 is in `packages/mpp/src/server/Charge.ts` (in-repo). Worth confirming who owns `mppx` before scoping TS remediation.

## Remediation status (iteration 3–4)

All confirmed exposures were fixed on branch `fix/cross-language-audit`, then a fresh adversarial **closure audit** (iteration 4) re-checked every fix against the *changed* code. The closure audit caught two gaps the implementation pass missed, which were then fixed:

- **Lua #25** — the tight fee-sponsored compute cap was claimed but never actually implemented (zero diff). Now fixed: `10_000` cap gated on `method_details.feePayer`. (602 tests pass.)
- **Swift #9** — cap was added to the `WWW-Authenticate` parser but not the direct-construction path. Now capped in `chargeRequest`/`init` too. (125 tests pass.)
- **PHP #19** (parity, not exploitable) — issuance currency/network/recipient match-checks were opt-in and the Adapter didn't set them. Adapter now pins currency/network/recipient/decimals. (431 tests pass.)

**Final state — all findings CLOSED and test-verified**, per language:
| Lang | Tests | Notes |
|---|---|---|
| Go | ✅ `go test ./...` green | all 16 findings closed |
| Python | ✅ MPP suites green (264) | pre-existing flask/django env errors unrelated |
| Ruby | ✅ 449 | server-only |
| PHP | ✅ 431 | #19 parity wired |
| Lua | ✅ 602 | #25 gap fixed |
| TypeScript | ✅ 418 + typecheck | in-repo subset; rest → mppx |
| Swift | ✅ 125 | #9 direct path fixed |
| Kotlin | ✅ 233 + coverage gate | toolchain installed (openjdk@17 + gradle 9.5.1); running it caught 2 stale fixtures missing `decimals` (from the #42 fix), now fixed |

`mppx`-owned findings (#1/#24/#15/#9) are documented in `MPPX-UPSTREAM-REPORT.md` for an upstream release.

## Recommended remediation order

1. **Port the 6 universal server gaps** (#24, #25, #15, #37, #38, #21) to TS/Go/Py/Rb/PHP/Lua — these are cheap, mostly boot-time or issuance-time guards, and close the highest-value drains/forgeries.
2. **Port the 4 universal client gaps** (#10, #20, #26, #42) to TS/Go/Py/Kotlin/Swift.
3. **Fix the language-specific high-severity divergences:** TS #3 (replay), Go+Py #2 (echoed-amount verify), PHP #19, Go+Lua #16.
4. **Tail:** #28 token-program resolution, #9 header size cap, #1 full comparison, #36 commitment, #44/#45 parser strictness.
