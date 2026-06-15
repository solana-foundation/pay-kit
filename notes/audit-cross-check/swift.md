# MPP/charge audit cross-check — Swift

**Scope:** `swift/Sources/SolanaPayKit/Protocols/Mpp/` (Client/Charge.swift, Client/HTTPClient.swift, Core/Headers.swift, Core/Models.swift).

**Posture confirmed: CLIENT-ONLY.** No server-side challenge issuance, HMAC signing, `verify_credential`, replay store, or on-chain settlement exists in the production SDK. Grep for `verifyCredential|chargeChallenge|HMAC|secretKey|issueChallenge` across `Sources/` returns only:
- `PayCore/Ed25519.swift` / `SolanaSigner.swift` — Ed25519 *signing* (the client wallet), not HMAC.
- `Sources/mpp-conformance/main.swift` — a cross-language **test-vector harness** that computes challenge-ids (`HMAC-SHA256` at main.swift:740) to validate canonicalization against the Rust/TS reference vectors. It is not a runtime server verify path; it never verifies a credential against a route.

Therefore every SERVER-SIDE finding is **N/A (confirmed: no server impl)**. The real work is the CLIENT and CORE/PARSING findings.

## Findings table

| Finding | Verdict | Evidence (path:line) | Notes |
|---|---|---|---|
| #2 verify trusts echoed request | N/A | — | No server verify in SDK. Confirmed. |
| #1 partial expected-vs-request compare | N/A | — | No server verify. Confirmed. |
| #22 low-level verify not bound to challenge | N/A | — | No server verify. Confirmed. |
| #19 full ChargeRequest signed at issuance | N/A | — | No challenge issuance. Confirmed. |
| #17 method/intent enforcement (server half) | N/A | — | No server verify. |
| #17 method/intent (client half) | SAFE | Charge.swift:75 (`pickChallenge` gates `method=="solana" && intent=="charge"`); Charge.swift:32,314 (`requireSolanaCharge()` in both `authorizationHeader` and `buildPullCredential`); Models.swift:48 | Both client entry points gate before signing. |
| #32 find_sol_transfer checks | N/A | — | Server-side parsed-tx verifier. No server impl. |
| #29 find_spl_transfer source ATA | N/A | — | Server-side verifier. No server impl. |
| #25 compute-unit price inflation cap | N/A (client posture noted) | Charge.swift:56 (defaults price=1, limit=200_000); Options is caller-overridable | This is a *server-side* cap finding (server signs before broadcast). No server here. Client emits the conservative defaults the Rust client also emits; an over-cap value would be rejected by a compliant server. |
| #24 weak secret key | N/A | — | No HMAC secret in SDK. Confirmed. |
| #15 default realm shared | N/A | — | Realm is server-issued; client only echoes it (Models.swift:54 `echo()`). |
| #37 network allowlist / mainnet default | N/A (client) | Charge.swift:91 `resolveStablecoinMint` passes `network` to `Mints.resolveChargeMint` | Network allowlisting is a server-boot concern. Client does not validate the slug; it only uses it for mint resolution. No silent mainnet fallback in this layer. |
| #16 feePayer=true w/ no signer | SAFE (client variant) | Charge.swift:158-167 | Client refuses to build when `feePayer==true` but `feePayerKey` is missing (`MppError.invalidTransaction`). The signer-config half is server-only / N/A. |
| #5 push mode binding/posture | N/A | — | Client builds **pull-mode** transaction credentials only (Charge.swift:308 `buildPullCredential`, payload `.transaction`). It never *constructs* a `.signature` (push) credential. Push acceptance is a server decision. |
| #40 push + fee-sponsored reject | N/A | — | Server-side reject. No server impl. |
| #38 primary recipient in splits + ataCreationRequired | N/A | — | Issuance-time guard (server). Client does not dedup/cross-check split recipient vs primary. |
| #21 split validation at issuance | N/A (issuance) — partial client gaps noted | Charge.swift:119 (count ≤ 8), :122-130 (sum overflow checked), :131 (sum < amount) | Issuance validation is server-side. Client does enforce count cap + checked sum, but does **not** reject zero-amount splits or duplicate split recipients (see Notes / UNCLEAR below). |
| #28 token program resolution (server) | N/A | — | Server boot-time mint-owner resolution. No server impl. |
| #13 hardcoded token program in diagnostics | N/A | — | Server diagnostic. No server impl. |
| #8 balance-diagnostics decimal overflow | N/A | — | Server diagnostic. No server impl. |
| #3 replay state recorded after broadcast | N/A | — | Server replay store. No server impl. |
| #41 constant-time HMAC id compare | N/A | — | No HMAC id comparison in SDK (only the test-vector harness computes ids; it never compares). |
| #11 error title alignment | N/A | — | Cosmetic; server VerificationError. |
| **#10 client signs untrusted challenges** | **EXPOSED** | Charge.swift:103-108 `buildChargeTransaction` / :308 `buildPullCredential` / HTTPClient.swift:41 (interceptor auto-signs) | `Charge.Options` (Charge.swift:52) exposes only `computeUnitLimit`/`computeUnitPrice`. There is **no `maxAmount` cap, no `expectedNetwork`/`expectedRecipient` gate, and no expiry refusal**. `expires` is parsed and echoed (Models.swift:12,61) but never checked — an expired or hostile challenge is signed unconditionally. The `ChargeInterceptor` (HTTPClient.swift:34-51) auto-signs on every 402 with zero policy, which is exactly the auto-pay threat model #10 calls out. Rust added `max_amount_base_units`, `expected_network`, and an always-on expiry refusal; Swift has none of these. |
| **#20 implicit client-funded split ATA creation** | **EXPOSED** | Charge.swift:220 `let createAta = !serverPaysFees || split.ataCreationRequired == true` | In client-paid mode (`serverPaysFees == false`), the client auto-creates an idempotent ATA for **every** split regardless of `ataCreationRequired` — the exact silent rent-drain shape #20 flagged. Rust's accepted fix changed this to `createAta = split.ataCreationRequired == true` for *both* modes. Swift still keys on `!serverPaysFees`. A hostile server can attach N dust splits and force N × ~0.002 SOL of client-funded ATA rent. |
| #33 min remaining SOL balance | N/A (posture) | Charge.swift:236-255 native SOL path exists | Same posture as Rust (rejected — stablecoin product). SOL `systemTransfer` path exists but is not the user-facing flow; no balance check. Flagged only per checklist instruction; matches Rust's accepted posture. |
| **#26 client signs unknown Token-2022 mints** | **EXPOSED** | Charge.swift:331-360 `resolveTokenProgram`; :174-197 SPL build path | The client accepts any mint whose owner is `tokenProgram` or `token2022Program` (Charge.swift:354) and signs it. There is **no `allow_unknown_token_2022` opt-in and no known-stablecoin gate** — an arbitrary Token-2022 mint (which can carry transfer hooks executing arbitrary code on transfer) is signed without restriction. Rust added a two-tier gate refusing unknown Token-2022 mints unless opted in. Swift has no equivalent. |
| #42 decimals defaulting | EXPOSED | Charge.swift:181 `let rawDecimals = methodDetails.decimals ?? 6` | SPL path silently defaults missing `decimals` to `6` (then range-checks 0–255 at :182). Rust's accepted client fix replaced `unwrap_or(6)` with a hard error (`decimals required for SPL, spec §7.2`). Swift still silently assumes 6 — a non-6-decimal mint with omitted `decimals` produces a wrong `transferChecked` divisor. Same vulnerable shape Rust fixed. |
| #36 blockhash commitment | UNCLEAR | Charge.swift:266-267 `rpc.getLatestBlockhash()` | When `methodDetails.recentBlockhash` is absent the client calls `rpc.getLatestBlockhash()` with no explicit commitment. Whether the underlying `RpcClient` defaults to `confirmed` (safe) vs `processed` (reorg-fragile, the #36 concern) is not visible in this layer — depends on `RpcClient` impl. In the harness path `recentBlockhash` is always supplied so the RPC branch is rarely hit, but ad-hoc callers are exposed if the default is `processed`. Needs review of `RpcClient.getLatestBlockhash`. |
| **#39 parse_units integer overflow** | SAFE | Charge.swift:408-413 `parseU64` = `UInt64(value)` only | Swift never computes `10^decimals × value`. Amounts arrive pre-scaled as base-unit strings and are parsed straight to `UInt64` (overflow → `nil` → clean error). No `parse_units`/`parseUnits` exists in the client. No overflow surface. |
| #30 split-amount sum overflow | SAFE | Charge.swift:124-129 `addingReportingOverflow` + guard | Split sum uses checked `addingReportingOverflow`, rejecting overflow with `MppError.invalidTransaction`. Matches Rust's `checked_sum_split_amounts`. |
| **#9 WWW-Authenticate parser missing size cap** | **EXPOSED** | Headers.swift:6-36 `parseWWWAuthenticate`; Models.swift:16-25 `chargeRequest` (base64url-decode + JSON-parse with no length bound) | The `request` parameter is read (Headers.swift:10) and later base64url-decoded + JSON-parsed (Models.swift:18-20) with **no `MAX_TOKEN_LEN` (16 KiB) cap**. HTTPClient.swift:72 `splitWWWAuthenticate` also has no header-size bound. Rust capped the `request` param at 16 KiB for parity with credential/receipt parsers. Swift has no cap anywhere — an oversized `WWW-Authenticate` drives unbounded decode + JSON work. (Lower severity client-side: the harness controls header size in normal use, but an open 402 endpoint serving attacker-influenced challenges is the threat surface.) |
| #44/#45 parse_units edge cases | SAFE | Charge.swift:409 `UInt64(value)` | Swift's `UInt64(_ text:)` initializer rejects `".5"`, `"5."`, `"."`, `"1.2.3"`, leading `+`/`-`, and any non-ASCII-digit — returns `nil` → `MppError`. Stricter than the multi-dot bug Rust had to fix; no decimal branch exists. |
| #34 ataCreationRequired mint-address check | SAFE | Charge.swift:151 `mintStr == request.currency, isLikelyBase58MintAddress(mintStr)` (:420-423 parses as `Pubkey`) | Direct base58/Pubkey-parse check on the currency when `ataCreationRequired` is set. Matches the clearer intent Rust adopted. |
| #27/#14 docstrings/precedence | N/A | — | Cosmetic/doc. |

## Top exposures (ranked by severity)

1. **#26 (Medium) — EXPOSED.** Client signs arbitrary Token-2022 mints (transfer-hook code execution) with no opt-in gate. `Charge.swift:354` accepts any token-2022-owned mint; no known-stablecoin allowlist, no `allow_unknown_token_2022`.
2. **#10 (Medium) — EXPOSED.** Auto-pay builder/interceptor signs untrusted challenges with no max-amount cap, no expected-network/recipient gate, and **no expiry refusal** (`expires` parsed but never checked). `Charge.swift:103`, `HTTPClient.swift:41`.
3. **#20 (Medium) — EXPOSED.** Implicit client-funded split ATA creation in client-paid mode — `Charge.swift:220` `createAta = !serverPaysFees || ...`. Silent rent-drain via N dust splits. Rust narrowed this to the flag only.
4. **#42 (Low) — EXPOSED.** SPL decimals silently default to 6 — `Charge.swift:181` `methodDetails.decimals ?? 6`. Wrong divisor for non-6-decimal mints. Rust now hard-errors.
5. **#9 (Low) — EXPOSED.** No 16 KiB size cap on the `WWW-Authenticate` `request` param before base64url-decode + JSON-parse — `Headers.swift:10` / `Models.swift:18-20`.
6. **#36 (Low) — UNCLEAR.** `Charge.swift:266` fetches blockhash with no explicit commitment; safety depends on the `RpcClient` default (`confirmed` vs `processed`). Needs review of `RpcClient.getLatestBlockhash`.

## Secondary observations (within N/A findings)

- **#21 client-side split gaps:** Swift enforces split count ≤ 8 (`Charge.swift:119`) and checked sum (`:124`), but unlike the full server validation does **not** reject zero-amount splits or duplicate split recipients before signing. Server-side issuance validation is N/A here, and these would fail on-chain, but a defense-in-depth gap relative to Rust's `validate_splits`.
