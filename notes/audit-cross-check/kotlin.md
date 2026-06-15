# MPP/charge audit cross-check — Kotlin

**Scope:** Kotlin MPP implementation is **CLIENT-ONLY**. Confirmed: there is no
server-side directory under `protocols/mpp/`. The only files are
`client/{Charge,HttpClient}.kt`, `core/{Headers,Types,CanonicalJson}.kt`, and the
top-level `client/ChargeInterceptor.kt`. A grep for `verify|hmac|secret|consume_signature|replay|issuance`
across the MPP tree returns only the `realm` field (echoed, never recomputed),
`chargeRequest()` decode, and a doc comment mentioning "broadcast" — no HMAC
recomputation, no replay store, no challenge issuance, no on-chain verification.
All SERVER-SIDE findings are therefore **N/A (confirmed: no server impl)**.

The amount path is also notably different from Rust: MPP charge amounts are
base-unit integer strings parsed via `parseU64` (BigInteger, bounded to
`[0, 2^64)`). There is **no `parse_units` (`10^decimals * value`) path** in the
MPP charge code — the decimal-scaling helper that #39/#44/#45 target lives only
in the x402 protocol (`protocols/x402/...`), which is out of scope for this MPP
cross-check.

| Finding | Verdict | Evidence (path:line) | Notes |
|---|---|---|---|
| #2 verify trusts echoed request | N/A | (no server verify) | No `verify_credential`-style API exists. |
| #1 partial expected-vs-request compare | N/A | (no server verify) | No comparison surface. |
| #22 low-level verify not bound to challenge | N/A | (no server verify) | — |
| #19 full ChargeRequest signed w/o validation | N/A | (no server issuance) | Client never HMAC-signs a ChargeRequest. |
| #17 method/intent enforcement | SAFE (client) | `client/Charge.kt:41,327`; `core/Types.kt:28-32` | `requireSolanaCharge()` rejects non-`solana`/non-`charge` before signing, at both entry points (`authorizationHeader`, `buildCredentialHeader`). Server half N/A. Selection in `core/Headers.kt:104` also filters on method/intent. |
| #32 find_sol_transfer missing checks | N/A | (no server verify) | Client builds, never parses/verifies on-chain. |
| #29 find_spl_transfer ignores source ATA | N/A | (no server verify) | — |
| #25 compute-unit price inflation (fee-sponsored) | N/A | (no server) | Client emits price=1/limit=200_000 (`Charge.kt:67,230-231`); the *cap* is a server defense. Client is not the harmed party. |
| #24 weak secret key | N/A | (no server) | No HMAC secret in client. |
| #15 default realm shared | N/A | (no server) | Realm only echoed (`Types.kt:16,52`). |
| #37 network allowlist / mainnet default | N/A | (no server boot) | Client reads `md.network` only to resolve a known-stablecoin mint (`Charge.kt:233`); no boot-time allowlist surface, no silent mainnet fallback in a verify path. |
| #16 feePayer=true w/o signer | N/A | (no server) | Client treats `feePayer==true && feePayerKey!=null` as the fee-payer case (`Charge.kt:224`); if `feePayerKey` is null it falls back to client-paid — no spec-violating challenge issued (client doesn't issue). |
| #5 push not bound to challenge | N/A | (no server verify) | Client builds transaction credentials only. |
| #40 push + fee-sponsored | N/A | (no server verify) | — |
| #38 primary recipient in splits + ataCreationRequired | N/A | (server issuance guard) | Client does not issue challenges; cannot gate at issuance. See note in #20. |
| #21 incomplete split validation at issuance | N/A | (no server issuance) | Client validates splits it consumes (count<=8, parse, non-negative, sum<=u64) at `Charge.kt:191-211`, but issuance-time validation is a server concern. |
| #28 token program resolution | SAFE (client) | `client/Charge.kt:388-421` | `resolveTokenProgram`: pinned program validated to {Token,Token-2022}; known stablecoins answered from table (PYUSD/USDG/CASH → Token-2022, `Charge.kt:402-408`); arbitrary mint reads on-chain owner via `MintOwnerResolver`, **fails closed** when no resolver (`Charge.kt:409-413`). Mirrors Rust #28. |
| #13 hardcoded token program in diagnostics | N/A | (no server diagnostics) | — |
| #8 balance-diagnostics decimal overflow | N/A | (no server diagnostics) | — |
| #3 replay state after broadcast | N/A | (no server verify/replay) | — |
| #41 non-constant-time HMAC compare | N/A | (no server) | — |
| #11 error title alignment | N/A | (cosmetic, server) | — |
| **#10 client signs untrusted challenges** | **EXPOSED** | `client/Charge.kt:319-343`; `core/Types.kt:20` | `buildCredentialHeader` signs with **no expiry check, no max-amount cap, no expected-network/recipient/currency guard**. `expires` is parsed and echoed (`Headers.kt:124`, `Types.kt:20,42`) but there is **no `isExpired()` anywhere** and no fail-closed expiry refusal. Rust #10 added always-on expiry refusal + opt-in `max_amount`/`expected_network`. None of this exists in Kotlin. Unsafe for auto-pay flows. |
| **#20 implicit client-funded split ATA creation** | **EXPOSED** | `client/Charge.kt:542` | `val createAta = feePayer == null || split.ataCreationRequired == true`. In client-paid mode (`feePayer == null`) the client **auto-creates an ATA for every split regardless of the flag** — the exact pre-fix Rust shape. Rust #20 changed this to `split.ata_creation_required == Some(true)` (flag-only, both modes). Hostile server can attach N dust splits → forces ~N×0.002 SOL rent drain on the client. |
| #26 client signs unknown Token-2022 (hook risk) | EXPOSED (partial) | `client/Charge.kt:388-421` | `resolveTokenProgram` resolves & validates the program to {Token, Token-2022} but **does NOT refuse unknown Token-2022 mints**. Rust #26 added an `allow_unknown_token_2022` opt-in gate: refuse to sign when the program is Token-2022 AND the mint is not a known stablecoin. Kotlin will happily sign an arbitrary Token-2022 mint (transfer-hook surface) with no opt-in. Known-stablecoin Token-2022 is fine; the gap is arbitrary Token-2022 mints. |
| #33 min remaining SOL for signers | N/A | (Rust REJECTED) | SOL transfer path exists (`Charge.kt:459-488`) but per Rust assessment the product is stablecoin-only and this was rejected. Same posture; only a concern if SOL is exposed as a user path. |
| **#42 decimals defaulting** | **EXPOSED** | `client/Charge.kt:506` | `val decimals = methodDetails.decimals ?: 6`. The client SPL path **silently defaults missing decimals to 6**, producing a wrong divisor / wrong `transferChecked` decimals byte for any non-6-decimal mint. Rust #42 changed the client to **error** when decimals is absent on the SPL path (`ok_or(... "decimals is required for SPL")`). This is a signed-transaction correctness bug, the worst failure mode per the Rust rationale. |
| #36 blockhash commitment | EXPOSED (minor) | `client/HttpClient.kt:73-78` | `getLatestBlockhash` is called with **no explicit commitment param** (`payload` has only jsonrpc/id/method). Rust #36 pins `confirmed`. RPC default is `finalized` (safer than `processed`, so not the worst case), but the explicit-`confirmed` guarantee the audit asked for is absent. Low severity. |
| #39 parse_units integer overflow | N/A | `client/Charge.kt:445-457` | No `10^decimals * value` path in MPP. `parseU64` uses BigInteger bounded to `[0,2^64)` — cannot overflow/wrap. The decimal-scaling helper lives only in x402, out of scope. |
| #30 split-amount sum overflow | SAFE | `client/Charge.kt:200-211` | Split amounts summed via `BigInteger.add`, with an explicit `splitsTotal > U64_MAX` bound check after each add. No wrapping `.sum()`; cannot overflow silently. |
| **#9 WWW-Authenticate parser missing size cap** | **EXPOSED** | `core/Headers.kt:116,128`; `client/Charge.kt` decode | The `request` param is read (`Headers.kt:116`) and `Base64Url.decode(request)` is run (`Headers.kt:128`) with **no `MAX_TOKEN_LEN` (16 KiB) cap**. `decodeChargeRequest` (`Headers.kt:150-157`) base64-decodes + JSON-parses the same param, also uncapped. `Base64Url` (`paycore/Base64Url.kt`) has no length guard. Rust #9 caps `request` at `MAX_TOKEN_LEN` before decode/parse. A large `WWW-Authenticate` value drives proportional decode+parse work. |
| #44/#45 parse_units edge cases (".5","5.","1.2.3") | N/A | `client/Charge.kt:453-457` | No dot/fraction parsing in MPP — `toBigIntegerOrNull` rejects any non-integer string (including `".5"`, `"5."`, `"1.2.3"`, non-digits) by returning null → `InvalidTransaction`. The dotted-decimal helper that #44/#45 target is x402-only. |
| #34 ataCreationRequired mint-address check | SAFE | `client/Charge.kt:250` | Direct check `mint != request.currency || !isLikelyBase58MintAddress(mint)` — requires currency to be the literal base58 mint when any split sets `ataCreationRequired`. |
| #27/#14 docstrings/precedence | N/A | (cosmetic) | — |

## Top exposures (EXPOSED + UNCLEAR, ranked)

1. **#42 decimals default to 6 — `client/Charge.kt:506`** (`methodDetails.decimals ?: 6`). Signs a transaction with a wrong `transferChecked` decimals byte / wrong divisor for any non-6-decimal mint. Worst failure mode (silent wrong signed output). Rust errors instead. **HIGH for correctness.**
2. **#10 no expiry / amount / network guards — `client/Charge.kt:319-343`.** `buildCredentialHeader` signs untrusted challenges with no always-on expiry refusal and no opt-in max-amount/expected-network caps. `expires` is parsed but never enforced (no `isExpired`). Unsafe for auto-pay. **MEDIUM.**
3. **#20 implicit split ATA creation — `client/Charge.kt:542`** (`createAta = feePayer == null || ataCreationRequired == true`). Client auto-creates split ATAs in client-paid mode regardless of the flag — rent-drain via dust splits. Rust is flag-only. **MEDIUM.**
4. **#26 unknown Token-2022 mints signed without opt-in — `client/Charge.kt:388-421`.** No refusal of arbitrary (non-stablecoin) Token-2022 mints, which can carry transfer hooks. No `allow_unknown_token_2022` gate. **MEDIUM.**
5. **#9 no size cap on WWW-Authenticate `request` param — `core/Headers.kt:116,128`.** Uncapped base64url-decode + JSON-parse of the challenge `request`. **LOW (DoS surface).**
6. **#36 blockhash fetched without explicit `confirmed` commitment — `client/HttpClient.kt:73-78`.** Relies on RPC default (`finalized`); not `processed`, so low risk, but the explicit-`confirmed` guarantee is missing. **LOW.**

No UNCLEAR items.
