# Adversarial verification — the "6 universal server-side gaps"

Goal: independently confirm that the six server-side findings flagged "EXPOSED in every
language" in `SUMMARY.md` are genuinely exposed, not a shared first-pass misread. For each
finding, two languages were sampled and the verifier tried HARD to REFUTE the exposure by
hunting for a guard. Default = CONFIRMED only if no guard exists.

Finding meanings: `rust/AUDIT-ASSESSMENT.md`. Matrix under test: `SUMMARY.md`.

Method: one adversarial sub-agent per finding, each told to locate a guard and only return
EXPOSED if none was found after a thorough search. Rust fix used as the "what a guard looks
like" reference in each case.

---

## #24 — weak secret key (no >=32-byte HMAC-secret floor) — Python, PHP

**Rust guard (reference):** `MIN_SECRET_KEY_BYTES = 32` + `validate_secret_key()` in `Mpp::new`,
covering both the `Config.secret_key` path and the `MPP_SECRET_KEY` env path.

**PYTHON — EXPOSED.** Secret resolved in `Mpp.__init__` at
`python/src/pay_kit/protocols/mpp/server/charge.py:152`
(`config.secret_key or os.environ.get(_SECRET_KEY_ENV_VAR, "")`). Only an emptiness check
(`if not secret_key: raise`). Env helper `detect_secret_key`
(`python/.../server/defaults.py:31-39`) only does `value and value.strip()`. Auto-resolver
`SecretResolver.resolve_mpp_secret` (`python/.../mpp/__init__.py:109-134`) returns the
operator string on truthiness only. HMAC consumes it at
`python/.../core/challenge.py:26` with no validation. No `len() >= 32` / byte-length /
strength gate on any path. A 1-byte `"x"` passes. **No guard found.**

**PHP — EXPOSED.** Config field `challengeBindingSecret` (`php/.../MppConfig.php:29`),
constructor validates only `expiresIn`. Adapter wires it as
`secretKey: $this->config->mpp->challengeBindingSecret ?? ''`
(`php/.../Adapter.php:202`) — even an empty string is tolerated. Server constructor
`ChargeServer` (`php/.../Server/ChargeServer.php:34-42`) accepts `string $secretKey` with no
body validation. Env/.env/generate path `resolveMppSecret`
(`php/.../SecretResolver.php:41-64`) gates only on `!== ''` / `!== null`. HMAC consumes it at
`php/.../Core/Challenge.php:81`. Every `strlen()` in the MPP tree is unrelated (dotenv quote
strip, header/credential size caps, signature parsing). **No guard found.**

**Verdict: HOLDS — both EXPOSED.**

---

## #25 — tight fee-sponsored compute-unit-price cap — Go, Ruby

**Rust guard (reference):** two caps — general `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000`
and tighter `..._FEE_SPONSORED = 10_000`, the tighter one selected when `fee_sponsored` (server
is fee payer).

**GO — EXPOSED.** Single cap constant `maxComputeUnitPriceMicroLamports uint64 = 5_000_000`
(`go/protocols/mpp/server/server.go:40`), checked at `server.go:1166`. Validator
`validateComputeBudgetInstructions(tx)` (`server.go:1120`) takes only the transaction — no
fee-payer / fee-sponsored argument; both call sites (`server.go:434`,
`verify_prebroadcast.go:45`) invoke it without fee-payer context. No `10_000`, no
`FEE_SPONSORED` variant anywhere. **No tighter fee-sponsored cap.**

**RUBY — EXPOSED.** Single cap constant `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000`
(`ruby/.../protocol/solana/verifier.rb:15`), checked at `verifier.rb:263`. `validate_compute_budget(ix)`
(`verifier.rb:252`) takes only the instruction. It is called from `validate_allowlist`
(`verifier.rb:213`) which *does* have `fee_payer` in scope, but `fee_payer` is never passed to
or consulted by the compute-budget check. No `10_000` / fee-sponsored constant. **No tighter
fee-sponsored cap.**

**Verdict: HOLDS — both EXPOSED.**

---

## #15 — shared default realm (constant vs per-recipient) — TypeScript, Lua

**Rust guard (reference):** removed `DEFAULT_REALM = "MPP Payment"`; default now derived from
the recipient pubkey (SHA-256 → `"App Id - #<digits>"`).

**LUA — EXPOSED.** Hard-coded in-repo shared constant `DEFAULT_REALM = 'MPP Payment'`
(`lua/.../server/init.lua:14`), used as fallback `realm = config.realm or DEFAULT_REALM`
(`server/init.lua:73`). It flows into the HMAC id as the first input
(`lua/.../protocol/core/challenge.lua:50-52`, `compute_challenge_id(secret_key, realm, ...)`).
`recipient` (`gate:pay_to()`) is used only as the payment target, never to derive the realm. No
per-recipient derivation exists. Two Lua services sharing the secret and leaving realm unset
share one credential namespace. **No guard found — EXPOSED.**

**TYPESCRIPT — NOT EXPOSED in the audited pay-kit source (refuted in scope).** `grep` for
`realm`/`DEFAULT_REALM`/`"MPP Payment"` across non-test, non-generated
`typescript/packages/mpp/src/` returns ZERO matches. `charge()`
(`typescript/packages/mpp/src/server/Charge.ts`) never sets a realm — realm resolution is
delegated to the external `mppx` npm dependency via `Method.toServer(Methods.charge, ...)`
(`Charge.ts:10`, `:103`). The shared constant `'MPP Payment'` exists only in the vendored
dependency (`typescript/node_modules/mppx/src/server/Mppx.ts:496`) and there it is the
LAST-resort fallback, after explicit realm > env vars > request-hostname derivation
(`resolveRealmFromRequest`). So the pay-kit TS surface under audit neither hard-codes a shared
constant nor lacks per-app differentiation (the dep derives per request hostname). The Rust
per-recipient derivation is absent, but the bare-shared-constant exposure the finding describes
is NOT present in pay-kit TS. (Caveat: if the embedding app sets `MPP_REALM` globally across
two services on the same host, the hostname derivation collapses — but that is a dependency /
deployment concern, not a pay-kit-source shared-constant default.)

**Verdict: BREAKS — TypeScript is SAFE-in-scope: no realm default in `typescript/packages/mpp/src/`;
the `'MPP Payment'` constant lives only in the external `mppx` dep behind hostname resolution
(`node_modules/mppx/src/server/Mppx.ts:496`). Lua EXPOSED (`lua/.../server/init.lua:14,73`).**

---

## #37 — network allowlist (unknown slug → mainnet) — Python, Go

**Rust guard (reference):** `validate_network()` called in `Mpp::new`, rejecting anything
outside `{mainnet, devnet, localnet}` at boot.

**PYTHON — EXPOSED.** `Mpp.__init__` (`python/.../server/charge.py:163-164`) does
`self._network = _canonical_net(config.network or "mainnet")` then `default_rpc_url(...)`.
`_canonical_network` (`python/.../_paycore/solana.py:46-53`) only maps `mainnet-beta`→`mainnet`,
passes everything else through. `default_rpc_url` (`solana.py:65-74`) returns the mainnet URL in
the else branch for any unknown slug. No boot allowlist; the constructor never validates the
slug. **No guard found.**

**GO — EXPOSED.** The `network_check.go` file is a decoy: `CheckNetworkBlockhash(network, blockhashB58)`
(`go/.../server/network_check.go:27-39`) is a verify-time, per-credential blockhash-prefix check
(rejects Surfpool localnet blockhash on non-localnet servers) — it does NOT validate the server's
own configured slug at boot (confirmed by `network_check_test.go`). Boot path `server.New`
(`go/.../server/server.go:107-116`) only handles the empty case (`config.Network = "mainnet-beta"`)
then `paycore.DefaultRPCURL(config.Network)` (`go/paycore/solana.go:61-70`) returns mainnet via
`default:` for unknown slugs. A real allowlist `ParseNetwork` exists
(`go/paykit/types.go:47-58`) but is never called in the construction path (`paykit.New`,
`go/paykit/client.go:128-131`, only checks empty); `Network` is a bare `string`, so garbage flows
through to mainnet. **No boot allowlist on the active path.**

**Verdict: HOLDS — both EXPOSED.**

---

## #38 — primary-recipient-in-splits + ataCreationRequired rejected at issuance — Ruby, PHP

**Rust guard (reference):** early loop in `validate_charge_options`
(`rust/.../server/charge.rs:491-497`) rejecting any split where
`split.recipient == self.recipient && split.ata_creation_required == Some(true)`, before HMAC,
at issuance.

**RUBY — EXPOSED.** Issuance chain `Charge#charge` (`ruby/.../server/charge.rb:54-68`) →
`payment_required_response` → `ChallengeStore#create_challenge`
(`ruby/.../protocol/core/challenge_store.rb:27`) → HMAC sign. Splits are merged into
method_details verbatim (`charge.rb:57`); `ChargeRequest` validates only amount/currency. No
split validation at issuance at all, and the combo is never checked. The only
`ataCreationRequired` logic is in the verification path (`protocol/solana/verifier.rb:84,94-95,206`),
which builds an owner allowlist and never rejects primary-in-splits. **No guard found.**

**PHP — EXPOSED.** Issuance chain `ChargeServer::createChallenge` / `paymentRequiredResponse`
(`php/.../Server/ChargeServer.php:47,178`) → `createChallenge` → `Challenge::withSecret`
(`:49-58`). Splits ride inside `request->methodDetails` untouched; `ChargeRequest` constructor
(`php/.../Intent/ChargeRequest.php:20-32`) validates only amount/currency. All split/ATA logic
is in the verification path (`php/.../Server/SolanaChargeTransactionVerifier.php:295,622-627,167,202`),
which reads `ataCreationRequired` only to build an owner allowlist, never to reject the primary.
**No guard found.**

**Verdict: HOLDS — both EXPOSED.** (Neither language has any issuance-time split validation
hook at all, so #21's checks are absent here too.)

---

## #21 — per-split validation at issuance (parse / positive / dedup / count) — TypeScript, Lua

**Rust guard (reference):** `validate_splits()` (`rust/.../server/charge.rs:482,626`) enforcing
count ≤ MAX_SPLITS, recipient parses as Pubkey, amount parses as u64 AND > 0, no duplicate
recipients — at both issuance entry points.

**TYPESCRIPT — EXPOSED.** Issuance `charge()`
(`typescript/packages/mpp/src/server/Charge.ts`), splits embedded at `Charge.ts:171`. Only the
count cap is enforced: `if (splits && splits.length > 8) throw` (`Charge.ts:85`). The Zod
schema is `recipient: z.string()` (`Methods.ts:101`) and `amount: z.string()` (`Methods.ts:95`)
— no pubkey decode, no `^\d+$`/`>0`, no dedup `Set` anywhere. 3 of 4 checks absent; they surface
late. **Materially absent — EXPOSED.**

**LUA — EXPOSED.** Issuance `Server:charge_with_options`
(`lua/.../server/init.lua:96-154`), splits guard at `init.lua:106-123`. Count cap present
(`init.lua:107`, `#options.splits > 8`); amount parseability present but NOT positivity
(`init.lua:113`, regex `^%d+$` accepts `"0"`; the aggregate-sum check at `init.lua:119` only
guards the total, so a single zero split passes). Recipient parse ABSENT (only decoded at
verify-time, `solana_verify.lua:58`). Dedup ABSENT. 2 of 4 met; per-split positivity, recipient
parse, and dedup all missing. **Materially absent — EXPOSED.**

**Verdict: HOLDS — both EXPOSED.**

---

## Bottom line

5 of 6 findings HOLD as universal server-side exposures across the sampled languages and could
not be refuted. The one BREAK is narrow and scope-dependent: **#15 in TypeScript** — the
pay-kit TS source carries no realm default at all (delegated to the external `mppx` dependency,
which resolves request hostname before any constant), so the bare-shared-constant exposure the
finding describes is not present in the audited pay-kit TS surface. The matrix's blanket "❌"
for TS #15 is an over-claim against the pay-kit source; Lua #15 (and every other sampled cell)
is genuinely exposed.
