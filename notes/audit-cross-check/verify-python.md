# Adversarial verification — Python MPP/charge

Goal: refute each claimed exposure by hunting for a missed guard. CONFIRMED EXPOSED only
when no mitigation exists; REFUTED(SAFE) requires a cited guard. Code root:
`python/src/pay_kit/protocols/mpp/`. Verified at branch `main`.

---

## Claim #2 (EXPOSED) — `verify_credential` settles against the credential's echoed amount

**Cited:** `server/charge.py:283-299`.

**Refutation attempt — looked for an expected-request requirement on the simple path.**

`verify_credential` (`charge.py:283-299`) calls `_verify_challenge_and_decode` then
`_verify_payload`. `_verify_challenge_and_decode` (`:338-375`) runs Tier-1 (HMAC at `:357`,
expiry at `:360`) and Tier-2 pinned fields (`_verify_pinned_fields:377-414`). The pinned
fields are: method (`:385`), recipient (`:410`), and — reading the full body — intent/realm/
currency are the documented set. **Amount is NOT in the pinned set.** The request handed to
`_verify_payload` is `request` derived from `challenge.decode_request()` (`:363`), i.e. the
credential's OWN echoed amount. Settlement runs against that.

The safe path `verify_credential_with_expected` (`:301-336`) explicitly compares
`cred_request.amount != expected.amount` (`:316`) and settles against `expected` (`:336`) —
but it is a separate method and is **not forced**. `verify_credential` remains public and
performs no amount comparison.

Searched for any guard that would block the simple path on a multi-route server (an
`if route_count > 1` style gate, a required-expected flag): none exists. The docstring at
`:286-296` itself concedes multi-route servers "MUST use `verify_credential_with_expected`"
— an instruction, not an enforced guard.

**Verdict: CONFIRMED EXPOSED.** A server gating >1 priced route on one secret accepts a
cheap credential at an expensive route. Deciding line: `server/charge.py:298` (settles
against credential-decoded `request`, no amount pin in `_verify_pinned_fields`).

---

## Claim #5 (UNCLEAR) — push-mode posture: opt-in or always accepted?

**Cited:** `server/charge.py:425-431`.

**Resolution.** `_verify_payload` (`:416-433`) dispatches purely on `payload.type`:
`"transaction"` → pull verify; `"signature"` → `_verify_signature` (`:431`). The only gate
on the `"signature"` branch is the fee-sponsorship rejection at `:426-430` (push + feePayer
is rejected — this is finding #40, SAFE). There is no `accept_push_mode` flag.

Searched the whole module for any opt-in toggle: `grep -rn "accept_push\|push_mode\|allow_push"`
over `mpp/` returns nothing. The `Mpp` constructor and `ChargeOptions` carry no such field.
Push (`type="signature"`) is **always accepted** by shape, subject only to the fee-sponsor
exclusion.

This matches MPP spec §13.5 (push is a legitimate shape-matching mode), so it is not a
correctness bug. But relative to Rust — which makes push opt-in (default OFF) to reduce
attack surface — Python accepts push by default.

**Verdict: EXPOSED (posture gap vs Rust), not a spec violation.** Deciding line:
`server/charge.py:425` (dispatches `type="signature"` with no opt-in gate; only the
fee-sponsor exclusion at `:426` guards it).

---

## Claim #36 (EXPOSED) — client blockhash fetch uses default commitment, not `confirmed`

**Cited:** `client/charge.py:262`.

**Refutation attempt — looked for an explicit commitment arg or a `confirmed` wrapper.**

`client/charge.py:262`: `resp = await rpc_client.get_latest_blockhash()` — called with NO
commitment argument, so it uses the solana-py RPC client default. The branch is reached only
when `details.recent_blockhash` is absent (`:259-263`), which is the normal client-funded
path. No commitment is threaded in anywhere on this branch.

Cross-checked the fixed reference: Rust `rust/crates/mpp/src/client/charge.rs:211-217`
explicitly documents "Audit #36" and calls
`get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())`. Python has no
equivalent — no `Commitment`/`confirmed` reference on this path.

**Verdict: CONFIRMED EXPOSED.** A `processed`-commitment blockhash can vanish under reorg →
signed tx fails `BlockhashNotFound`. Low severity. Deciding line: `client/charge.py:262`.

---

## Claim #44/#45 (EXPOSED) — `parse_units` accepts malformed amounts

**Cited:** `_paycore/currency.py:36-61`.

**Is this MPP charge's amount path or only x402?** BOTH. Callers (`grep parse_units`):
- `server/charge.py:242` — `charge_with_options` calls `base_units = parse_units(amount, self._decimals)`. This output becomes `request_obj["amount"]` (`:257`) which is HMAC-signed into the challenge (`:268,278`) and later settled against on-chain. **MPP charge amount path confirmed.**
- `x402/__init__.py:103` — also uses it.
So this is shared and squarely on the MPP charge amount path, not x402-only.

**Does it corrupt amounts?** Executed the exact source logic (env Python is 3.9, so
`StrEnum` import blocks direct import; reran the function body verbatim standalone):

| input | parse_units(x, 6) | should be |
|---|---|---|
| `".5"` | `500000` | REJECT |
| `"5."` | `5000000` | REJECT |
| `"."` | `0` | REJECT |
| `"+5"` | `5000000` (silent — means "5") | REJECT |
| `"1_000"` | `1000000000` (Python int underscores → 1000) | REJECT |
| `"١٢٣"` (Arabic-Indic) | `123000000` (`int()` accepts Unicode digits) | REJECT |
| `"1.2.3"` | REJECTED (`len(parts) > 2`, `:39`) | REJECT ✓ |

Only the multi-dot case (`:38-40`) is guarded. The integer-part path does `int(value_str)`
(`:56`) with no ASCII-digit / sign / underscore screening; the `.split(".")` (`:38`) does
not reject empty integer or empty fractional halves (`whole = parts[0] or "0"` at `:42`
silently rehabilitates `".5"`; `fractional = ""` makes `"5."` look like `"5"`).

**Corruption is real but bounded by who supplies `amount`:** on the MPP charge path the
`amount` argument originates from the SERVER's own `charge("...")` call, not an attacker — so
the practical impact is a server fat-fingering `"+5"`/`"1_000"`/`"١٢٣"` and silently charging
a different amount than written, with no error. Not remote-attacker-reachable on the charge
issuance path, but it is a silent-corruption / data-integrity defect.

Cross-checked the fix shape: Rust `protocol/intents/mod.rs:50` rejects empty halves
(`integer.is_empty() || fraction.is_empty()`, "Audit #44/#45"), requires
`b.is_ascii_digit()` on both parts, and its no-dot branch uses `u128::parse` which rejects
`+` and underscores. Python matches none of these.

**Verdict: CONFIRMED EXPOSED.** Deciding line: `_paycore/currency.py:56` (`int(value_str)`
accepts Unicode digits / underscores; combined with the empty-half rehab at `:42-43` and the
missing ASCII-digit screen). On the MPP charge amount path via `server/charge.py:242`.

---

## Summary

| Claim | Verdict | Deciding file:line |
|---|---|---|
| #2 | CONFIRMED EXPOSED | `server/charge.py:298` (settles credential's echoed amount; no amount pin in `_verify_pinned_fields:377-414`) |
| #5 | EXPOSED (posture; spec-permitted) | `server/charge.py:425` (push always accepted; no `accept_push_mode` opt-in anywhere in module) |
| #36 | CONFIRMED EXPOSED | `client/charge.py:262` (default commitment vs Rust's pinned `confirmed`) |
| #44/#45 | CONFIRMED EXPOSED | `_paycore/currency.py:56` (no ASCII-digit/empty-half/sign guard; on MPP charge path via `server/charge.py:242`) |
