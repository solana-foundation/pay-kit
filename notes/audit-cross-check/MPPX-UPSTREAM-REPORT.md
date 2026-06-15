# Security report for `mppx` — MPP/charge findings (from pay-kit audit cross-check)

**To:** maintainers of the `mppx` npm package
**From:** Solana pay-kit team
**Date:** 2026-06-15
**Origin:** the Rust MPP/charge implementation was audited (2026-05-26 Solana MPP audit) and hardened. We cross-checked our TypeScript SDK (`@solana/mpp`) delegates its **server-side** HMAC issuance/verification, the challenge↔credential binding, expiry, realm handling, and the `WWW-Authenticate` codec to the external **`mppx`** dependency. The four findings below therefore cannot be fixed in pay-kit — they live in `mppx` and need an upstream release.

- **Resolved version analyzed:** `mppx` v0.5.5 (pay-kit peerDep `mppx >= 0.5.5`). The 0.5.17 variant under the playground example binds the same field set; the drift changes no verdict.
- The compiled `dist/` is the runtime source of truth (mppx is not built from pay-kit).
- "Required fix" is taken from the Rust audit's "Action taken" (the reference implementation of each fix).

## Severity summary

| # | Severity | Title | mppx location |
|---|---|---|---|
| #1 | **Medium** | Partial expected-vs-request comparison — most payment fields never pinned | `dist/server/Mppx.js:312-335`, used `:181` |
| #24 | **Medium** | Weak HMAC secret key accepted (non-empty check only) | `dist/server/Mppx.js:28-30`, `dist/Challenge.js:451` |
| #15 | **Low** | Default realm is a shared constant across servers | `dist/server/Mppx.js:287` |
| #9 | **Low** | `WWW-Authenticate` parser missing size cap | `dist/Challenge.js` `deserialize`/`deserializeList` |

pay-kit applied a defense-in-depth 16 KiB header cap for #9 at its own boundary (`packages/mpp/src/shared/challenge-guard.ts`), but the authoritative per-`request`-param cap belongs in mppx.

---

## #1 (Medium) — Partial expected-vs-request comparison

- **Location:** `dist/server/Mppx.js:312-319` (`requestBindingFields`), `:320-335` (`getRequestBindingMismatch`/`getRequestBinding`), invoked at `:181`.
- **Vulnerable behavior:** the credential↔route binding compares only `['amount','currency','recipient','chainId','memo','splits']`. `chainId`/`memo` don't apply to Solana charge, so effectively only amount/currency/recipient/splits are pinned. **`network`, `decimals`, `tokenProgram`, `feePayer`, `feePayerKey`, `externalId`, `description` are never compared.** The consumer's `verify()` then reads those unchecked fields straight off the echoed credential, so a credential carrying a different decimals/tokenProgram/feePayerKey/network than the route configured flows into on-chain settlement unchecked.
- **Required fix (Rust #1):** exhaustive up-front comparison between the route-built request and the credential's decoded request, covering all payment-constraining fields — top-level `amount,currency,recipient,externalId,description` and `methodDetails.{network,decimals,tokenProgram,feePayer,feePayerKey,splits}` (splits element-wise, order-sensitive). **Exclude `recentBlockhash`** (per-challenge state, would break the happy path). Extend `requestBindingFields` or add a dedicated exhaustive comparator so any divergence is rejected before settlement.

## #24 (Medium) — Weak secret key accepted

- **Location:** `dist/server/Mppx.js:28-30` (`Mppx.create`: `if (!secretKey) throw` — non-empty only); consumed at `dist/Challenge.js:451` (`Bytes.fromString(options.secretKey)`) with no length/entropy check.
- **Vulnerable behavior:** any non-empty string (`"key"`, `"a"`) is accepted as the HMAC-SHA256 key that binds challenge IDs. A weak key lets an attacker forge challenges.
- **Required fix (Rust #24):** enforce a strict **32-byte minimum** (`MIN_SECRET_KEY_BYTES = 32`, per NIST SP 800-107 for HMAC-SHA256). Validate in `Mppx.create` on both the explicit `secretKey` and the `MPP_SECRET_KEY` env path (one shared gate). Reject empty/short keys with a clear error; document `openssl rand -base64 32`.

## #15 (Low) — Default realm shared across servers

- **Location:** `dist/server/Mppx.js:287` (`const defaultRealm = 'MPP Payment'`), fallback in `resolveRealmFromRequest` (`:298-311`) when no Host header / explicit realm is present; realm participates in the cross-route binding (`:167`) and the HMAC ID.
- **Vulnerable behavior:** two services sharing one `MPP_SECRET_KEY` and both keeping the default realm share one credential namespace — a credential paid against service A passes HMAC verification on service B. The Host-header default partially mitigates, but the explicit fallback is a fixed shared string.
- **Required fix (Rust #15):** derive the default realm from a per-app identity (Rust uses the recipient pubkey: SHA-256 → `App Id - #<digits>`) so two services with the same secret automatically get distinct realms. Reject explicit `realm: ''`; keep explicit non-empty realms verbatim.

## #9 (Low) — WWW-Authenticate parser missing size cap

- **Location:** `dist/Challenge.js` `deserialize`/`deserializeList` base64-decode + JSON-parse the embedded `request` parameter with no length guard.
- **Vulnerable behavior:** an oversized `WWW-Authenticate` header drives proportionally larger decode + parse work than the credential/receipt parsers allow — a client-side DoS surface.
- **Required fix (Rust #9):** cap the `request` parameter at `MAX_TOKEN_LEN = 16 KiB` before base64-decode/JSON-parse, matching the credential/receipt parsers.
