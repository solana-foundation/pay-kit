# MPPX upstream findings (TypeScript)

These MPP/charge audit findings resolve in the **external `mppx` npm dependency**,
not in `@solana/mpp` (`typescript/packages/mpp/src`). The framework owns HMAC
issuance/verification, the challenge↔credential binding, expiry, realm handling,
and the WWW-Authenticate codec, so the fixes cannot land in this repo — they
belong in an upstream `mppx` report.

- Resolved mppx version: `typescript/node_modules/mppx` = **v0.5.5** (peerDep `mppx >= 0.5.5`).
- The compiled `dist/` is the runtime source of truth (mppx is not built from this repo).
- The 0.5.17 variant present under `examples/playground-api` binds the same field set; the
  version drift does not change any verdict (0.5.5 `requestBindingFields` =
  0.5.17 `coreBindingFields ∪ methodBindingFields`).
- "Required fix" columns are taken from the Rust `AUDIT-ASSESSMENT.md` "Action taken".

---

## #1 (Medium) — Partial expected-vs-request comparison

- **mppx file:line:** `node_modules/mppx/dist/server/Mppx.js:312-319` (`requestBindingFields`),
  `:320-335` (`getRequestBindingMismatch` / `getRequestBinding`), invoked at `:181`.
- **Vulnerable behavior:** the credential↔route binding compares only
  `['amount','currency','recipient','chainId','memo','splits']`. `chainId`/`memo`
  do not apply to Solana charge, so effectively only amount/currency/recipient/splits
  are pinned. `network`, `decimals`, `tokenProgram`, `feePayer`, `feePayerKey`,
  `externalId`, `description` are **never** compared. The in-repo `verify()` then
  reads those unchecked fields straight off the echoed credential
  (`packages/mpp/src/server/Charge.ts:180` `const challenge = cred.challenge.request`),
  so a credential carrying a different decimals/tokenProgram/feePayerKey/network/externalId
  than the route configured flows into on-chain settlement unchecked.
- **Required fix (Rust #1):** perform an exhaustive up-front comparison between the
  route-built request and the credential's decoded request, covering all
  payment-constraining fields — top level `amount,currency,recipient,external_id,description`
  and `methodDetails.{network,decimals,token_program,fee_payer,fee_payer_key,splits}`
  (splits element-wise, order-sensitive). Deliberately **exclude** `recentBlockhash`
  (per-challenge state). Add `network`/`decimals`/`tokenProgram`/`feePayer`/`feePayerKey`/
  `externalId`/`description` to `requestBindingFields` (or a separate exhaustive
  comparator) so divergence is rejected before settlement.

---

## #24 (Medium) — Weak secret key accepted

- **mppx file:line:** `node_modules/mppx/dist/server/Mppx.js:28-30` (`Mppx.create`:
  `if (!secretKey) throw` — non-empty check only); the key is consumed at
  `node_modules/mppx/dist/Challenge.js:451` (`Bytes.fromString(options.secretKey)`)
  with no length/entropy validation.
  - (pay-kit's env path `packages/pay-kit/src/config.ts:75-85` also only requires non-empty,
    but it ultimately feeds the same mppx `secretKey`; the gate belongs in mppx.)
- **Vulnerable behavior:** any non-empty string (`"key"`, `"a"`) is accepted as the
  HMAC-SHA256 key that binds challenge IDs. A weak key lets an attacker forge challenges.
- **Required fix (Rust #24):** enforce a strict minimum of **32 bytes**
  (`MIN_SECRET_KEY_BYTES = 32`, per NIST SP 800-107 for HMAC-SHA256). Validate in
  `Mppx.create` on both the explicit `secretKey` and the `MPP_SECRET_KEY` env path
  (same gate). Reject empty and short keys with a clear error; document
  `openssl rand -base64 32` as the way to generate one.

---

## #15 (Low) — Default realm shared across servers

- **mppx file:line:** `node_modules/mppx/dist/server/Mppx.js:287`
  (`const defaultRealm = 'MPP Payment'`), fallback used by `resolveRealmFromRequest`
  (`:298-311`) when no Host header / explicit realm is available; realm participates
  in the cross-route binding at `:167` and in the HMAC ID.
  - (pay-kit additionally defaults `realm` to the constant `'App'` at
    `packages/pay-kit/src/config.ts:155`, compounding the shared namespace.)
- **Vulnerable behavior:** two services sharing one `MPP_SECRET_KEY` and both keeping
  the default realm participate in one credential namespace — a credential paid against
  service A passes HMAC verification on service B. The Host-header default partially
  mitigates but the explicit fallback is a fixed shared string.
- **Required fix (Rust #15):** derive the default realm from a per-app identifier so two
  services with the same secret automatically get different realms. Rust derives it from
  the recipient pubkey (SHA-256, first 4 bytes → `App Id - #<digits>`), rejects an explicit
  empty realm, and keeps explicit non-empty realms verbatim. For mppx, derive the default
  from a stable application identity (recipient/origin) rather than a hardcoded constant,
  and reject `realm: ''`.

---

## #9 (Low) — WWW-Authenticate parser missing size cap

- **mppx file:line:** `node_modules/mppx/dist/Challenge.js` — `deserialize`/`deserializeList`
  base64-decode + JSON-parse the embedded `request` parameter with no `MAX_TOKEN_LEN`-style
  length guard (no size cap anywhere in `Challenge.js`/`Credential.js`).
- **Vulnerable behavior:** an oversized `WWW-Authenticate` header drives proportionally
  larger base64-decode + JSON-parse work than the credential/receipt parsers allow — a
  client-side DoS surface.
- **Required fix (Rust #9):** cap the decoded `request` parameter at `MAX_TOKEN_LEN = 16 KiB`
  before base64-decode/JSON-parse, matching the cap the credential/receipt parsers already
  enforce.
- **In-repo mitigation already applied:** `@solana/mpp` now caps the full challenge header at
  16 KiB at its own boundary in `packages/mpp/src/shared/challenge-guard.ts`
  (`MAX_CHALLENGE_HEADER_LEN`), mirroring the pre-existing empty-id guard. This is a
  defense-in-depth wrapper only; the authoritative fix is the per-`request`-param cap inside
  mppx's parser.

---

## Confirmed SAFE in mppx (no upstream change required)

- **#2 (verify trusts echoed amount):** `Mppx.js:181-192` binds `amount` from the
  route-built request (not echoed); no `verify(credential, arbitrary request)` escape
  hatch exists. SAFE.
- **#17 (method/intent/realm enforcement):** `Mppx.js:167` explicitly compares
  `method`/`intent`/`realm` after HMAC. SAFE.
- **#41 (non-constant-time HMAC id comparison):** `Challenge.js:429-430` →
  `internal/constantTimeEqual.js` SHA-256s both inputs and XOR-accumulates — constant time. SAFE.
- **#16 (feePayer=true without signer):** handled in-repo; the challenge only sets
  `feePayer:true` together with a `feePayerKey` derived from a validated signer
  (`packages/mpp/src/server/Charge.ts`). SAFE.
