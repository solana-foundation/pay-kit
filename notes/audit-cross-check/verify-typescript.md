# Adversarial re-verification — TypeScript MPP/charge

Goal: actively refute the first-pass verdicts by hunting for a guard the first pass missed.
Default to CONFIRMED EXPOSED only if no mitigation found. Mark REFUTED(SAFE) if a guard exists.

## Version note (matters for the mppx-dep claims)
- `@solana/mpp` (packages/mpp) resolves mppx at `typescript/node_modules/mppx` = **v0.5.5** (peerDep `mppx: >=0.5.5`).
- The first-pass cited **v0.5.17** (only present under `examples/playground-api/node_modules/.pnpm/...`).
- I verified the binding logic in BOTH versions. The set of bound fields is identical, so the version
  drift does NOT change any verdict here. (0.5.5: `requestBindingFields = ['amount','currency','recipient','chainId','memo','splits']`
  at `node_modules/mppx/dist/server/Mppx.js:312-319`. 0.5.17: `coreBindingFields=['amount','currency','recipient']`
  + `methodBindingFields=['chainId','memo','splits']` at `.../mppx@0.5.17/.../Mppx.js:357-358` — same union.)
- mppx is an EXTERNAL npm dep, NOT built from this repo. Its compiled `dist/` is the runtime source of truth.

---

## #3 — replay state recorded only after confirmation (claimed EXPOSED). Tried to refute by finding reserve-before-broadcast.

VERDICT: **CONFIRMED EXPOSED**.

Pull-mode flow `packages/mpp/src/server/Charge.ts:691-700`:
```
691  const signature = await broadcastTransaction(rpcUrl, txToSend);
694  await waitForConfirmation(rpcUrl, signature);
697  await verifyOnChain(rpcUrl, signature, challenge, recipient);
700  await store.put(`solana-charge:consumed:${signature}`, true);
```
- No `store.put`/reservation between broadcast (691) and the consumed mark (700). The consumed mark only
  lands AFTER confirmation + verifyOnChain both succeed. Searched the whole file for `reserve`/`store.put`/
  `store.get` — only two `store.put` calls (pull :700, push :741) and one `store.get` (push :728). No
  pre-broadcast reservation call exists anywhere.
- `waitForConfirmation` (`:1225-1255`) polls `getSignatureStatuses` in a loop and on timeout just
  `throw new Error('Transaction confirmation timeout')` (`:1254`). NO post-timeout one-shot
  `getSignatureStatus` recovery to distinguish "landed but RPC lagging" from "never landed" (Rust's
  `interpret_post_timeout_status` fix has no TS equivalent).
- Consequence: a tx that lands during the timeout window is never recorded; the user paid but gets a 402.
  Retry re-broadcasts (double-charge risk) or fails. Both halves of the audit claim (no reservation + no
  post-timeout status recovery) hold.

Deciding lines: `Charge.ts:691-700` (no reservation) and `Charge.ts:1254` (bare timeout throw).

---

## #1 — partial expected-vs-request comparison (claimed EXPOSED). Tried to refute by finding a route-config pin on the unchecked fields.

VERDICT: **CONFIRMED EXPOSED**.

Two facts together pin this:
1. mppx binding pins ONLY amount/currency/recipient/splits (chainId/memo unused on Solana):
   `node_modules/mppx/dist/server/Mppx.js:312-319` (`requestBindingFields`) + `:181`
   (`getRequestBindingMismatch(challenge.request, credential.challenge.request)`). `getRequestBinding`
   (`:325-335`) only reads `amount,currency,recipient,chainId,memo,splits`. So `network`, `decimals`,
   `tokenProgram`, `feePayer`, `feePayerKey`, `externalId`, `description` are NEVER compared by the framework.
2. The in-repo `verify()` then reads those unchecked fields straight off the ECHOED credential, not route config:
   - `Charge.ts:180` `const challenge = cred.challenge.request;` (echoed credential request)
   - `Charge.ts:189` passes that echoed `challenge` into `verifyTransaction`, which calls
     `verifyChargeTransaction(clientTxBase64, challenge)` (`:673`).
   - `verifyChargeTransaction` reads `challenge.methodDetails.network` (`:316,325`), `.decimals` (`:333,344`),
     `.tokenProgram` (`:324`), `.feePayer`/`.feePayerKey` (`:363-377`), and `challenge.externalId` (`:305,349`)
     — ALL from the echoed credential.
   - Same on the on-chain re-verify path: `verifyInstructions` reads `challenge.methodDetails.{network,tokenProgram,
     feePayer,feePayerKey}` and `challenge.externalId` from the echoed credential (`:773,775,787-789,812`).
   The route-built `recipient` IS threaded through as a separate arg from route config (`:174`→`:189`→used),
   and currency/amount/splits are bound by mppx — but the rest are not.

Refutation attempt failed: there is NO `compare_expected_to_request`-style exhaustive comparison anywhere
(grep confirms no such helper in packages/mpp or pay-kit). A credential carrying e.g. a different
`tokenProgram`/`decimals`/`feePayerKey`/`network`/`externalId` than the route configured is not rejected by
binding and flows into on-chain verification. (recentBlockhash correctly not compared — per-challenge state.)

Deciding lines: `node_modules/mppx/dist/server/Mppx.js:312-319` (binding field set) + `Charge.ts:180` (verify
re-reads echoed methodDetails).

---

## #5 — push mode always-on, no accept_push_mode opt-in (claimed UNCLEAR). Resolve to EXPOSED or SAFE.

VERDICT: **EXPOSED (unclear → resolved as EXPOSED)**.

- No opt-in parameter exists. grep for `acceptPush|accept_push|pushMode|allowSignature|allowPush|
  enableSignature|signatureMode` across `packages/mpp/src` and `packages/pay-kit/src` → zero hits.
  `charge.Parameters` (`Charge.ts:1257-1319`) has no push/signature toggle.
- `verify()` dispatch (`Charge.ts:181-192`) unconditionally routes any `payloadType === 'signature'` payload
  to `verifySignature`. The ONLY gate is `payloadType === 'signature' && challenge.methodDetails.feePayer`
  → reject (`:184-186`, that's finding #40, not an opt-in).
- `verifySignature` (`:714-751`) → `verifyInstructions` matches the on-chain tx by recipient/amount/mint/splits
  shape only (`verifySplTransfer:846-872`, `verifySolTransfer:874+`) with NO binding of the supplied on-chain
  signature to the challenge id.
- Rust added an `accept_push_mode` off-by-default gate; TS has no equivalent. Push is always-on.

Deciding lines: `Charge.ts:181-192` (unconditional signature dispatch, only feePayer-combo gated).

---

## #2 — confirm there is NO verify_credential-style API trusting the echoed amount (claimed SAFE). Tried to find one.

VERDICT: **REFUTED (SAFE)** — confirmed safe; no echoed-amount-trusting API found.

- `amount` IS in the binding set (`Mppx.js:312-319`), and the route-built request's amount comes from the
  ROUTE config, not the credential:
  - mppx builds the comparison request from `merged = {...defaults, ...rest}` where `rest` is the per-call
    `options` passed to `mppx.charge(options)` (`Mppx.js:91-92`), then runs the `request` hook on `merged`
    (`:108-110`), then `getRequestBindingMismatch(challenge.request, credential.challenge.request)` (`:181`).
  - The Solana `request` hook returns `{...request, recipient, methodDetails}` (`Charge.ts:165-175`) — it
    spreads the route-supplied `request` (which carries `amount` from `merged`) and never echoes the credential's
    amount.
  - pay-kit supplies that amount from the gate's own price: `optionsFor(gate)` →
    `amount: totalAmount(gate).toString()` (`packages/pay-kit/src/adapters/mpp.ts:80-82`).
  So a $1 credential presented at a $100 route mismatches on `amount` and is rejected at `Mppx.js:181-192`.
- grep for `verifyCredential|verify_credential` exposed APIs → none. There is no public
  "verify(credential, arbitrary echoed request)" escape hatch; `verify()` only ever receives the
  framework-supplied credential and the route-built request, and HMAC is recomputed over `credential.challenge`
  (`Mppx.js:147`). No divergent-request / echoed-amount path is reachable.

Deciding lines: `node_modules/mppx/dist/server/Mppx.js:181` (amount-bound mismatch check) +
`packages/pay-kit/src/adapters/mpp.ts:80-82` (route-config amount, not echoed).
