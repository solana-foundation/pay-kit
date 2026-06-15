# Adversarial verification — Ruby / PHP / Lua MPP charge

Method: each first-pass claim was treated as guilty-until-cleared. I hunted for a
missing guard that would refute the EXPOSED verdict (or, for SAFE claims, an
echo-trust / bypass path that would refute SAFE). Default verdict = CONFIRMED
EXPOSED unless a concrete mitigation is cited.

Note on cited paths: the first-pass Ruby report cites `challenge_store.rb` and
`headers.rb` without the `protocol/core/` prefix; the real files live at
`ruby/lib/pay_kit/protocols/mpp/protocol/core/{challenge_store,headers,credential}.rb`.
Line numbers match.

---

## PHP

### PHP #19 — `createChallenge` signs an arbitrary request — CONFIRMED EXPOSED (low)
Refutation attempt: looked for any validation gate on the issuance path or for a
construction that pins currency/recipient at the server.

- `ChargeServer::__construct` (ChargeServer.php:34-42) takes optional
  `$pinnedCurrency` / `$pinnedRecipient`, but these only feed the **verify** path
  (ChargeServer.php:147-152). They do nothing at issuance.
- `createChallenge` (ChargeServer.php:47-59) HMAC-signs whatever `ChargeRequest`
  it is handed via `Challenge::withSecret`. No recipient-parses-as-pubkey,
  no currency/network/decimals/tokenProgram == server-config, no split
  validation.
- The only validation is inside `ChargeRequest::__construct`
  (ChargeRequest.php:28-31, 83-93): amount is a positive base-unit integer and
  currency is non-empty. Nothing else.
- The in-SDK caller (`Adapter::chargeRequestFor`, Adapter.php:147-188) builds a
  well-formed request, AND the Adapter constructs `ChargeServer` with **no**
  pinned currency/recipient (Adapter.php:201-205) — so even the verify-side
  backstop is inert for adapter-built servers. The public `createChallenge`
  remains an unvalidated signing oracle for direct callers.

No mitigation found → EXPOSED. Severity stays low (server-trusts-self; the harm
requires the operator to call the public API with a hostile request).

### PHP #28 — arbitrary Token-2022 mint defaults to legacy Token — RESOLVED: UNCLEAR → CONFIRMED EXPOSED (partial), embedded-tokenProgram mask confirmed
- Part 1 (known Token-2022 stablecoins) is SAFE: `TOKEN_2022_SYMBOLS = ['PYUSD','USDG','CASH']`
  (Mints.php:64) and `tokenProgramFor` (Mints.php:117-123) returns the 2022 program for them.
- Part 2 confirmed exposed: for an arbitrary mint address, `symbolFor` returns
  null (Mints.php:144-165 — a raw mint not in the table), so `tokenProgramFor`
  (Mints.php:120-122) falls back to legacy `TokenProgram::PROGRAM_ID`. There is
  **no on-chain mint-owner fetch** anywhere (no equivalent of Rust
  `resolve_server_token_program`).
- Mask is real and partial: the verifier prefers an embedded
  `methodDetails.tokenProgram` when present (SolanaChargeTransactionVerifier.php:198,
  `Json::optionalString(... , $defaultTokenProgram)`) — so a credential/challenge
  that carries the correct tokenProgram bypasses the wrong default. But the
  server's own default for an unknown Token-2022 mint (when tokenProgram is
  absent) is wrong, and ATA derivation at :198 would then be wrong.

Verdict: EXPOSED for the no-embedded-tokenProgram arbitrary-Token-2022-mint case.

### PHP #16 — feePayer=true without signer — RESOLVED: verify-side SAFE, issuance ungated but in-SDK untriggerable
- Verify side SAFE: `expectedFeePayer` (SolanaChargeTransactionVerifier.php:318-333)
  throws `feePayer=true requires feePayerKey` when `feePayer===true` and
  `feePayerKey` is missing/empty (lines 320-326), and also enforces tx fee-payer
  == feePayerKey (line 328). No way to settle the bad shape.
- Issuance ungated: `createChallenge` (ChargeServer.php:47-59) has no
  feePayer/key consistency check — a direct caller can sign a `feePayer=true`
  request with no key.
- In-SDK untriggerable: the Adapter only sets `feePayer=true` together with
  `feePayerKey = $sgn->pubkey()` and only when `$sgn !== null`
  (Adapter.php:176-179). So adapter-built challenges can't carry the bad shape.

Verdict: SAFE on the path that matters (verify rejects it; in-SDK issuance can't
produce it). The bare public-API issuance gap is the same class as #19 — record
as marginal, not a live exposure.

---

## Ruby

### Ruby #1 — externalId/description not compared — RESOLVED: UNCLEAR → low parity, NOT a live exposure
- `verify_expected` (challenge_store.rb:124-131) compares amount (125), currency
  (126), recipient (127), and `comparable_method_details` (128) which strips only
  `recentBlockhash` (143-144). So network/decimals/tokenProgram/feePayer/
  feePayerKey/**splits** ARE all compared (they live inside methodDetails).
  Top-level **externalId and description are NOT compared** — refutation of a
  "fully compared" reading confirmed.
- But the divergence cannot reach settlement: the verifier resolves
  `request = expected_request || ...` (verifier.rb:18-20) and the server ALWAYS
  passes `expected_request` (challenge_store.rb:92, `verify_authorization_header`
  requires it as a mandatory keyword). `verify_memos` (verifier.rb:185-187) then
  enforces the **expected** request's externalId as an on-chain memo. A credential
  echoing a different externalId still has to carry an on-chain memo matching the
  *expected* externalId, so it cannot divert anything. `description` has no
  on-chain effect.

Verdict: low-severity parity gap with Rust (add externalId/description to the
up-front compare for defense-in-depth), no drain. Deciding line: verifier.rb:20
+ verifier.rb:187 (expected request drives the memo check).

### Ruby #9 — WWW-Authenticate request param not size-capped — RESOLVED: real gap, NOT reached server-side
- `parse_www_authenticate` (headers.rb:55-58) base64url-decodes + JSON-parses the
  `request` param with no size cap — confirmed.
- The **server** verify path uses `Credential.from_authorization_header`
  (challenge_store.rb:70), which DOES cap at `MAX_TOKEN_LENGTH = 16*1024`
  (credential.rb:42). The server never calls `parse_www_authenticate`.
- `parse_www_authenticate` is only reachable via `parse_www_authenticate_all`
  (headers.rb:41-43). A repo grep finds no server/middleware/sinatra/decorator
  caller — it's a client/inbound helper for parsing a *received* challenge.

Verdict: parity gap, no server-side exposure. Deciding line: credential.rb:42
(server inbound path is capped) vs headers.rb:57-58 (uncapped client helper, not
on the server path).

### Ruby #2 / #22 — verify always bound to explicit expected_request — CONFIRMED SAFE
Refutation attempt: hunt for an echo-trust path where verify runs against the
credential's own decoded request instead of a server-supplied expected.
- `verify_authorization_header` (challenge_store.rb:69) takes `expected_request:`
  as a **required** keyword (no default). It runs `verify_expected(decoded,
  expected)` (line 89) AND passes `expected_request: expected_request` into the
  verifier (line 92).
- `Charge#charge` (server/charge.rb:54-67) is the only public entry; it always
  builds `request` from method config and `@handler.handle` (line 67) forwards it
  as the expected.
- The verifier's `request = expected_request || challenge.decode_request`
  (verifier.rb:20) has an echo fallback ONLY when `expected_request` is nil —
  unreachable from the server path, which always supplies it. No public
  `verify(credential, arbitrary_request)` divorced from a challenge.

Verdict: SAFE. Deciding line: challenge_store.rb:69,92 (expected_request is
mandatory and threaded into settlement).

---

## Lua

### Lua #16 — feePayer=true without signer not rejected at boot — CONFIRMED EXPOSED
Refutation attempt: look for a boot gate or a charge-time guard rejecting
feePayer-without-key.
- `M.new` (server/init.lua:56-90) validates recipient (60-62) and secret_key
  (63-66) only. It stores `fee_payer = bool_or_nil(config.fee_payer)` (line 79)
  and `fee_payer_key = config.fee_payer_key` (line 80) with **no** consistency
  check. No signer concept exists in `M.new`.
- `charge_with_options` (init.lua:135-140): `if options.fee_payer or self.fee_payer`
  sets `method_details.feePayer = true` (136), but `feePayerKey` is set only when
  `options.fee_payer_key or self.fee_payer_key` is truthy (137-139). So
  `fee_payer=true` + no key emits `feePayer:true` with no `feePayerKey` — a
  spec-violating challenge.
- Adapter caveat: `mpp/init.lua:134-137` sets `opts.fee_payer = true` only
  together with `opts.fee_payer_key`, so adapter-built servers are safe. The
  standalone `mpp.server.new` API (the audited surface) is unguarded.

Verdict: EXPOSED. Deciding line: server/init.lua:79 (no boot gate) +
server/init.lua:137 (key conditionally omitted).

### Lua #5 — push-mode posture — RESOLVED: UNCLEAR (push always on, no opt-in)
- `M.new_signature_verifier` (solana_verify.lua:566-572) routes any
  `payload.type ~= 'transaction'` to `verify_signature` unconditionally.
- `Handler:settle` (charge_handler.lua:282-287) dispatches `type == 'signature'`
  to `settle_push` with no `accept_push_mode` flag.
- The only push gate is B34 (push + feePayer=true rejected), confirmed elsewhere.
  There is no posture control to disable push, vs Rust's default-off.

Verdict: UNCLEAR / posture — push is always accepted; needs a human decision on
intended posture (add an `accept_push_mode` opt-in to match Rust). Not a hard
drain by itself. Deciding line: solana_verify.lua:566-572 (unconditional push
dispatch).

### Lua #3 — reserve-before-broadcast ordering — CONFIRMED (SAFE-with-residual-gap)
- `settle_pull` (charge_handler.lua): Stage 5 broadcast
  `self.rpc:send_raw_transaction` (line 236) → Stage 6 `consume_replay(self,
  signature)` (line 242) → Stage 7 `self:await_confirmation(signature)` (line
  246). The reserve sits BETWEEN broadcast and confirmation polling — the
  audited replay-ordering bug is closed.
- Residual gap confirmed: `await_confirmation` errors out on timeout and the
  signature stays consumed; there is no post-timeout `getSignatureStatus`
  recovery (Rust #3's extra mitigation). A tx that lands during polling locks the
  user out on retry (UX gap, not a replay hole).

Verdict: ordering confirmed present. Deciding line: charge_handler.lua:236,242,246.

---

## FINAL — per claim

- PHP #19: CONFIRMED EXPOSED (low) — `ChargeServer.php:47-59` (no issuance validation; pinned fields are verify-only, Adapter.php:201-205 leaves them unset)
- PHP #28: CONFIRMED EXPOSED (partial) — `Mints.php:120-122` (legacy fallback, no on-chain owner fetch); masked when embedded — `SolanaChargeTransactionVerifier.php:198`
- PHP #16: REFUTED(SAFE) — `SolanaChargeTransactionVerifier.php:324` (verify rejects); issuance untriggerable in-SDK — `Adapter.php:176-179`
- Ruby #1: REFUTED(low parity, not exposed) — gap at `challenge_store.rb:124-131`; neutralized by expected-driven memo at `verifier.rb:20,187`
- Ruby #9: REFUTED(SAFE server-side) — server path capped at `credential.rb:42`; uncapped helper `headers.rb:57-58` not reached server-side
- Ruby #2/#22: REFUTED(SAFE) — `challenge_store.rb:69,92` (expected_request mandatory and routed into settlement)
- Lua #16: CONFIRMED EXPOSED — `server/init.lua:79` + `:137` (no boot gate; feePayerKey conditionally omitted); adapter-safe via `mpp/init.lua:134-137`
- Lua #5: UNCLEAR(posture) — `solana_verify.lua:566-572` (push always accepted, no opt-in)
- Lua #3: CONFIRMED(ordering present, SAFE-with-residual-gap) — `charge_handler.lua:236,242,246`
