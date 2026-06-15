# MPP/charge audit — cross-language exposure checklist

Source of truth: `rust/AUDIT-ASSESSMENT.md` (45 findings from the 2026-05-26 Solana MPP audit, assessed against the Rust impl). This checklist condenses each finding so other-language implementations can be checked for the *same* vulnerability. For each finding, determine for the target language:

- **EXPOSED** — the same vulnerable shape exists in this language's code (cite file:line + the vulnerable expression).
- **SAFE** — the code already does the right thing (cite the guard).
- **N/A** — this language does not implement the affected surface (e.g. client-only impl, no server verify).
- **UNCLEAR** — needs human review; explain what's ambiguous.

Always cite `path:line` evidence. Do not assume parity with Rust — read the actual code.

## SERVER-SIDE (challenge issuance + verification)

- **#2 — verify trusts echoed request for amount.** Is there a `verify_credential`-style API that decodes the amount/economics from the *credential's own echoed challenge* and verifies against that, instead of an explicit expected request? A server with >1 priced route would accept a $1 credential on a $100 route. SAFE = caller must pass an explicit expected ChargeRequest / the amount is pinned against server config.
- **#1 — partial expected-vs-request comparison.** When comparing the credential's decoded request to the expected request, are ALL payment-constraining fields compared (amount, currency, recipient, externalId, description, network, decimals, tokenProgram, feePayer, feePayerKey, splits element-wise) — or only amount/currency/recipient? recentBlockhash must NOT be compared.
- **#22 — low-level verify request not bound to challenge.** Does the lowest-level `verify(credential, request)` confirm `request == credential.challenge.request` (HMAC authenticates the challenge, settlement uses caller request — they can diverge)?
- **#19 — full ChargeRequest signed without validation at issuance.** When the server HMAC-signs a caller-supplied ChargeRequest, does it validate amount parses, currency/network/decimals/tokenProgram match server config, recipient + splits parse?
- **#17 — method/intent enforcement.** Server: after HMAC, does it explicitly require `method == "solana"` && `intent == "charge"`? Client: does the credential-header builder reject non-solana/non-charge challenges before signing?
- **#32 — find_sol_transfer missing checks.** Parsed System-transfer matching: does it verify `programId == System Program` AND reject `source == fee_payer` (fee-sponsored: server must not bankroll the value transfer)?
- **#29 — find_spl_transfer ignores source ATA.** Parsed transferChecked matching: does it reject `authority == fee_payer` AND `source == fee_payer's ATA`?
- **#25 — compute-unit price inflation in fee-sponsored pull mode.** Is there a *tight* compute-unit-price cap when the server is fee payer (vs the general higher cap when client pays its own gas)?
- **#24 — weak secret key accepted.** Is the HMAC secret key (config + env var paths) length-validated (>= 32 bytes)? Empty / "key" must be rejected.
- **#15 — default realm shared across servers.** Is there a hardcoded default realm (e.g. "MPP Payment") shared by all servers using the same secret? SAFE = realm derived per-recipient / required non-empty.
- **#37 — network allowlist / mainnet default.** Are network slugs allowlisted to {mainnet,devnet,localnet} at boot? Does anything silently treat unknown slugs (e.g. "mainnet-beta","testnet") as mainnet?
- **#16 — feePayer=true with no signer.** Is `feePayer=true && fee_payer_signer==None` rejected at config boot AND per-call override?
- **#5 — push-mode credential not bound to challenge.** Push mode matches on-chain tx by shape only; is push mode opt-in/off-by-default, and is the §13.5 trade-off acknowledged? (Spec-accepted; check posture.)
- **#40 — push + fee-sponsored.** Is a push (Signature) credential rejected when `feePayer == true`?
- **#38 — primary recipient in splits + ataCreationRequired.** Is the combination `split.recipient == top-level recipient && split.ataCreationRequired == true` rejected at issuance (fee-sponsored ATA recreate drain)?
- **#21 — incomplete split validation at issuance.** At challenge creation, are splits validated: count <= MAX_SPLITS(8), recipient parses, amount parses & > 0, no overflow on sum, no duplicate recipients — for ALL splits (not only when one has ataCreationRequired)?
- **#28 — token program resolution.** Does the server resolve the token program correctly for Token-2022 stablecoins (PYUSD, USDG, CASH) instead of defaulting to legacy Token? For arbitrary mints, does it fetch the mint owner on-chain rather than guessing?
- **#13 — hardcoded token program in balance diagnostics.** Does any diagnostic derive the payer ATA with a hardcoded legacy Token program (wrong for Token-2022)?
- **#8 — balance-diagnostics decimal overflow.** `10^decimals` divisor with unbounded decimals — checked/None-on-overflow?
- **#3 — replay state recorded after broadcast.** Is the signature reserved in the replay store *between* broadcast and confirmation (not only after)? Is there a definitive post-timeout status check so a landed tx during polling timeout isn't lost?
- **#41 — non-constant-time HMAC id comparison.** Is the challenge-id == recomputed-HMAC comparison constant-time?
- **#11 — error title alignment.** (Cosmetic.)

## CLIENT-SIDE (transaction building + signing)

- **#10 — client signs untrusted challenges.** For auto-pay flows, does the builder offer guards (max amount cap, expected network) and ALWAYS refuse expired challenges before signing?
- **#20 — implicit client-funded split ATA creation.** Does the client auto-create split ATAs regardless of `ataCreationRequired` (silent rent drain), or only when the flag is set?
- **#26 — client signs arbitrary mint-address currencies (Token-2022 transfer-hook risk).** Does the client refuse to sign unknown Token-2022 mints (which can carry transfer hooks) unless explicitly opted in? Vanilla Token mints are fine.
- **#33 — min remaining SOL balance for signers.** (Rust REJECTED — stablecoin-only product, SOL transfer path not user-facing. Note posture; only flag if a language exposes SOL transfer as a user path.)
- **#42 — decimals defaulting.** Client SPL path: does it `unwrap_or(6)` decimals (silent wrong divisor for non-6-decimal mints) or require decimals to be present?
- **#36 — blockhash commitment.** Client fetches blockhash with `confirmed` commitment (not `processed`)?

## CORE / PARSING (shared utilities)

- **#39 — parse_units integer overflow.** `10^decimals * value` — bounded decimals (MAX_DECIMALS) + checked arithmetic?
- **#30 — split-amount sum overflow.** Summing split amounts with checked_add (not wrapping/panicking `.sum()`)?
- **#9 — WWW-Authenticate parser missing size cap.** Is the base64url `request` parameter length-capped (e.g. 16 KiB) before decode+JSON-parse, consistent with credential/receipt parsers?
- **#44/#45 — parse_units edge cases.** Does it reject `".5"`, `"5."`, `"."`, `"1.2.3"` (multi-dot silently concatenating), and non-ASCII-digit chars?
- **#34 — ataCreationRequired mint-address check.** (Clarity: direct pubkey-parse check on currency.)
- **#27/#14 — docstrings/precedence.** (Cosmetic/doc.)

## OUTPUT FORMAT (write to notes/audit-cross-check/<lang>.md)

A markdown table: `| Finding | Verdict | Evidence (path:line) | Notes |` covering every finding above, followed by a short "Top exposures" summary listing only EXPOSED + UNCLEAR items ranked by severity.
