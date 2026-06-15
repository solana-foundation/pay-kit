# `mpp/charge/push`

**Push mode**: client builds, signs, **and broadcasts** the transaction
itself; the server only verifies the on-chain signature. The credential
payload carries a Solana signature instead of a serialized transaction.
This is the default in browser flows (payment links) where the client
wallet does the broadcasting.

Spec: <https://paymentauth.org>, charge intent.
Rust reference: `rust/crates/mpp/src/server/charge.rs::verify_push`,
`rust/crates/mpp/src/protocol/solana.rs::CredentialPayload`.

## Wire format

### Challenge — identical to pull

Same `WWW-Authenticate` header shape as `mpp-charge-pull.md`. The server
does **not** advertise pull-vs-push directly; the client picks based on
whether `methodDetails.feePayer` is set and whether it wants to broadcast
itself.

### Credential — payload variant

```json
{ "signature": "<base58>" }
```

The credential payload is a `CredentialPayload::Signature { signature }`
(see `rust/crates/mpp/src/protocol/solana.rs::CredentialPayload`), tagged via serde
internally tag/untag rules.

## Server obligations

Mirror `verify_push` (search `rust/crates/mpp/src/server/charge.rs` for the function;
the entry is `match payload { CredentialPayload::Signature { ref
signature } => self.verify_push(...) }` at `rust/crates/mpp/src/server/charge.rs:541`):

1. **HMAC tier-1** + **expiry** + **pinned-field tier-2** + **cross-route
   tier-2** — same as pull (see `mpp-charge-pull.md`).
2. **Decode signature.** Base58 → 64-byte `Signature`.
3. **Fetch the transaction.** `rpc.get_transaction(signature,
   UiTransactionEncoding::Base64)` — note: confirmed transactions on
   mainnet may not be immediately available. Poll with backoff,
   ceilinged at a reasonable timeout (the Rust code uses ~3 attempts
   matching `SIMULATION_MAX_ATTEMPTS` / `SIMULATION_RETRY_DELAY_MS`).
4. **Decode and verify the on-chain transaction.** Run the same
   instruction-set verifier as pull mode:
   - Whitelist instructions (System transfer, SPL transfer,
     associated-token-account-create, Memo, ComputeBudget).
   - Compute-budget caps.
   - Primary transfer + splits sum to `amount`.
   - Recipient ATAs derive correctly.
   - Mint matches `currency`.
5. **Replay store check-and-consume.**
   `store.put_if_absent("solana-charge:consumed:<sig>", true)`. Returns
   `false` → `SignatureConsumed`. The replay key is the same as pull
   mode so a single signature cannot be used twice in either direction.
6. **Network match.** The signature was settled on whichever network
   the client used; the server must verify the transaction's
   `recent_blockhash` (or block context) matches its configured network.
   In practice this falls out of using the server's RPC endpoint to
   look up the signature — if it isn't on the configured network, the
   lookup fails.
7. **Receipt.** Same as pull mode — `Receipt::success(method="solana",
   reference=signature, challengeId=challenge.id)`.

## Client obligations

The push client builds the transaction the same way as pull, then
signs and broadcasts:

1. Parse `WWW-Authenticate` (same as pull).
2. Build the transaction (same as pull) — but set the fee payer to the
   client's own pubkey, ignoring `methodDetails.feePayer`/`feePayerKey`
   advertisements if you do not want server-broadcast.
3. Sign locally; broadcast via `rpc.send_transaction`.
4. Wait for confirmation (`rpc.confirm_transaction` or
   `getSignatureStatuses` polling).
5. Encode the resulting signature as base58.
6. Build the credential payload: `{"signature": "<base58>"}`.
7. Send `Authorization: Payment id=..., payload=<b64u-json>, ...`.

For payment-link / browser flows, the wallet adapter does steps 3-4 and
hands the signature back. The MPP SDK's role is steps 1-2 and 5-7;
see the service worker pattern in
`rust/crates/mpp/src/server/html/service_worker.gen.js` and the example at
`rust/examples/payment_link_server.rs`.

## Things to pay attention to

- **Same replay key as pull.** A signature consumed in push mode must
  prevent re-use in pull mode and vice-versa. The replay key prefix is
  `solana-charge:consumed:` and the value is the base58 signature.
  Don't introduce a per-mode prefix.
- **Don't trust the credential's transaction.** In push mode there is
  no transaction in the credential; the client only hands you a
  signature. You **must** fetch the transaction from the RPC and
  verify its instruction set yourself — never assume "the client
  built it correctly".
- **`get_transaction` may return `Confirmed` or `Finalized`.** Use the
  server's `CommitmentConfig`; do not accept `Processed` for
  settlement. The Rust default is `Confirmed`.
- **Browser CORS for `payment-receipt` header.** The example at
  `rust/examples/payment_link_server.rs:50-58` exposes `payment-receipt`
  in the response. The corresponding service worker reads it back.
  Don't strip the header in middleware.
- **Service worker assets must be served from the same origin** as the
  protected route — see `html::SERVICE_WORKER_PARAM` and the
  `service-worker-allowed: /` header in
  `rust/examples/payment_link_server.rs:79-84`. The new-language server
  must expose the same `?<param>` query that returns the generated
  service-worker JS.
- **Signature length / encoding.** Solana signatures are 64 bytes; the
  base58 encoding length is 87-88 chars. Reject anything outside that
  range up-front.

## Test plan

Unit tests (mirror Rust's `verify_push`-adjacent tests):

- Signature parse — valid base58, invalid base58, wrong byte length.
- Transaction-fetch error paths: not found, RPC failure, finalization
  timeout.
- Same instruction-set whitelist tests as pull mode.
- Replay across modes — a signature consumed by pull cannot be reused
  by push and vice versa (same store key).

Harness scenarios: scaffold a `charge-basic-push` variant. The current
default scenario (`charge-basic`) exercises pull because the TS server
is fee-payer; once the new SDK enables push for the client adapter,
add an explicit push-mode variant to `harness/src/contracts.ts`.

E2E: the Playwright tests in `html/tests` exercise the push flow via a
browser wallet. The new-language server must run this suite (see
`test-payment-links-rust` job in `.github/workflows/ci.yml`) on
`localhost:3001` to claim push-mode support.
