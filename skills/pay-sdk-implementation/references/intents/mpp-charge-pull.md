# `mpp/charge/pull`

**Pull mode**: client signs a transaction, server broadcasts it. Server is
the fee payer (or co-signs alongside the client's signature). The HTTP
shape is `WWW-Authenticate: Payment ...` (server) → `Authorization: Payment ...`
(client) → `Payment-Receipt: ...` (server).

Spec: <https://paymentauth.org>, charge intent.
Spec PR: <https://github.com/tempoxyz/mpp-specs/pull/188>.
Rust reference: `rust/crates/mpp/src/server/charge.rs`, `rust/crates/mpp/src/client/charge.rs`.

## Wire format

### Challenge (server → client) — `WWW-Authenticate` header

```
Payment realm="<realm>", id="<hmac>", method="solana", intent="charge",
        request="<base64url-canonical-json(ChargeRequest)>",
        expires="<RFC3339>", description="..."[, digest="..."][, opaque="<b64u>"]
```

- Multiple challenges in one response — comma-separated. Parse with
  `parse_www_authenticate_all` (handles quoted commas in values; see
  `rust/crates/mpp/src/protocol/core/headers.rs`).
- All param values **quoted**; the parser unquotes.

`ChargeRequest` (`rust/crates/mpp/src/protocol/intents/charge.rs`):

```json
{
  "amount": "1000000",            // base units, string
  "currency": "<USDC|mint|SOL>",  // symbol or base58 mint
  "recipient": "<base58>",        // optional in cred; required in challenge
  "description": "...",           // optional
  "externalId": "...",            // optional merchant ref
  "methodDetails": {              // Solana-specific
    "network": "mainnet-beta|devnet|localnet",
    "decimals": 6,
    "tokenProgram": "<base58>",    // for SPL transfers
    "feePayer": true,              // server pays fees
    "feePayerKey": "<base58>",
    "splits": [{ "recipient": "<base58>", "amount": "...", "memo": "...", "ataCreationRequired": true }],
    "recentBlockhash": "<base58>"  // pre-fetched by server
  }
}
```

### Credential (client → server) — `Authorization` header

```
Payment id="<echo>", request="<b64u-echo>",
        payload="<b64u-canonical-json({transaction: '<b64-std>'})>",
        ...[echoed challenge fields]
```

The `payload.transaction` value is **standard-alphabet base64 (with
padding)** of the bincode-serialized `Transaction` or `VersionedTransaction`.
Everything else moves through **base64url-no-pad** of canonical JSON.

### Receipt (server → client) — `Payment-Receipt` header

```
Payment status="success", method="solana", reference="<signature-base58>", challengeId="<id>"
```

## Server obligations

Implement these steps in `server::charge::verify` (mirror
`rust/crates/mpp/src/server/charge.rs:474-563`):

1. **HMAC tier-1.** Recompute the challenge ID with
   `compute_challenge_id(secret_key, realm, method, intent, request,
   expires, digest, opaque)` (`rust/crates/mpp/src/protocol/core/challenge.rs:192`)
   and compare. Constant-time compare.
2. **Expiry check.** Reject if `expires` is in the past. Reject if it
   fails to parse as RFC 3339 (fail-closed).
3. **Pinned-field tier-2.** Even if the credential's echoed request is
   "trusted as-is", pin `method`, `intent`, `realm`, `currency`,
   `recipient` to the server's configured values (see
   `verify_pinned_fields` at `rust/crates/mpp/src/server/charge.rs:424`). The
   realm pin is critical because HMAC uses the server's realm — a
   tampered echoed realm would otherwise pass HMAC.
4. **Cross-route tier-2 (recommended).** Expose
   `verify_credential_with_expected(credential, expected: ChargeRequest)`
   so route handlers can pin `amount`/`currency`/`recipient` per
   endpoint. The expected request — not the credential's echo — is
   then passed to settlement (see
   `rust/crates/mpp/src/server/charge.rs:412-418` and `examples/payment_link_server.rs:25`).
5. **Network blockhash gate.** Before broadcasting, call
   `check_network_blockhash(network, tx.message.recent_blockhash())`
   to reject mainnet keys pointed at a sandbox server (and vice versa).
6. **Pre-broadcast verifier.** Decode the transaction (accept legacy
   bincode `Transaction`, then fall back to `VersionedTransaction`);
   walk the instructions; verify:
   - Only system-transfer / SPL-transfer / SPL-create-ATA /
     ComputeBudget / Memo instructions.
   - Transfer amounts sum to `amount` (primary + splits).
   - Recipient ATAs derive from the expected recipient pubkey.
   - Mint matches `currency`.
   - Compute-budget limits ≤ `MAX_COMPUTE_UNIT_LIMIT` (200_000) and
     priority ≤ `MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS` (5_000_000).
7. **Co-sign (if fee payer).** Only after the pre-broadcast verifier
   passes. Use the keychain signer.
8. **Simulate then broadcast.** Up to `SIMULATION_MAX_ATTEMPTS` (3)
   with `SIMULATION_RETRY_DELAY_MS` (400) between.
9. **Replay store check-and-consume.** `store.put_if_absent("solana-charge:consumed:<sig>", true)`.
   On `false`, return `SignatureConsumed`. The check happens **after**
   on-chain settlement so a failed broadcast doesn't burn the signature.
10. **Receipt.** Return `Receipt::success(method="solana",
    reference=signature, challengeId=challenge.id)`.

## Client obligations

Mirror `rust/crates/mpp/src/client/charge.rs::build_charge_transaction` and the
adapter at `rust/crates/mpp/src/bin/harness_client.rs`:

1. Parse all `WWW-Authenticate` values; pick the `solana`/`charge`
   challenge (filter by `method.as_str() == "solana"`,
   `intent.as_str() == "charge"`). Multiple challenges may appear; pick
   the first compatible one.
2. Decode `request` (base64url → JSON → `ChargeRequest`).
3. Build the transaction:
   - Compute-budget instructions (limit + price).
   - One primary `Transfer` (system-program for SOL, SPL-token for
     mint).
   - One `Transfer` per split, in order. If
     `split.ataCreationRequired`, prepend the
     `AssociatedTokenAccount::create_idempotent` instruction.
   - Memo program instruction with the `externalId` if provided.
   - Use `methodDetails.recentBlockhash` if present (saves an RPC
     round-trip); otherwise `rpc.get_latest_blockhash()`.
   - If `methodDetails.feePayer === true && feePayerKey`, set the
     fee payer to that key; otherwise the signer is the fee payer.
4. Sign with the client signer.
5. Build the credential payload:
   `{"transaction": base64_std(bincode(tx))}`.
6. Build the `Authorization` header with `format_authorization(credential)`.
7. Re-issue the GET with the header.

## Things to pay attention to

- **Canonical JSON, not just `JSON.stringify`.** All base64url-encoded
  JSON uses RFC 8785 canonicalization (`serde_json_canonicalizer` in
  Rust). Otherwise the HMAC ID will not match what the server computes
  on verification.
- **base64url-no-pad for headers; base64-std for transactions.** Mixing
  them is the #1 cross-language bug. `parse_authorization` accepts
  both alphabets for the payload but the canonical write path emits
  no-pad URL-safe for header fields and std-with-pad for the
  transaction body. See `rust/crates/mpp/src/protocol/core/types.rs:177-198`.
- **`MethodName` and `IntentName` are normalized lowercase ASCII.** The
  parser rejects mixed case in `method` (see
  `rust/crates/mpp/src/protocol/core/headers.rs:42-46`). The `IntentName::new` ctor
  forces lowercase. Mirror this in your types.
- **`ChargeRequest.decimals` is `serde(skip)`.** It is not part of the
  wire format; it lives in `methodDetails.decimals` instead. Mark the
  equivalent field non-serialized in your type — see
  `rust/crates/mpp/src/protocol/intents/charge.rs:22-24`.
- **`amount` is a string in base units.** Do not parse to a number on
  the wire — JS can't safely round-trip u64. Use `parse_units(amount,
  decimals)` to convert from a decimal display string at the SDK
  boundary (`rust/crates/mpp/src/protocol/intents/mod.rs:18`).
- **Splits cap at 8.** `rust/crates/mpp/src/client/charge.rs:76` enforces this; the
  server's pre-broadcast verifier enforces it too. Reject earlier in
  the new SDK.
- **`recentBlockhash` in `methodDetails`** is **base58**, not base64.
  Same for `tokenProgram`, `feePayerKey`, and split `recipient`.
- **Pre-broadcast verification is BEFORE co-signing.** Co-signing a
  hostile transaction (and then catching it post-hoc) leaks the fee
  payer key's signature; the order in `verify_pull`
  (`rust/crates/mpp/src/server/charge.rs:596-599`) is verify → cosign → simulate
  → broadcast.
- **Network gate first.** Calling `check_network_blockhash` before
  decoding instructions is cheaper than letting broadcast fail with a
  generic blockhash error.

## Test plan

Unit tests to mirror (from `rust/crates/mpp/src/protocol/core/types.rs`,
`rust/crates/mpp/src/protocol/intents/charge.rs`, and
`rust/crates/mpp/src/server/charge.rs` `#[cfg(test)] mod tests`):

- `MethodName` normalizes to lowercase, rejects empty / non-ASCII.
- `IntentName::is_charge` is case-insensitive.
- `base64url` round-trip; accepts standard alphabet with padding.
- `parse_units("1.5", 6) == "1500000"`; too-many-decimals errors;
  leading zeros.
- `ChargeRequest` serde — `externalId`, `methodDetails`, omits None
  fields, `decimals` skipped.
- `validate_max_amount` boundary cases.
- HMAC determinism: same inputs → same id; one bit flip → different id.
- Pinned-field verifier: realm mismatch, method mismatch, currency
  mismatch, recipient mismatch all reject.
- Cross-route replay: credential issued for cheap route rejected on
  protected route (this is the scenario the harness exercises).

Integration test:

- Surfpool-backed `tests/charge_integration.<ext>` mirroring
  `rust/tests/charge_integration.rs`. Cover SOL transfer, SPL transfer,
  splits with ATA creation, fee-payer mode.

Harness scenario: `charge-basic` and `charge-split-ata` in
`harness/src/contracts.ts`. Both must pass against the Rust
server before the new SDK is enabled by default.
