# Conformance vectors

Deterministic, offline cross-SDK parity layer. Each vector is one case every
SDK's conformance testee must agree on. The driver, `pkc run`
(`rust/crates/conformance/src/run/`), keeps one testee process per SDK
(testee ABI v2, `harness/README.md#testee-abi`), serves each vector's chain
state from a fixture RPC, judges the result against the vector's `expect`
block and, for builds, with the Rust kit's verifier and its own build of the
same case, then reconciles against `harness/expectations/<sdk>.toml`.

```sh
cd rust
cargo run -q -p paykit-conformance --bin pkc -- run --sdk all --tier offline --require
```

It does NOT replace on-chain settlement tests: RPC simulation, real
Token-2022 extension behaviour, rent and confirmation stay in the surfpool
matrix.

## Where vectors come from

The `*.json` files here (except the vendored `mpp-protocol*/` directories)
are **filled**, not written: the case registry in
[`rust/crates/conformance`](../../rust/crates/conformance) (`pkc`) runs the
real Rust kit on every case and writes the result.

```sh
cd rust
cargo test -p paykit-conformance                         # one positive-control test per case
cargo run -p paykit-conformance --bin pkc -- fill         # rewrite harness/vectors/
cargo run -p paykit-conformance --bin pkc -- fill --check # CI: fail on any byte difference
cargo run -p paykit-conformance --bin pkc -- fill --list  # case ids and counts
cargo run -p paykit-conformance --bin pkc -- req-lint     # spec quotes and requirement drift
```

- **Deterministic.** Fixed keys (client seed `[7;32]`, x402 sponsor seed
  `[9;32]`), blockhash `111…1`, fixed clocks, no randomness. `--seed N --out
  DIR` writes a variant corpus (different memo nonces and mutation
  magnitudes, same verdicts) and never touches the committed tree.
- **Drift-checked.** `FILL.sha256` records the SHA-256 of every filled file.
  `fill --check` regenerates in memory, compares every byte (vectors,
  annotated views, manifest), and refuses to run on a dirty
  `harness/vectors/`, so a local edit cannot mask drift.
- **Annotated.** `annotated/<id>.txt` shows each vector's transaction as
  instructions with program names, named accounts and decoded data (System
  transfer, SPL Token / Token-2022 `TransferChecked`, ATA `CreateIdempotent`,
  Memo, ComputeBudget limit/price), x402 headers as decoded JSON, and
  canonical bytes split by offset and field. Build vectors show the Rust
  kit's reference build. Review these when a vector changes.

### Provenance

Every vector says where its expected value comes from:

- `"provenance": "generated"`: computed by the Rust kit (wire bytes, decoded
  transaction shape, reject code). The registry declares the verdict and
  which fields to pin; the kit supplies the values. A case's test fails when
  the kit stops producing the declared verdict.
- `"provenance": "authored"`: taken from the spec text, because the kit
  disagrees with the spec or cannot express the case. The case records the
  kit divergence with a reason; its test asserts the divergence still
  exists, so a kit fix forces the entry to be removed.

Rust bugs are therefore never silently fossilised into a vector: a
disagreement is either an authored case with a named divergence or a failing
test.

### Traceability fields

On top of the runner ABI each vector carries (the driver strips these, and
`expect`, before a testee sees the vector):

| Field | Meaning |
| --- | --- |
| `spec` | **Required.** `{ doc, section, quote }`: `doc` is `mpp-specs/specs/...` (submodule `external/mpp-specs`) or `x402/specs/...` (submodule `typescript/external/x402`); `quote` is verbatim (whitespace and markdown emphasis normalised). `load.ts` rejects a vector without it; `pkc req-lint` fails when the quote is not in the pinned text. |
| `requirements` | Ids of the normative sentences the case covers, from `harness/requirements/{mpp,x402}.toml`. |
| `bugType` | `replay`, `auth-bypass`, `settlement`, `wire`, `defaults`, `malleability`, `precedence`. |
| `tier` | Minimum tier: `offline`, `interop`, `onchain`. All current vectors are `offline`. |
| `role` | `client`, `server` or `both`. |
| `provenance` | `generated` or `authored` (above). |

### Adding a case

1. Find the normative sentence: `pkc req-lint --list mpp` (or `x402`) prints
   every extracted MUST / MUST NOT / SHALL / REQUIRED sentence with its id.
   Add the entry (id, doc, text) to `harness/requirements/<repo>.toml` if it
   is not mapped yet.
2. Add the case to `rust/crates/conformance/src/cases/<suite>.rs` inside the
   `registry!` block. The macro generates the case's test from the same
   entry, so a case cannot exist without its test.
   - A reject case is usually a valid input plus a mutation operator
     (`mutate.rs`); its reject code comes from the operator table, per suite.
   - Pair each reject case with an accept case that differs only in the field
     under test.
   - Verify vectors always pin a real transaction (`Input::ChargeTransaction`,
     `Input::X402Header`), so server-only SDKs verify the same bytes.
3. `cargo test -p paykit-conformance`, then `pkc fill`, then `pkc req-lint`.
4. Run every SDK against the new vector: `pkc run --sdk all --tier offline
   --discover` (see `CONTRIBUTING.md`), then `pkc case show <id>` to review
   it.

## Runner ABI

Types live in `harness/src/conformance/schema.ts`; `pkc` validates every
result at the process boundary (`rust/crates/conformance/src/run/result.rs`,
no unknown keys). Testees speak ABI v2 (`serve`, one process, newline JSON
`{id, op, input}` -> `{id, ok, result}`); the one-shot form below is the v1
shim (`pkc run --legacy`) and the payload of both.

- input: one vector `{ id, intent, mode, description, input }` (no `expect`),
  with `input.rpcUrl` injected by the driver.
- result: one `RunnerResult` `{ id, outcome, transactionShape?,
  x402EnvelopeShape?, exactBytes?, error?, rejectCode?, transaction?,
  x402PaymentHeader? }`. An accepted charge build carries the built
  `transaction`, an accepted x402 build the built `x402PaymentHeader`; `pkc`
  runs the Rust verifier on it and compares its instruction multiset with the
  kit's own build.
- `outcome: "unsupported-mode"` declares that the SDK has no equivalent (for
  example a server-only SDK asked to build); whether that is allowed is
  decided by `harness/expectations/<language>.toml`.
- Runners pass `input.rpcUrl` to their SDK and never resolve chain state,
  fill defaults or apply field precedence themselves.

### Fixture RPC

`input.rpcFixtures` (`{ recentBlockhash?, mints?: { <mint>: { owner,
decimals } } }`) is served by `rust/crates/conformance/src/fixture_rpc.rs`,
the same fixture the filler runs the kit against:
`getLatestBlockhash`, `getAccountInfo` / `getMultipleAccounts` (mints in the
82-byte SPL layout), `getMinimumBalanceForRentExemption`, `getSlot`,
`getHealth`. Anything else is refused with an error naming the method. A
mint absent from `mints` does not exist. The blockhash defaults to the
charge request's `methodDetails.recentBlockhash`.

## Oracles

- Every accepted `charge` / `x402-exact` build: the Rust kit's verifier must
  accept it against the vector's request (or the offer's route), and its
  instruction multiset (program, set of accounts, data; signatures excluded,
  ordering free; an x402 hex memo nonce compares as a nonce) must equal the
  kit's own build. Then the shape checks below.
- `charge` build / verify: the decoded transaction shape
  (`transactionShape`). SPL transfers are expressed by `destinationOwner`
  (the driver derives the ATA); `maxComputeUnitLimit` and
  `maxComputeUnitPrice` are upper bounds; `forbiddenPrograms` must not
  appear.
- `x402-exact` build / verify: the decoded envelope (`x402EnvelopeShape`).
  v2 (`PAYMENT-SIGNATURE`): `{ x402Version: 2, accepted, payload }`, no
  top-level scheme/network. v1 (`X-PAYMENT`): `{ x402Version: 1, scheme,
  network: "solana" | "solana-devnet", payload }`, no `accepted`.
- `canonical-bytes`: exact bytes (`exactBytes.canonicalJson`, `base64Url`,
  `bytes`).
- `session` verify: outcome and reject code of the voucher verifier at the
  pinned clock.
- Rejects: `expect.rejectCode` from the shared vocabulary (`RejectCode` in
  `schema.ts`); `rejectReason` documents and is never asserted.
  `accepted-mismatch` is the code for a v2 x402 credential whose `accepted`
  disagrees with the route (amount, payTo, asset or network), whether the
  SDK checks fields one by one or matches `accepted` against its offers.

### Inputs by intent

- charge: `request` (decoded charge request), `signerSecretKey`,
  `rpcFixtures`, and for verify vectors the pinned `transaction` (the Rust
  kit's build, possibly mutated).
- x402 build: `x402Version` (1 | 2, default 2), `x402Offer`,
  `signerSecretKey`, `rpcFixtures`, and for extensions
  `x402AdvertisedExtensions` / `x402PaymentIdentifierId`.
- x402 verify: `x402PaymentHeader` (base64 JSON envelope whose
  `payload.transaction` is a partially signed §3.1 static-layout
  transaction: limit, price, `TransferChecked`, Memo; sponsor slot empty),
  the route (`x402ServerNetwork`, `x402ServerRecipient`,
  `x402ServerCurrency`, `x402ServerAmount`, optional `x402ServerMemo`), the
  sponsor (`x402ServerFeePayer`, `x402ServerFeePayerSecretKey`) and
  `x402ServerRequiresPaymentIdentifier`.
- session: `voucherPreimage`, `sessionWire { shape, value }`,
  `sessionVoucherVerify`, `signerSecretKey`.
- canonical bytes: `value` (JCS), `encodeBase64Url { hexBytes | utf8 }`,
  `challengeId`.

## Files

| File | Contents |
| --- | --- |
| `canonical-bytes.json`, `wire-bytes.json` | JCS, base64url, challenge-id HMAC, x402 envelope wire bytes |
| `charge-defaults.json` | client builds: decimals required, token program from the mint owner, SOL |
| `charge-rejects.json`, `charge-envelope.json` | verify: compute cap, fee payer as authority, decimals, splits, split ATA + memo |
| `charge-verify-mutations.json` | verify: wrong amount / recipient / mint, duplicate split legs and memos (SOL and SPL) |
| `session-*.json` | voucher preimage, session wire round trips, voucher expiry |
| `x402-build.json`, `x402-v1-build.json`, `x402-extensions.json` | x402 client envelopes, v1 and v2, extension echo |
| `x402-verify.json`, `x402-v1-verify.json` | x402 server verify, versions and networks |
| `x402-verify-mutations.json` | x402 verify: zero / two transfers, underpayment, overpayment, fee payer isolation, memo, cross-route `accepted` lies |
| `mpp-protocol/`, `mpp-protocol-flows/` | vendored mpp-tools vectors (external owner, not filled) |
