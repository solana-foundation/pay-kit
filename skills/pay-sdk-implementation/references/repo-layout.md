# Repo layout

The new-language SDK lives as a sibling of the existing language
directories in `solana-foundation/pay-kit`:

```
mpp-sdk/
├── rust/        ← reference; mirror its module split
├── typescript/
├── go/
├── python/
├── lua/
├── <new-lang>/  ← what you are creating
├── harness/
│   └── <new-lang>-client/   ← interop adapter (see interop-harness.md)
├── .github/workflows/ci.yml ← add a job (see ci-quality-coverage.md)
└── justfile     ← add recipes (see "justfile recipes" below)
```

## Inside `<new-lang>/`

The Rust crate is the reference. Mirror its module split so file paths
in the intent leaves translate directly:

```
<new-lang>/
├── <manifest>                       ← language-native manifest (Cargo.toml,
│                                      pyproject.toml, package.json, composer.json…)
├── src/                             ← or `lib/`, `pkg/`, `<package>/` per idiom
│   ├── error.<ext>                  ← Error enum + Result alias
│   ├── expires.<ext>                ← RFC 3339 helpers (`expires::minutes(5)`)
│   ├── store.<ext>                  ← Store trait + MemoryStore (put_if_absent)
│   ├── protocol/
│   │   ├── core/
│   │   │   ├── challenge.<ext>      ← PaymentChallenge / Credential / Receipt
│   │   │   ├── headers.<ext>        ← parse/format WWW-Authenticate / Authorization / Payment-Receipt
│   │   │   └── types.<ext>          ← MethodName, IntentName, Base64UrlJson, ReceiptStatus
│   │   ├── intents/
│   │   │   ├── charge.<ext>         ← ChargeRequest (string amounts; methodDetails)
│   │   │   └── session.<ext>        ← SessionRequest, OpenPayload, VoucherData, Commit/Close/TopUp
│   │   └── solana.<ext>             ← programs::*, mints::*, resolve_stablecoin_mint
│   ├── server/
│   │   ├── charge.<ext>             ← Mpp handler: charge(), charge_with_options(), verify_credential[_with_expected]()
│   │   ├── session.<ext>            ← Session lifecycle handler
│   │   ├── html.<ext>               ← Payment-link page renderer
│   │   └── html/                    ← Generated payment-link assets (DO NOT EDIT BY HAND)
│   ├── client/
│   │   ├── charge.<ext>             ← build_charge_transaction, build_credential_header
│   │   ├── session.<ext>            ← Session client (open, voucher, commit, close)
│   │   ├── http_stream.<ext>        ← Optional: SSE / metered streaming helper
│   │   └── payment_channels.<ext>   ← Optional: payment-channels program client
│   └── bin/                         ← or `cmd/`, `scripts/` — interop adapters
│       ├── interop_client.<ext>
│       └── interop_server.<ext>
├── examples/
│   └── payment_link_server.<ext>    ← One protected endpoint on :3001-ish
└── tests/
    ├── charge_integration.<ext>     ← Surfpool-backed end-to-end
    └── ...                          ← Unit tests per module (or `src/.../*_test.<ext>` per idiom)
```

The Rust crate is the canonical reference for everything in `src/`:

- `rust/src/lib.rs` — public re-exports the new SDK must mirror.
- `rust/src/protocol/core/{challenge,headers,types}.rs` — wire format.
- `rust/src/protocol/intents/{charge,session}.rs` — intent request types.
- `rust/src/protocol/solana.rs` — program/mint constants.
- `rust/src/server/{mod,charge,session,html,axum}.rs` — server side.
- `rust/src/client/{mod,charge,session,...}.rs` — client side.
- `rust/src/store.rs` — replay store trait.
- `rust/src/bin/interop_{client,server}.rs` — interop adapter shape.
- `rust/examples/payment_link_server.rs` — minimal protected example.
- `rust/Cargo.toml` — manifest pattern (atomic Solana crate pinning).

## Public surface — re-exports

Every SDK exposes the same top-level identifiers (under the language's
naming convention) so consumers can switch SDKs by changing the import
prefix:

- **Protocol primitives:** `PaymentChallenge`, `PaymentCredential`,
  `Receipt`, `ChallengeEcho`, `MethodName`, `IntentName`,
  `Base64UrlJson`, `ReceiptStatus`, `compute_challenge_id`.
- **Headers:** `parse_authorization`, `format_authorization`,
  `parse_www_authenticate`, `parse_www_authenticate_all`,
  `format_www_authenticate`, `format_www_authenticate_many`,
  `parse_receipt`, `format_receipt`, `extract_payment_scheme`, plus
  the header-name constants (`WWW_AUTHENTICATE_HEADER`,
  `AUTHORIZATION_HEADER`, `PAYMENT_RECEIPT_HEADER`, `PAYMENT_SCHEME`).
- **Intent types:** `ChargeRequest`, `SessionRequest`, `OpenPayload`,
  `VoucherPayload`, `VoucherData`, `SignedVoucher`, `CommitPayload`,
  `CommitReceipt`, `CommitStatus`, `ClosePayload`, `TopUpPayload`,
  `MeteringDirective`, `MeteringUsage`, `MeteredEnvelope`,
  `SessionAction`, `SessionMode`, `SessionPullVoucherStrategy`,
  `SessionSplit`, `DEFAULT_SESSION_EXPIRES_AT`, `parse_units`.
- **Solana protocol:** `programs::*` constants, `mints::*` constants,
  `resolve_stablecoin_mint`, `default_token_program_for_currency`.
- **Server:** `Mpp` handler, `Config`, `ChargeOptions`,
  `check_network_blockhash`, `VerificationError`.
- **Store:** `Store` trait/interface, `MemoryStore`, `MemoryChannelStore`,
  `ChannelStore`, `Store`-error type.
- **Re-exports of vendor crates** consumers will need (the Rust crate
  re-exports `solana_keychain` and `solana_rpc_client`). The new SDK
  re-exports the equivalent — e.g. the Solana RPC client and the
  in-memory signer — so callers don't pin a second copy.

## `justfile` recipes

Add one section per language, matching the existing pattern in
`mpp-sdk/justfile`. The required recipes are:

```just
# ── <Language> ──

# Install <language> deps
<l>-install:
    cd <dir> && <install-cmd>

# Build <language> package
<l>-build:
    cd <dir> && <build-cmd>

# Test
<l>-test:
    cd <dir> && <test-cmd>

# Format
<l>-fmt:
    cd <dir> && <fmt-cmd>

# Lint
<l>-lint:
    cd <dir> && <lint-cmd>

# Coverage with ≥90% gate
<l>-test-cover:
    cd <dir> && <coverage-cmd-with-fail-under-90>
```

Then add the new `<l>-test` to the `test` target, `<l>-fmt` to the
`fmt` target, and the lint + coverage + format to `pre-commit`.

## Package manifest patterns

The reference manifests are intentionally minimal — no extra
dependencies the SDK does not actually use. Use these as templates:

- **Rust:** `rust/Cargo.toml` — note the `solana-*` crates are pinned
  to atomic crates only, never the umbrella `solana-sdk`. The
  `solana-keychain` dependency is pinned to a specific rev (matters
  for cross-language signer compatibility).
- **Python:** `python/pyproject.toml` — `solders + solana` for the
  Solana types and RPC client; `httpx` for the HTTP client.
- **Go:** `go/go.mod` (read it). Note no `github.com/solana-foundation/*`
  bindings — types are open-coded against the wire format.

If the target language has no canonical Solana SDK, open-code the
small set of constants you need from `protocol/solana.<ext>` and the
two or three transaction/instruction structures used in charge. Do
**not** pull in a heavy chain client just for one helper.
