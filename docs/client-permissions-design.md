# Client permissions for automatic payments

Status: Rust implementation in this change; TypeScript API proposed for parity.

## Summary

PayKit clients can answer HTTP 402 challenges automatically, but a protocol
challenge is untrusted input. The client must decide whether a payment is
allowed before it constructs a transaction or invokes a wallet.

The permission layer is protocol-neutral. MPP and x402 offers are normalized
to the same Solana payment candidate, filtered through one policy, and checked
again at the signing boundary. The policy controls:

- exact HTTP(S) origins;
- Solana cluster (`mainnet`, `devnet`, or `localnet`);
- default stablecoins and explicitly allowed SPL mints;
- a global per-payment cap; and
- caps that replace the global cap for one exact origin.

This library is Solana-only, so its public network names are the short cluster
names. In particular, callers configure `mainnet`, not a chain-qualified name.
The x402 adapter owns conversion from CAIP-2 identifiers.

## Goals

- Provide one fluent client API for both MPP charge and x402 exact payments.
- Refuse disallowed challenges before any signer call.
- Support a safe default while keeping an explicit unrestricted escape hatch.
- Allow a global cap and tighter or looser caps for a trusted origin.
- Consider all supported offers and fall back when the preferred offer is
  denied.
- Preserve the existing lower-level protocol clients.

## Non-goals

- Daily or lifetime budgets, which require durable concurrent accounting.
- Interactive approval callbacks.
- Recipient allowlists.
- x402 `upto` or `batch-settlement` in the first high-level client. Their
  stateful channel lifecycle remains available through the protocol APIs.
- Server-signed batch channels. Rust refuses those today; a permission option
  will be added only when the Rust client can enforce the complete lifecycle.

## Rust API

The Rust SDK exposes builders for both the HTTP client and permission policy:

```rust
use solana_pay_kit::client::{
    AssetPermission, ClientPermissions, ClientProtocol,
    OriginPermissionOverride, PayKitClient, SolanaNetwork,
};

let api_override = OriginPermissionOverride::builder("https://api.example.com")
    .max_amount_per_payment("$5.00".parse()?)
    .build()?;

let permissions = ClientPermissions::builder()
    .allow_origin("https://api.example.com")?
    .only_network(SolanaNetwork::Mainnet)
    .max_amount_per_payment("$1.00".parse()?)
    .override_origin(api_override)
    .allow_asset(AssetPermission::with_cap(
        SolanaNetwork::Mainnet,
        custom_mint,
        2_000_000,
    )?)
    .build()?;

let client = PayKitClient::builder()
    .signer(signer)
    .rpc_url("https://api.mainnet-beta.solana.com")
    .network(SolanaNetwork::Mainnet)
    .accept([ClientProtocol::Mpp, ClientProtocol::X402])
    .permissions(permissions)
    .build()?;

let response = client
    .get("https://api.example.com/report")
    .send()
    .await?;
```

`ClientPermissions::unrestricted()` is the explicit escape hatch for supported
high-level payment types. It permits any HTTP(S) origin, Solana cluster, mint,
and amount. It does not make unsupported channel schemes available.

### Defaults

When `.permissions(...)` is omitted, the client constructs a policy with:

| Rule | Default |
|---|---|
| Origins | Any HTTP(S) origin |
| Network | The client network; `mainnet` when omitted |
| Assets | Known PayKit stablecoins |
| Per-payment cap | USD 1.00 |
| Origin overrides | None |

The default keeps a general-purpose HTTP client useful while bounding automatic
payments. Production applications should usually pin their service origins.

### Global and origin caps

Caps resolve from most specific to least specific:

1. matching asset cap for the exact response origin;
2. stablecoin cap for the exact response origin;
3. matching global asset cap; and
4. global stablecoin cap.

An origin override may raise, lower, or remove the global stablecoin cap. It
does not grant access to that origin: the origin must independently pass the
allowlist. Origin values normalize to `scheme://host[:port]`, so paths do not
create separate trust domains.

USD caps apply only to known dollar-pegged assets with known decimals. A custom
mint is denied unless added with `AssetPermission` or the caller explicitly
uses `.allow_any_asset()`. Custom asset caps are atomic integer amounts.

## TypeScript API

TypeScript exposes the same concepts through immutable fluent builders:

```ts
import {
  AssetPermission,
  ClientPermissions,
  OriginPermissionOverride,
  PayKitClient,
  usd,
} from '@solana/pay-kit/client'

const permissions = ClientPermissions.builder()
  .allowOrigin('https://api.example.com')
  .onlyNetwork('mainnet')
  .maxAmountPerPayment(usd('1.00'))
  .allowAsset(AssetPermission.withCap('mainnet', customMint, 2_000_000n))
  .overrideOrigin(
    OriginPermissionOverride.builder('https://api.example.com')
      .maxAmountPerPayment(usd('5.00'))
      .build(),
  )
  .build()

const client = await PayKitClient.builder()
  .signer(signer)
  .rpcUrl('https://api.mainnet-beta.solana.com')
  .network('mainnet')
  .accept(['mpp', 'x402'])
  .permissions(permissions)
  .build()

const response = await client.fetch('https://api.example.com/report')
```

`.permissions(false)` mirrors Rust's `ClientPermissions::unrestricted()`.
`createPayKitClient({...})` remains available as the config-object factory.

## Python API

Python follows the same builder vocabulary and defaults:

```python
from solana_pay_kit.client import (
    ClientPermissions,
    OriginPermissionOverride,
    PayKitClient,
    usd,
)

permissions = (
    ClientPermissions.builder()
    .allow_origin("https://api.example.com")
    .only_network("mainnet")
    .max_amount_per_payment(usd("1"))
    .override_origin(
        OriginPermissionOverride.builder("https://api.example.com")
        .max_amount_per_payment(usd("5"))
        .build()
    )
    .build()
)

client = (
    PayKitClient.builder()
    .signer(signer)
    .rpc(rpc)
    .network("mainnet")
    .accept(("mpp", "x402"))
    .permissions(permissions)
    .build()
)
```

The public classes and methods carry docstrings and are included automatically
in the package's pydoc-markdown API reference. `.permissions(False)` is the
explicit unrestricted escape hatch.

## Architecture

Each adapter produces an internal candidate:

```text
PaymentCandidate
├── response origin    derived from the final 402 response URL
├── network            mainnet | devnet | localnet
├── mint               canonical Solana public key
└── amount             atomic integer
```

The origin never comes from a challenge body. Symbols such as `USDC` resolve to
the canonical mint before matching. Invalid networks, mints, and amounts are
not signable offers.

The request flow is:

```text
send request
  -> receive 402
  -> parse enabled MPP and x402 offers
  -> normalize each offer
  -> filter through ClientPermissions
  -> select the first permitted offer
  -> build and sign its transaction
  -> retry once against the final challenge URL
```

Evaluation enables deterministic fallback and aggregate rejection details and
occurs immediately before transaction construction. The authorized result also
carries the resolved atomic cap into the MPP transaction builder, retaining its
defense-in-depth amount and network checks.

Redirect handling fails closed unless the HTTP stack exposes the effective
request as a new transport request. Rust and TypeScript refuse a 402 reached
through an internally followed redirect because replaying the original request
could leak caller credentials or restore a POST that became GET after a 303.
Python's transport runs beneath httpx redirect handling, so it evaluates and
retries the effective request directly.

## Errors

If supported offers exist but all are denied, Rust returns
`ClientError::PermissionDenied`. It contains a rejection per candidate with a
stable `PermissionDeniedCode`:

- `OriginNotAllowed`
- `NetworkNotAllowed`
- `AssetNotAllowed`
- `AmountExceedsLimit`
- `InvalidChallengeTerms`

If the 402 has no MPP charge or x402 exact offer that this high-level client can
handle, it returns `ClientError::NoSupportedChallenge`.

## Security invariants

- Permission checks complete before transaction construction and signing.
- Internally followed redirects never trigger a guessed payment retry.
- The signer is never invoked when every offer is denied.
- An origin override never grants the origin itself.
- Exact origin matching includes scheme and port; there are no suffix or
  wildcard matches.
- Unknown assets never inherit a USD cap whose decimals are unknown.
- Amount parsing and cap comparisons use integers only.
- Protocol-specific checks remain mandatory. Asset permission does not bypass
  MPP Token-2022 safety checks or x402 transaction validation.
- The high-level client retries at most once.

## Test strategy

Rust tests cover policy defaults, strict USD parsing, exact-origin behavior,
cap precedence, unknown assets, network refusal, unrestricted mode, signer
non-invocation on denial, MPP and x402 paid retries, and fallback from a denied
MPP offer to a permitted x402 offer.

Rust and TypeScript tests cover the shared policy decisions and resolved atomic
caps. Python follows the same cases.
