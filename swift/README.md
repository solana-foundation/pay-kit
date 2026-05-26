<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# SolanaPayKit

Consume stablecoin-gated HTTP endpoints (USDC, USDT, PYUSD, ...) from
Swift. Implements the client side of the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

This library is **client-only**. It parses MPP `402 Payment Required`
challenges, derives the Solana transaction on the client, signs it with
the user's Ed25519 key, and replays the request with an
`Authorization: Payment ...` header. Server support lives in the
TypeScript, Rust, Go, PHP, Ruby, Lua, and Python packages.

**MPP** is [an open protocol proposal](https://paymentauth.org) that
lets any HTTP API accept payments using the `402 Payment Required` flow.
You do not need to know anything about Solana to use this library: pick
a currency, give it your wallet address, and pay a protected route in
two lines.

[![Swift](https://img.shields.io/badge/Swift-6.0%2B-blue)]()
[![Platforms](https://img.shields.io/badge/platforms-iOS%2016%20%7C%20macOS%2013-lightgrey)]()

## Quick start

Drive an MPP-gated endpoint with the URLSession-backed `MppHTTPClient`:

```swift
import SolanaMpp

let signer = try MemorySigner(secretKey: secretKeyData) // 32-byte seed or 64-byte Solana keypair
let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
let client = MppHTTPClient(signer: signer, rpc: rpc)

let response = try await client.fetch(url: URL(string: "https://api.example.com/paid")!)
print(response.status)              // 200 after MPP retry
print(response.settlementSignature) // base58 on-chain signature
```

`MppHTTPClient` sends the request, on a 402 response it parses the
`WWW-Authenticate: Payment ...` challenge, builds the credential through
the supplied `SolanaSigner`, and replays the same request once with the
`Authorization: Payment ...` header attached. Any non-402 status
(success, other 4xx, 5xx) is returned verbatim. Transport errors
propagate.

Lower-level entry points are also exposed:

```swift
let challenge = try MppHeaders.parseWWWAuthenticate(wwwAuthenticateHeader)
let auth = try await Charge.buildPullCredential(
    challenge: challenge,
    signer: signer,
    rpc: rpc
)
// Attach `auth` as Authorization: Payment ... in your own HTTP stack.
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"` (the SDK looks up the mint, token program, and decimals from
a built-in table), or a raw base58 mint pubkey.

## Install

Add the package to your Swift Package Manager dependencies:

```swift
.package(path: "../mpp-sdk/swift")
```

Then add `SolanaPayKit` to your target dependencies.

## Protocol compatibility matrix

This library is client-only. Server support lives in the TypeScript,
Rust, Go, PHP, Ruby, Lua, and Python packages.

### MPP

| Intent | Client |
|---|:---:|
| `mpp/charge/pull` | pass |
| `mpp/charge/push` | planned |
| `mpp/session` | planned |
| `mpp/subscription` | planned |

### x402

| Intent | Client |
|---|:---:|
| `x402/exact` | planned |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |

## Examples

The `Examples/` directory hosts sample clients (a Solana Seeker demo
app is planned). For an end-to-end exercise, run the interop adapter at
[`harness/swift-client/`](../harness/swift-client) against any
registered server.

### Drive a TypeScript server

```bash
cd harness
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=typescript pnpm exec vitest run
```

## Solana dependencies

The SDK keeps Solana dependencies intentionally small. Pure Swift, no
external dependency beyond Foundation and Apple CryptoKit.

| Dependency | Why | Version |
|---|---|---|
| `Foundation` | URLSession, JSON, Data | system |
| `CryptoKit` | Ed25519 signing / verification, SHA-256 | system |

There is no `solana-swift` umbrella dependency. Base58, the transaction
codec, PDA derivation, the on-curve check, and the minimal JSON-RPC
client are vendored in-tree for byte-for-byte parity with the Rust spine.
Parity is locked by golden vectors in `Tests/SolanaPayKitTests`.

## Coding convention

This SDK follows the
[Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/):
clarity at point of use, role-based parameter labels, structured
concurrency (`Sendable`-only public surface), throws over precondition
on caller-controlled input, and value types for wire-format models.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, Swift idioms second.

## Tests and coverage

```bash
cd swift
swift test --enable-code-coverage
```

Coverage artifacts live in `swift/.build/debug/codecov/`. CI uploads
them as the `swift-coverage` artifact.

## Interop

The Swift interop adapter lives at
[`harness/swift-client`](../harness/swift-client). Focused harness
commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=typescript pnpm exec vitest run
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=rust       pnpm exec vitest run
```

## Spec

This SDK implements the
[Solana Charge Intent draft](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## Repo layout

```text
swift/
├── Sources/SolanaMpp/
│   ├── Client/                # Charge client, HTTP retry, JSON-RPC
│   │   ├── Charge.swift       # MPP charge intent wire-signing pull path
│   │   ├── HTTPClient.swift   # URLSession-backed 402 retry client
│   │   └── RpcClient.swift    # Minimal JSON-RPC client
│   ├── Protocol/              # Wire format types
│   │   ├── Headers.swift      # Payment WWW-Authenticate / Authorization
│   │   └── Models.swift       # Wire-format Codable types
│   └── Crypto/                # Solana primitives (vendored, no umbrella dep)
├── Tests/SolanaMppTests/      # XCTest / swift-testing suite
└── Examples/                  # Sample clients (planned: Solana Seeker demo)
```

## License

MIT
