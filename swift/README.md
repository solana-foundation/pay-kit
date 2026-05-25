<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# SolanaMpp

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Swift.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library, pick a
currency, give it your wallet address, and pay a protected route in two lines.

[![Swift](https://img.shields.io/badge/Swift-6.0%2B-blue)]()
[![Platforms](https://img.shields.io/badge/platforms-iOS%2016%20%7C%20macOS%2013-lightgrey)]()

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
│       ├── Base58.swift       # Bitcoin / Solana alphabet base58
│       ├── Base64URL.swift    # RFC 4648 base64url for credential framing
│       ├── Curve25519Field.swift # GF(2^255 - 19) for PDA on-curve checks
│       ├── Pubkey.swift       # 32-byte account identifier
│       ├── Ed25519.swift      # CryptoKit signing facade
│       ├── SolanaSigner.swift # Signer abstraction + MemorySigner
│       ├── Transaction.swift  # Legacy + v0 message codec
│       ├── Instructions.swift # System, SPL, ATA, compute budget, memo
│       └── Ata.swift          # Associated Token Account PDA derivation
├── Tests/SolanaMppTests/      # XCTest / swift-testing suite
└── Examples/                  # Sample clients (M2: Solana Seeker demo app)
```

Mirrors the Rust layout (`rust/src/{client,protocol}/`) so cross-language
contributors can navigate by feature, not file name.

## Scope

Swift is **client-only** across every milestone in the MPP roadmap.
This package ships the charge client; an MPP server in Swift is not
in scope. The session and subscription intents add to this package
in M2 and M3.

## Quick start, client

```swift
import SolanaMpp

let signer = try MemorySigner(secretKey: secretKeyData) // 32-byte seed or 64-byte Solana keypair
let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
let client = MppHTTPClient(signer: signer, rpc: rpc)

let response = try await client.fetch(url: URL(string: "https://api.example.com/paid-content")!)
print(response.status)              // 200
print(response.settlementSignature) // base58 on-chain signature
```

`MppHTTPClient` sends the request, on a 402 response it parses the
`WWW-Authenticate: Payment ...` challenge, builds the credential through
the supplied `SolanaSigner`, and replays the same request once with the
`Authorization: Payment ...` header attached. Any non-402 status (success,
other 4xx, 5xx) is returned verbatim. Transport errors propagate.

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

Then add `SolanaMpp` to your target dependencies.

## Client compatibility matrix

Swift is client-only across the MPP roadmap.

| Intent | Status |
|---|:---:|
| `x402/exact` | planned (M2) |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |
| `mpp/charge/pull` | available |
| `mpp/charge/push` | planned |
| `mpp/session` | planned (M2) |
| `mpp/subscription` | planned (M3) |

## Server compatibility matrix

Swift does not ship a server in any milestone.

| Intent | Status |
|---|:---:|
| `x402/exact` | --- |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |
| `mpp/charge/pull` | --- |
| `mpp/charge/push` | --- |
| `mpp/session` | --- |
| `mpp/subscription` | --- |

## Solana dependencies

The SDK keeps Solana dependencies intentionally small. Pure Swift, no
external dependency beyond Foundation and Apple CryptoKit.

| Dependency | Why | Version |
|---|---|---|
| `Foundation` | URLSession, JSON, Data | system |
| `CryptoKit` | Ed25519 signing / verification, SHA-256 | system |

There is no `solana-swift` umbrella dependency. Base58, the transaction
codec, PDA derivation, the on-curve check (`Curve25519Field`), and the
minimal JSON-RPC client are vendored in-tree for byte-for-byte parity
with the Rust spine (`solana-message 3.1`, `solana-pubkey 3.x`,
`bs58 0.5`, `solana-curve25519`). Parity is locked by golden vectors
in `Tests/SolanaMppTests`.

## Coding convention

This SDK follows the
[Swift API Design Guidelines](https://www.swift.org/documentation/api-design-guidelines/)
for idiomatic Swift practices: clarity at point of use, role-based
parameter labels, structured concurrency (`Sendable`-only public
surface), throws over precondition on caller-controlled input, and
value types for wire-format models.

Formatting and linting are not enforced in CI on the Swift package
today; `swift-format` and `swiftlint` are reasonable defaults for
contributors.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, Swift idioms second.

## Tests and coverage

```bash
cd swift
swift test --enable-code-coverage
```

Coverage artifacts live in `swift/.build/debug/codecov/`. CI uploads
them as the `swift-coverage` artifact. The harness covers:

- base58 round-trip parity with `bs58 0.5` (14 golden vectors)
- transaction codec parity with `solana-message 3.1` (4 golden vectors:
  legacy SOL, v0 SOL, v0 SPL transferChecked, v0 multi-instruction with
  compute budget prepended)
- ATA derivation parity with `solana-pubkey 3.x` (4 golden vectors)
- Curve25519 on-curve check direct vectors (generator point + known
  on-curve / off-curve PDA candidates)
- Ed25519 signing fixed length and verification correctness
- Charge wire signing end-to-end (SPL split with ATA creation, SOL
  transfer, splits-exceed-amount rejection, multi-challenge selection)
- MppHTTPClient 402 retry semantics (retry once on 402, no retry on
  5xx or transport error, multi-challenge WWW-Authenticate splitting)

## Interop

The Swift interop adapter lives at
[`tests/interop/swift-client`](../tests/interop/swift-client) and is
registered in `tests/interop/src/implementations.ts`. Default on after
the focused TS-to-Swift matrix passes locally (this PR ships both the
default-off registration and the default-on flip atop the same diff,
per the roadmap's sequential-rebase rule on the
`implementations.ts` hotspot).

Focused matrix commands:

```bash
cd tests/interop
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=typescript pnpm exec vitest run
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=rust       pnpm exec vitest run
```

## Spec

This SDK implements the
[Solana Charge Intent draft](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
