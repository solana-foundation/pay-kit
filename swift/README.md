<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-swift-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-swift-light.png">
    <img alt="Solana pay-kit — Swift" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-swift-light.png">
  </picture>
</div>

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

The public surface is namespaced under `PayKit` and modeled on
[Alamofire](https://github.com/Alamofire/Alamofire): build one reusable
`PayKit.HttpClient` with config, then issue fluent requests. Payment is
handled by an interceptor (the Alamofire `RequestInterceptor` pattern),
so the same client shape drives both the MPP charge flow and x402.

```swift
import SolanaPayKit

let signer = try MemorySigner(secretKey: secretKeyData) // 32-byte seed or 64-byte Solana keypair
let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
let client = PayKit.HttpClient.mpp(signer: signer, rpc: rpc)

let response = try await client
    .request(URL(string: "https://api.example.com/paid")!)
    .response()
print(response.status)              // 200 after the payment retry
print(response.settlementSignature) // base58 on-chain signature
```

`PayKit.HttpClient` is created once and reused across requests, the way
an Alamofire `Session` is. `client.request(_:method:headers:body:)`
returns a `PayKit.DataRequest` value; terminate it with `.response()`
for the raw `PayKit.DataResponse`, or `.serializingDecodable(of:)` to
decode the body directly:

```swift
struct Quote: Decodable { let price: String }

let quote = try await client
    .request(URL(string: "https://api.example.com/quote")!)
    .serializingDecodable(of: Quote.self)
```

The payment interceptor sends the request, and on a `402` response it
parses the challenge, builds the credential through the supplied
`SolanaSigner`, and replays the request once with the payment header
attached (`Authorization: Payment ...` for MPP charge,
`Payment-Signature` for x402). Any non-402 status (success, other 4xx,
5xx) is returned verbatim. Transport errors propagate. To drive x402
instead, build the client with `PayKit.HttpClient.x402(signer:rpc:)`.

The `mpp` and `x402` factories each wire a concrete
`PayKit.PaymentInterceptor` (`ChargeInterceptor` and `X402Interceptor`).
Supply your own to the designated `PayKit.HttpClient(interceptor:)`
initializer to customise the payment flow.

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
| `x402/exact` | pass |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |

## Examples

The `Examples/` directory hosts sample clients (a Solana Seeker demo
app is planned):

- [`ChargeClient/`](Examples/ChargeClient) — headless MPP charge client.
- [`X402Client/`](Examples/X402Client) — headless x402 exact client; probes
  a gated resource, builds the `Payment-Signature` header through a signer,
  and replays once.

Both are source-only so the default `swift build` stays library-only; add an
executable target to `Package.swift` locally to run them. For an end-to-end
exercise, run the interop adapter at
[`harness/swift-client/`](../harness/swift-client) (MPP) or
[`harness/swift-x402-client/`](../harness/swift-x402-client) (x402) against
any registered server.

### Drive a TypeScript server

```bash
cd harness
MPP_INTEROP_CLIENTS=swift MPP_INTEROP_SERVERS=typescript pnpm exec vitest run
```

### Drive the Rust x402 server

```bash
cd harness
X402_INTEROP_CLIENTS=swift-x402 X402_INTEROP_SERVERS=rust-x402 \
  MPP_INTEROP_INTENTS=x402-exact MPP_INTEROP_SCENARIOS=x402-exact-basic \
  pnpm exec vitest run test/e2e.test.ts \
  --testNamePattern "swift-x402 client pays rust-x402 server"
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
├── Sources/SolanaPayKit/
│   ├── SolanaPayKit.swift     # PayKit namespace: HttpClient, DataRequest, interceptor
│   ├── PayCore/               # Solana primitives + RPC (vendored, no umbrella dep)
│   └── protocols/
│       ├── mpp/
│       │   ├── client/
│       │   │   ├── Charge.swift      # MPP charge intent wire-signing pull path
│       │   │   └── HTTPClient.swift  # ChargeInterceptor (402 -> Authorization: Payment)
│       │   └── core/                 # Payment WWW-Authenticate / Authorization, models
│       └── x402/
│           ├── client/exact/
│           │   ├── Payment.swift     # x402 challenge parse + payment building
│           │   └── Transport.swift   # X402Interceptor (402 -> Payment-Signature)
│           └── exact/Types.swift     # x402 wire-format Codable types
├── Tests/SolanaPayKitTests/   # swift-testing suite
└── Examples/                  # Sample clients (planned: Solana Seeker demo)
```

## License

MIT
