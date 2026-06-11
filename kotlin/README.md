<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-kotlin-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-kotlin-light.png">
    <img alt="Solana pay-kit — Kotlin" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-kotlin-light.png">
  </picture>
</div>

# com.solanafoundation:pay-kit

Pay stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Kotlin.

One package, one surface, two protocols underneath: x402 and the Machine
Payments Protocol. Android and JVM clients ride on top of the same Solana
primitives.

This package is **client-only**. It consumes a `402 Payment Required`
challenge, derives and signs the Solana payment on the device, and replays
the request with the payment header. Server support lives in the TypeScript,
Rust, Go, PHP, Ruby, Lua, and Python packages.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet key, and drive a protected route in a few
lines. The mint address, token program, decimals, and transaction layout
are resolved for you from the challenge.

[![Kotlin](https://img.shields.io/badge/Kotlin-2.3.21-blue)]()
[![JVM](https://img.shields.io/badge/JVM-17-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D90%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-jacoco-blue)]()

## Quick start

The client is built [Retrofit](https://square.github.io/retrofit/)-style: a
`PayKitClient.Builder` configures it, payment handling lives in an OkHttp
interceptor, and the call surface is a small set of suspend functions returning
a typed `PayResponse`.

```kotlin
import com.solana.paykit.client.PayKitClient
import com.solana.paykit.protocols.mpp.client.JsonRpcClient
import com.solana.paykit.paycore.MemorySigner

val signer = MemorySigner.fromSecretKey(walletSecretKeyBytes)
val client = PayKitClient.Builder()
    .signer(signer)
    .charge(blockhashProvider = JsonRpcClient("https://402.surfnet.dev"))
    .build()

val result = client.get("https://402.surfnet.dev/paid") // 200 after the MPP retry
println(result.status)        // 200
println(result.paymentSent)   // true
println(result.settlement)    // on-chain signature (Payment-Receipt)
result.response.close()       // the caller owns the body
```

The first request hits a `402`; the payment interceptor builds and signs the
charge transaction, then replays with `Authorization: Payment ...`. The
currency, mint, token program, and decimals all come from the challenge body.

The same client and call surface drive both protocols. For x402 `exact`, swap
the protocol on the builder:

```kotlin
val client = PayKitClient.Builder()
    .signer(signer)
    // RPC is only consulted when an offer omits extra.recentBlockhash.
    // null network defaults to mainnet; pass "devnet" for Surfpool/devnet.
    .x402(rpc = "https://402.surfnet.dev", network = "devnet")
    .build()

val result = client.get("https://402.surfnet.dev/protected")
println(result.settlement) // x402 Payment-Response echo
```

A client may carry both protocols (call `charge(...)` and `x402(...)` on the
same builder); on a `402` the first interceptor to recognise the challenge
pays. There is also a DSL form:

```kotlin
val client = PayKitClient.httpClient {
    signer(signer)
    x402(rpcBlockhashProvider = { rpc.fetchRecentBlockhash() })
}
```

### Design: 402 retry as an OkHttp interceptor

The `402 -> pay -> retry` loop is not in the call methods. It is an OkHttp
`Interceptor` (`PaymentInterceptor`) in the client's chain, exactly how
Retrofit/OkHttp model auth and retry: on a `402` it buffers the body, parses
the protocol challenge, builds and signs the credential through the signer,
attaches the payment header, and replays the request once. One interceptor per
protocol (`ChargeInterceptor`, `X402Interceptor`) is composed onto the OkHttp
client by the builder. Bring your own OkHttp configuration (timeouts, logging,
proxies) through `okHttpClient(...)`; pay-kit only layers its interceptor on
top.

## Run the example

`examples/ChargeClient` (MPP) and `examples/X402Client` (x402 exact) are
single-file clients that gate one request. Point a Kotlin application module
at the file and run it against a server:

```bash
# curl gets a 402:
curl -i https://402.surfnet.dev/paid

# the client pays and gets a 200:
MPP_CLIENT_SECRET_KEY_HEX=<hex> ChargeClient https://402.surfnet.dev/paid
```

`examples/AndroidDemo` is a full Seeker / Android demo app that gates one
endpoint behind a wallet signature; its README walks through running it on a
device or emulator.

## x402

The x402 exact scheme builds a v0 payment transaction through
[web3-solana](https://github.com/solana-mobile/web3-solana) and replays with
the `Payment-Signature` header. See [x402.org](https://x402.org).

| Intent | Client |
|---|:---:|
| `x402/exact` | ✅ |
| `x402/upto` | — |
| `x402/batch-settlement` | — |

## MPP

The Machine Payments Protocol charge intent. The client parses the
`402` challenge, derives the Solana transfer, signs it, and replays.

| Intent | Client |
|---|:---:|
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Vocabulary

| Term | Meaning |
|---|---|
| gate | the `402` that protects a route |
| amount | the value transferred to the recipient |
| total | amount plus any fee on top |
| price | the operator-set amount for a route |
| fee within | a fee carved out of the amount |
| fee on top | a fee added to the amount |
| payment | the signed, replayed transaction |
| protocol | `x402` or `mpp` (the top-level dispatch) |
| scheme | the protocol sub-form (`exact` for x402, `charge` for mpp) |
| currency | the stablecoin symbol (USDC, USDT, PYUSD, ...) |
| settlement | the on-chain confirmation, returned as `Payment-Receipt` |

## Mobile / wallet integration

`MemorySigner` is for tests and local examples only. Production Android apps
implement `SolanaSigner` against a wallet stack via the official
[Solana Mobile](https://docs.solanamobile.com) packages:

```kotlin
implementation("com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.3")
implementation("com.solanamobile:web3-solana:0.3.1")
implementation("com.solanamobile:rpc-core:0.2.7")
```

Pass your `SolanaSigner` to `PayKitClient.Builder().signer(...)`; the rest of
the flow is unchanged.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `com.solanamobile:web3-solana` | x402 exact transaction / instruction / SPL transfer layout | 0.3.1 |
| `io.github.funkatronics:multimult` | Base58 codec shared with the Solana Mobile Kotlin stack | 0.2.3 |
| `org.bouncycastle:bcprov-jdk18on` | Ed25519 sign + verify, off-curve PDA checks | 1.78.1 |
| `com.squareup.okhttp3:okhttp` | HTTP client, JSON-RPC transport, 402-retry interceptor | 4.12.0 |
| `org.jetbrains.kotlinx:kotlinx-serialization-json` | challenge / credential JSON | 1.9.0 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` | suspend call surface (`PayKitClient.get`) | 1.10.1 |

What `web3-solana` does not yet supply (and so stays hand-rolled in
`paycore`): v0 `VersionedMessage` compilation, the ComputeBudget program, a
synchronous ATA derivation, and Blake3. The remaining hand-rolled Base58
fallback gap is tracked at
[solana-foundation/pay-kit#84](https://github.com/solana-foundation/pay-kit/issues/84).

## Harness

The harness adapters live outside the shipped library:

- [`harness/kotlin-client`](../harness/kotlin-client) drives an MPP server.
- [`harness/kotlin-x402-client`](../harness/kotlin-x402-client) drives an
  x402 exact server.

```bash
cd harness
MPP_HARNESS_CLIENTS=kotlin MPP_HARNESS_SERVERS=typescript pnpm test
```

## Coverage

```sh
cd kotlin
gradle check
```

`gradle check` runs the tests and enforces the 90 percent line-coverage gate
through Jacoco. Reports land at `build/reports/jacoco/test/`.

## Spec

- Solana Charge Intent: <https://paymentauth.org/draft-solana-charge-00.html>
- HTTP Payment Authentication scheme: <https://paymentauth.org>
- x402: <https://x402.org>
- Rust reference: `rust/crates/mpp/src/client/charge.rs` in this repository

## Repo layout

```text
kotlin/
├── src/main/kotlin/com/solana/paykit/
│   ├── client/                   # PayKitClient (builder) + payment interceptors
│   │   ├── PayKitClient.kt       # builder + suspend call surface
│   │   ├── PaymentInterceptor.kt # OkHttp interceptor: 402 -> pay -> retry
│   │   ├── ChargeInterceptor.kt  # MPP charge credential build
│   │   ├── X402Interceptor.kt    # x402 exact credential build
│   │   └── PaymentResult.kt      # PayResponse (status, paymentSent, settlement)
│   ├── paycore/                  # PayCore: protocol-agnostic primitives
│   │   ├── Base58.kt             # Base58 codec (multimult-backed)
│   │   ├── Base64Url.kt          # url-safe base64 (no padding)
│   │   ├── Ed25519.kt            # signing + off-curve PDA checks
│   │   ├── Instructions.kt       # SystemProgram, SPL, ATA, compute budget
│   │   ├── Mints.kt              # stablecoin mint + token-program table
│   │   ├── Network.kt            # CAIP-2 network ids + slug resolution
│   │   ├── SolanaSigner.kt       # signer interface + MemorySigner
│   │   └── Transaction.kt        # legacy + v0 wire codec
│   └── protocols/
│       ├── mpp/                  # Machine Payments Protocol
│       │   ├── client/           # Charge build + JSON-RPC client
│       │   └── core/             # canonical JSON, headers, wire types
│       └── x402/                 # x402
│           ├── exact/            # exact scheme wire types
│           └── client/exact/     # payment build + RPC blockhash client
├── src/test/kotlin/com/solana/paykit/{paycore,protocols/mpp,protocols/x402}/
│                                 # tests mirror the source tiers
└── examples/                     # ChargeClient, X402Client, AndroidDemo
```

## License

MIT
