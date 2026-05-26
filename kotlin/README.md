<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# com.solanafoundation:pay-kit

Consume stablecoin-gated HTTP endpoints (USDC, USDT, PYUSD, ...) from
Kotlin. Implements the client side of the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

This library is **client-only**. It parses MPP `402 Payment Required`
challenges, derives the Solana transaction on the client, signs it with
the user's Ed25519 key (or a wallet via Mobile Wallet Adapter), and
replays the request with an `Authorization: Payment ...` header. Server
support lives in the TypeScript, Rust, Go, PHP, Ruby, Lua, and Python
packages.

**MPP** is [an open protocol proposal](https://paymentauth.org) that
lets any HTTP API accept payments using the `402 Payment Required` flow.
You do not need to know anything about Solana to use this library: pick
a currency, give it your wallet address, and pay a protected route in a
few lines.

[![Kotlin](https://img.shields.io/badge/Kotlin-2.3.21-blue)]()
[![JVM](https://img.shields.io/badge/JVM-17-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D90%25-brightgreen)]()

## Quick start

Drive an MPP-gated endpoint with `MppHttpClient`:

```kotlin
import com.solana.mpp.Charge
import com.solana.mpp.JsonRpcClient
import com.solana.mpp.MemorySigner
import com.solana.mpp.MppHttpClient

// Wallet integrations swap MemorySigner for their own SolanaSigner.
val signer = MemorySigner.fromSecretKey(walletSecretKeyBytes)
val rpc = JsonRpcClient("http://localhost:8899")
val client = MppHttpClient(signer = signer, blockhashProvider = rpc)

val response = client.mppGet("http://localhost:4570/paid")
println(response.code)                      // 200 after MPP retry
println(response.header("Payment-Receipt")) // on-chain signature
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The challenge body sets the actual currency; the client
resolves the mint address, token program, and decimals from
`Charge.resolveStablecoinMint` and the challenge `methodDetails`.

### Mobile / wallet integration

`MemorySigner` is for tests and local examples only. Production Android
apps connect `SolanaSigner` to a wallet stack via the official
[Solana Mobile](https://docs.solanamobile.com) packages:

```kotlin
implementation("com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.3")
implementation("com.solanamobile:web3-solana:0.2.5")
implementation("com.solanamobile:rpc-core:0.2.7")
```

Implement `SolanaSigner` against your wallet's signing primitive; pass
it to `MppHttpClient` and the rest of the flow is unchanged.

## Protocol compatibility matrix

This library is client-only. Server support lives in the TypeScript,
Rust, Go, PHP, Ruby, Lua, and Python packages.

### MPP

| Intent | Client |
|---|:---:|
| `mpp/charge/pull` | pass |
| `mpp/charge/push` | --- |
| `mpp/session` | planned |
| `mpp/subscription` | --- |

### x402

| Intent | Client |
|---|:---:|
| `x402/exact` | --- |
| `x402/upto` | --- |
| `x402/batch-settlement` | --- |

## Examples

The `examples/` directory hosts sample clients (a Solana Seeker demo
app is planned). For an end-to-end exercise, run the interop adapter
at [`harness/kotlin-client`](../harness/kotlin-client) against any
registered server.

### Drive a TypeScript server

```bash
cd harness/kotlin-client
MPP_INTEROP_TARGET_URL=http://localhost:4570/paid \
MPP_INTEROP_RPC_URL=http://localhost:8899 \
MPP_INTEROP_CLIENT_SECRET_KEY='[1,2,3,...,64]' \
  gradle run --no-daemon
```

The adapter is the same Kotlin client wired to the env-var contract the
TypeScript / Vitest harness drives in CI.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `org.bouncycastle:bcprov-jdk18on` | Ed25519 sign + verify, point validation for PDA off-curve checks | 1.78.1 |
| `com.squareup.okhttp3:okhttp` | HTTP client, JSON-RPC transport, 402 retry | 4.12.0 |
| `org.jetbrains.kotlinx:kotlinx-serialization-json` | challenge body parsing, credential payload encoding | 1.9.0 |

Solana base58, transaction bincode, instruction builders, ATA derivation,
and the compute-budget program are implemented inline in pure Kotlin so
the SDK does not pin a full Solana stack. Byte-for-byte parity with the
Rust spine is asserted in the test suite.

## Coding convention

This SDK follows the
[official Kotlin coding conventions](https://kotlinlang.org/docs/coding-conventions.html)
plus the per-language style notes at
`skills/pay-sdk-implementation/references/coding-conventions.md`.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust wire format first, Kotlin idioms second.

## Code coverage

```sh
cd kotlin
gradle check
```

`gradle check` runs the unit tests and enforces the 90 percent line
coverage gate through Jacoco. The XML and HTML reports land at
`build/reports/jacoco/test/`.

## Interop

Adapter at `harness/kotlin-client`. Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=kotlin MPP_INTEROP_SERVERS=typescript pnpm test
```

## Spec

- HTTP Payment Authentication scheme: <https://paymentauth.org>
- MPP spec PRs: <https://github.com/tempoxyz/mpp-specs>
- Rust reference: `rust/src/client/charge.rs` in this repository

## Repo layout

```text
kotlin/
├── src/main/kotlin/com/solana/mpp/
│   ├── client/                # Charge build pipeline + HTTP/JSON-RPC
│   │   ├── Charge.kt          # full charge build pipeline
│   │   └── HttpClient.kt      # OkHttp client with 402 retry + JSON-RPC
│   ├── protocol/              # Wire format + canonical JSON + errors
│   │   ├── CanonicalJson.kt   # deterministic JSON encoding
│   │   ├── Headers.kt         # WWW-Authenticate / Authorization parser
│   │   └── Models.kt          # exceptions, challenge + credential schema
│   └── crypto/                # Solana primitives (vendored)
│       ├── Base58.kt          # Bitcoin-alphabet base58 codec
│       ├── Base64Url.kt       # url-safe base64 (no padding)
│       ├── Ed25519.kt         # BouncyCastle signing + PDA derivation
│       ├── Instructions.kt    # SystemProgram, SPL, ATA, compute budget
│       ├── SolanaSigner.kt    # signer abstraction + MemorySigner
│       └── Transaction.kt     # legacy + v0 Solana wire codec
├── src/test/kotlin/com/solana/mpp/{client,protocol,crypto}/
│                                # tests mirror the main source layout
└── examples/                  # Sample clients (Solana Seeker demo app)
```

## License

MIT
