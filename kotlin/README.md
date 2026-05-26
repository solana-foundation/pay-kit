<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# org.solana.x402.exact

Kotlin client for the [x402](https://x402.org) `exact` payment scheme on
Solana. Pay any HTTP endpoint that responds with `402 Payment Required`
in JVM applications, with a small dependency footprint and a wire format
that mirrors the Rust spine byte-for-byte.

[![Kotlin](https://img.shields.io/badge/Kotlin-2.3%2B-blue)]()
[![JVM](https://img.shields.io/badge/JVM-17%2B-lightgrey)]()

## Repo layout

```text
kotlin/
├── build.gradle.kts            # Kotlin JVM toolchain, gson, JUnit
├── settings.gradle.kts
├── src/main/kotlin/org/solana/x402/exact/
│   ├── ExactChallenge.kt       # 402 challenge parsing, SVM network table,
│   │                           # stablecoin mint resolution, selection logic
│   ├── ExactPaymentClient.kt   # Unsigned tx builder interface, signer
│   │                           # interface, X-PAYMENT header assembly
│   ├── SolanaTransaction.kt    # v0 message codec, instruction layout,
│   │                           # ATA derivation, signature framing
│   └── InteropClient.kt        # Command-line interop driver consumed by
│                               # tests/interop
└── src/test/kotlin/org/solana/x402/exact/
    ├── ExactChallengeTest.kt
    ├── ExactPaymentClientTest.kt
    └── SolanaTransactionTest.kt
```

Package and directory layout follows the canonical Solana JVM convention
(`org.solana.x402.exact`) so the namespace is stable across artifact
publication, IDE navigation, and the JVM ecosystem at large.

## Scope

This module is **client-only**. It builds the `X-PAYMENT` header for a
Solana `exact` payment requirement and re-issues the request. An x402
server in Kotlin is not in scope; the Rust spine in `rust/` is the
canonical server reference and is the facilitator for the interop
harness.

## Quick start, client

```kotlin
import org.solana.x402.exact.ExactChallenge
import org.solana.x402.exact.ExactPaymentClient
import org.solana.x402.exact.DefaultSolanaExactTransactionBuilder
import org.solana.x402.exact.JsonRpcSolanaClient
import org.solana.x402.exact.MemorySolanaTransactionSigner
import java.net.HttpURLConnection
import java.net.URI

val signer = MemorySolanaTransactionSigner.fromJsonByteArray(secretKeyJson)
val rpc = JsonRpcSolanaClient("https://api.mainnet-beta.solana.com")
val client = ExactPaymentClient(DefaultSolanaExactTransactionBuilder(rpc), signer)

val first = (URI("https://api.example.com/paid").toURL().openConnection() as HttpURLConnection)
val challenge = ExactChallenge.selectSvmChallenge(
    headers = first.headerFields.mapValues { it.value.joinToString(",") },
    body = first.errorStream?.bufferedReader()?.readText() ?: "",
    network = ExactChallenge.DEFAULT_NETWORK,
    scheme = "exact",
    preferredCurrencies = listOf("USDC"),
) ?: error("no Solana exact challenge")

val headers = client.createPaymentHeaders(challenge, signer.publicKey.base58)
// Re-issue the request with `headers` attached. The facilitator returns
// 200 plus an `X-FIXTURE-SETTLEMENT` header carrying the on-chain
// signature once the transaction lands.
```

The `signer.publicKey.base58` argument is the on-chain payer; the
builder fills in the fee payer slot, derives the source associated
token account, and resolves the mint and decimals from the SVM
stablecoin table embedded in `ExactChallenge`.

## Install

Add the module to your Gradle project. While the artifact is not
published to Maven Central, depend on it through a composite build or
`includeBuild`:

```kotlin
// settings.gradle.kts
includeBuild("../mpp-sdk/kotlin")
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("org.solana.x402:exact")
    implementation("com.google.code.gson:gson:2.13.2")
}

kotlin {
    jvmToolchain(17)
}
```

Runtime dependencies are intentionally lean: Gson for JSON, the Kotlin
standard library, and the JVM. No `web3-solana`, no `multimult`, no
umbrella SDK.

## Client compatibility matrix

The Kotlin client targets the x402 `exact` scheme on Solana. The Rust
spine serves as the facilitator across the interop harness.

| Intent | Status |
|---|:---:|
| `x402/exact` | available |
| `x402/upto` | ___ |
| `x402/batch-settlement` | ___ |
| `mpp/charge/pull` | ___ |
| `mpp/charge/push` | ___ |

## Server compatibility matrix

Kotlin does not ship a server. Pair this client with the Rust spine
under `rust/` or any spec-compliant x402 facilitator.

| Intent | Status |
|---|:---:|
| `x402/exact` | ___ |
| `x402/upto` | ___ |
| `x402/batch-settlement` | ___ |

## Solana dependencies

Solana primitives are vendored in `SolanaTransaction.kt` to keep the
dependency footprint small and the on-wire bytes locked to the Rust
spine.

| Dependency | Why | Version |
|---|---|---|
| `kotlin-stdlib` | language runtime | 2.3.x |
| `com.google.code.gson` | JSON encode and decode | 2.13.2 |
| `java.net.HttpURLConnection` | JSON-RPC and HTTP | system |
| `java.security.MessageDigest` | SHA-256 for PDA derivation | system |
| Ed25519 (vendored) | signing, on-curve check | in-tree |

There is no umbrella Solana JVM dependency. Base58, the v0 message
codec, instruction encoding, associated-token-account derivation, and
the Curve25519 on-curve check are all in-tree, with golden vectors
pinned against the Rust spine in `src/test/kotlin/`.

## Coding convention

This module follows
[Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
and standard Kotlin JVM idioms: explicit visibility on the public
surface, immutable `data class` wire types, `sealed class` for closed
network enumerations, `fun interface` for small builder and signer
SAMs, and `require(...)` for caller-controlled validation.

JVM target is 17 (`kotlin { jvmToolchain(17) }`). Formatting and
linting are not enforced by CI on the Kotlin module today; `ktlint`
and `detekt` are reasonable defaults for contributors and are tracked
in the broader Kotlin tooling backlog.

The repo-level pay-sdk implementation guidance is the protocol source
of truth: the Rust spine wire format first, Kotlin idioms second.

## Tests and coverage

```bash
cd kotlin
./gradlew test
```

The suite pins parity against the Rust spine through golden vectors:

- base58 alphabet round-trip
- v0 transaction codec (legacy SOL transfer, SPL `transferChecked`,
  multi-instruction with compute-budget prefix)
- ATA derivation across known mint and owner pairs
- Curve25519 on-curve check for PDA candidates
- Ed25519 signing length and verification
- Challenge selection for multi-requirement 402 bodies, including
  preferred-currency ordering and unknown-network rejection
- End-to-end payment header build for `exact` with the in-tree memory
  signer

Test runs produce JUnit XML under `kotlin/build/test-results/test/`.
The repository-level coverage policy targets a 90% line threshold for
the `org.solana.x402.exact` package; the JaCoCo wiring is tracked
separately.

## Interop

The Kotlin x402 client runs against the interop harness at
`tests/interop`, driven by the JVM entry point
`org.solana.x402.exact.InteropClientKt` exposed through the
`runInteropClient` Gradle task. Adapter registration lives alongside
the other client adapters in `tests/interop/src/`.

Focused matrix command:

```bash
cd tests/interop
MPP_INTEROP_CLIENTS=kotlin MPP_INTEROP_SERVERS=rust pnpm exec vitest run
```

The Kotlin client is verified against the Rust spine, which is the
canonical facilitator for the interop matrix.

## Spec

- [x402 protocol](https://x402.org)
- [Machine Payments Protocol](https://mpp.dev)
- [paymentauth.org](https://paymentauth.org), HTTP `402 Payment
  Required` flow definition
- Rust spine, `rust/crates/x402/`, is the on-wire reference for the
  `exact` scheme on Solana

## License

Apache-2.0
