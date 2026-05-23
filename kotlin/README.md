# Solana MPP Kotlin SDK

Kotlin support currently provides the MPP charge client protocol core:

- parse `WWW-Authenticate: Payment ...` charge challenges
- decode Solana charge request payloads
- build pull-mode `Authorization: Payment ...` credentials
- inject a transaction provider for wallet or application-specific signing
- model a small JVM `SolanaSigner` boundary for wallet-backed signing

The package does not pick an Android wallet dependency yet. Android integrations can connect the signer boundary to Solana Mobile Wallet Adapter or another signing stack while the SDK keeps the MPP challenge and credential contract aligned with TypeScript and Rust.

`MemorySigner` uses JDK Ed25519 and is intended for tests and local development only. It is not a wallet, key-management layer, or Solana transaction builder.

## Solana Mobile integration

For Android applications, keep this package as the MPP protocol layer and add the official Solana Mobile dependencies in the app or adapter module:

```kotlin
implementation("com.solanamobile:mobile-wallet-adapter-clientlib-ktx:2.0.3")
implementation("com.solanamobile:web3-solana:0.2.5")
implementation("com.solanamobile:rpc-core:0.2.7")
implementation("io.github.funkatronics:multimult:0.2.3")
```

`mobile-wallet-adapter-clientlib-ktx` is the right boundary for connecting to MWA-compatible wallets. `web3-solana` and `rpc-core` are useful for transaction construction and RPC in an Android app. They are intentionally not runtime dependencies of the core MPP package yet so non-Android JVM users can parse challenges and build credentials without pulling in a wallet stack.

## Build

```sh
gradle check
```

## Usage

```kotlin
import com.solana.mpp.ChargeCredentialBuilder
import com.solana.mpp.ChargeTransactionProvider
import com.solana.mpp.Base64Url
import com.solana.mpp.MemorySigner
import com.solana.mpp.MppHeaders

val challenge = MppHeaders.parseWWWAuthenticate(wwwAuthenticateHeader)
val signer = MemorySigner.generate()
val builder = ChargeCredentialBuilder(
    ChargeTransactionProvider { request ->
        // Build the Solana transaction with your wallet/application code, then
        // sign the transaction message through the signer boundary.
        val transactionMessage = "${request.externalId}:${request.recipient}:${signer.address}".encodeToByteArray()
        Base64Url.encode(signer.sign(transactionMessage))
    }
)

val authorization = builder.authorizationHeader(challenge)
```
