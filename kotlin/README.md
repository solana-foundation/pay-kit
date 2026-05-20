# Solana MPP Kotlin SDK

Kotlin support currently provides the MPP charge client protocol core:

- parse `WWW-Authenticate: Payment ...` charge challenges
- decode Solana charge request payloads
- build pull-mode `Authorization: Payment ...` credentials
- inject a transaction provider for wallet or application-specific signing
- model a small JVM `SolanaSigner` boundary for wallet-backed signing

The package does not pick an Android wallet dependency yet. Android integrations can connect the signer boundary to Solana Mobile Wallet Adapter or another signing stack while the SDK keeps the MPP challenge and credential contract aligned with TypeScript and Rust.

`MemorySigner` uses JDK Ed25519 and is intended for tests and local development only. It is not a wallet, key-management layer, or Solana transaction builder.

## Build

```sh
gradle test
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
