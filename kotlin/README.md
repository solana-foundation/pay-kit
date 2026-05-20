# Solana MPP Kotlin SDK

Kotlin support currently provides the MPP charge client protocol core:

- parse `WWW-Authenticate: Payment ...` charge challenges
- decode Solana charge request payloads
- build pull-mode `Authorization: Payment ...` credentials
- inject a transaction provider for wallet or application-specific signing

The package does not pick an Android wallet dependency yet. Android integrations can connect this boundary to Solana Mobile Wallet Adapter or another signing stack while the SDK keeps the MPP challenge and credential contract aligned with TypeScript and Rust.

## Build

```sh
gradle test
```

## Usage

```kotlin
import com.solana.mpp.ChargeCredentialBuilder
import com.solana.mpp.MppHeaders
import com.solana.mpp.StaticChargeTransactionProvider

val challenge = MppHeaders.parseWWWAuthenticate(wwwAuthenticateHeader)
val builder = ChargeCredentialBuilder(
    StaticChargeTransactionProvider("signed-base64-transaction")
)

val authorization = builder.authorizationHeader(challenge)
```
