# Solana MPP Swift SDK

Swift support currently provides the MPP charge client protocol core:

- parse `WWW-Authenticate: Payment ...` charge challenges
- decode Solana charge request payloads
- build pull-mode `Authorization: Payment ...` credentials
- inject a transaction provider for wallet or application-specific signing

The package intentionally does not pick an iOS wallet or Solana transaction dependency yet. Integrations can provide a signed base64 transaction through `ChargeTransactionProviding` while the SDK keeps the MPP challenge and credential contract aligned with the TypeScript and Rust implementations.

## Install

Add the local package to your Swift Package Manager dependencies:

```swift
.package(path: "../mpp-sdk/swift")
```

Then add `SolanaMpp` to your target dependencies.

## Usage

```swift
import SolanaMpp

let challenge = try MppHeaders.parseWWWAuthenticate(wwwAuthenticateHeader)
let builder = ChargeCredentialBuilder(
    transactionProvider: StaticChargeTransactionProvider(transaction: signedBase64Transaction)
)

let authorization = try await builder.authorizationHeader(for: challenge)
```

The transaction provider is where an app integrates its selected Solana signing stack.
