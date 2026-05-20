# Solana MPP Swift SDK

Swift support currently provides the MPP charge client protocol core:

- parse `WWW-Authenticate: Payment ...` charge challenges
- decode Solana charge request payloads
- build pull-mode `Authorization: Payment ...` credentials
- inject a transaction provider for wallet or application-specific signing
- model a small `SolanaSigner` abstraction for application-owned signing code

The package intentionally does not pick an iOS wallet or Solana transaction dependency yet. Integrations can provide a signed base64 transaction through `ChargeTransactionProviding` while the SDK keeps the MPP challenge, credential contract, and signer boundary aligned with the TypeScript and Rust implementations.

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

The transaction provider is where an app integrates its selected Solana transaction construction and signing stack. That provider can depend on a signer without moving MPP challenge parsing into wallet code:

```swift
struct WalletTransactionProvider: ChargeTransactionProviding {
    let signer: any SolanaSigner

    func buildTransaction(for request: ChargeRequest) async throws -> String {
        // Construct the Solana transaction with your chosen wallet/Solana stack,
        // ask the signer to sign the transaction message, then return the signed
        // base64 transaction expected by the MPP credential payload.
        let message = Data("transaction-message-placeholder".utf8)
        let signedTransaction = try await signer.sign(message: message)
        return signedTransaction.base64EncodedString()
    }
}
```

`MemorySigner` is included for tests and development examples. It is not a Solana transaction builder and does not perform Ed25519 signing by itself.
