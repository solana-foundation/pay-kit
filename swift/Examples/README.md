# Examples

Sample clients exercising the `SolanaPayKit` package.

- [`PayKitClient/`](PayKitClient) — headless CLI driver. Picks the
  protocol via a positional arg (`mpp` or `x402`), reads the signer
  seed from `PAYKIT_CLIENT_SECRET_KEY_HEX`, replays a 402-gated request
  once with the payment header attached. Source-only — add an
  executable target to `Package.swift` locally to run it.
- [`PayKitDemo/`](PayKitDemo) — SwiftUI iOS app that drives the SDK
  end-to-end against `pay server demo`. Keychain-backed signer, in-app
  Surfpool topup, carousel of demo gateway endpoints, append-only
  result log. See its README for the run recipe.
