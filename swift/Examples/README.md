# Examples

Sample clients exercising the `SolanaMpp` package.

- `ChargeClient/` — minimal CLI that performs a `mpp/charge/pull` against
  a 402-protected endpoint. Mirrors `rust/examples/payment_link_server.rs`
  on the client side.

Planned (M2): `iOSDemo/` — SwiftUI app targeting the Solana Seeker dev
kit, end-to-end charge intent flow against `https://402.surfnet.dev`.
Tracked as a separate deliverable to keep the SDK PR focused.
