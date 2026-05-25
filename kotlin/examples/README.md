# Examples

Sample clients exercising the `solana-mpp-kotlin` library.

- `ChargeClient/` — minimal JVM CLI that performs an `mpp/charge/pull`
  against a 402-protected endpoint. Build via the existing `gradle build`
  in the parent project; the example is source-only today.

Planned (M2): `AndroidDemo/` — Compose UI app targeting the Solana
Seeker dev kit, end-to-end charge intent flow against
`https://402.surfnet.dev`. Tracked as a separate deliverable to keep
the SDK PR focused.
