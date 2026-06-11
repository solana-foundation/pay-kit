# PayKit interface drift — TODO

Tracking list for the cross-SDK drifts identified while writing
[paykit-interface.md](./paykit-interface.md). Each item brings an SDK in line
with the spec. Items marked **(breaking)** need a one-release deprecation
alias.

## Cross-cutting (every SDK)

- [ ] `Payment` gains `payer` (settling wallet address) and carries `scheme`
      everywhere (`exact` / `charge`). Only Ruby has `scheme` today; nobody
      exposes `payer`.
- [ ] `Gate.accepts?(protocol)` replaces per-protocol predicates
      (`x402_accepted?` / `mpp_accepted?` / etc.) so adding a protocol never
      grows the Gate API. Keep old predicates as deprecated aliases.
- [ ] `gate.fee_within()` / `gate.fee_on_top()` accessors, so callers stop
      filtering `gate.fees` by kind themselves.
- [ ] Align canonical defaults table: `mpp.expires_in = 120`, stablecoin set
      `USDC, USDT, USDG, PYUSD, CASH`, accept order `[x402, mpp]`.
- [ ] Canonical `InvalidProof` machine codes asserted by conformance suites
      (Python list is the reference; Ruby `spec_code` and PHP codes map to it).
- [ ] Conformance suites assert the defaults table and error codes, not just
      wire shapes.

## Ruby

- [ ] `mpp.expires_in` default 300 → 120.
- [ ] Stablecoin set: add `USDG`, `CASH`.
- [ ] Add `PayKit.configure_from_env` (mirrors Python `configure_from`).
- [ ] Wire `external_id` through every flow (currently inconsistent).
- [ ] Add `payer` to `Payment`.
- [ ] `Gate#accepts?(protocol)`; deprecate `x402_accepted?` / `mpp_accepted?`.

## Python

- [ ] Collapse `is_paid` / `is_paid_for` → `is_paid(request, gate=None)`
      **(breaking)**.
- [ ] Rename `FileReplayStore` → `FileStore` **(breaking)**.
- [ ] Rename `x402_async_client` / `X402Client` → `pay_kit.client(...)` and
      make it protocol-agnostic — select from the server's `accepts[]`, add
      MPP charge support behind the same transport **(breaking)**.
- [ ] Demote `seconds/minutes/hours/days/weeks` from top-level exports —
      they are MPP internals, not core.
- [ ] Type `PaymentRequiredError.challenge` properly instead of stashing
      untyped `challenge_headers` / `body` attributes.
- [ ] Add `payer` and `scheme` to `Payment`.
- [ ] Drop deprecated `configure()` kwargs (`pay_to`, `facilitator`,
      `facilitator_secret_key`, `secret`) on the next minor.

## PHP

- [ ] Add `name` to `Gate`; `Pricing` injects it from the property name at
      construction instead of reflecting at lookup.
- [ ] Add the imperative trio — `require_payment($request, $gate)`,
      `paid($request, $gate)`, `payment($request)` helper functions over the
      `paykit.payment` request attribute — so non-middleware code paths exist.
- [ ] Add `Config::fromEnv()`.
- [ ] Add `Gate::accepts(Protocol $p): bool`.
- [ ] Add `payer` to `Payment`.
- [ ] Simplify `MppConfig::resolveExpiresIn` (plain int + an
      `EXPIRES_NEVER = 0` constant).
- [ ] Fix the nullable signer cascade in `effectiveX402Signer()`
      (`x402.signer ?? operator.signer` can still resolve to null).

## TypeScript

Different in kind: `@solana/mpp` is a layer-3 protocol package (session
machinery, charge/session/subscription methods, mppx dispatch) and is in good
shape at that layer. The layer-1 surface now lives in
`typescript/packages/pay-kit` (`@solana/pay-kit`), with `@solana/mpp` wrapped
as its first protocol adapter.

- [x] Decide packaging: `@solana/pay-kit` provides layer 1, with
      `@solana/mpp` (and a future x402 package) underneath as protocol
      adapters.
- [x] Layer-1 nouns: `Config`, `Operator`, `Price` (`usd()`/`eur()`/`gbp()`),
      `Fee`, `Gate`, `Pricing`, `Payment`.
- [x] `Signer` static factory (`demo/file/env/json/hex/base58/bytes/generate`)
      including the demo signer and the demo-on-mainnet boot refusal. Built on
      Solana Keychain: local keys via `@solana/keychain-memory`, remote
      backends (AWS KMS, GCP KMS, Vault, Privy, Turnkey, ...) via
      `Signer.from(keychainSigner)`.
- [x] Error hierarchy: `PayKitError` root with the canonical subtypes.
- [x] Server verbs: `requirePayment` / `paid` / `payment` over a dispatcher
      (web-standard `Request`/`Response`; result-object idiom instead of
      halt-by-exception).
- [x] MPP charge expressed as a spec Adapter
      (`detect / acceptsEntry / challengeHeaders / verifyAndSettle`) wrapping
      `Mppx` + `solana.charge`, including fee → splits lowering.
- [ ] x402 adapter: no x402 implementation exists in TypeScript at all;
      `configure({ accept: ['x402'] })` throws `ProtocolNotSupportedError`
      until one ships.
- [ ] Protocol-agnostic client: `SessionFetchClient` is Solana/session-only;
      fold it into one client factory that selects from `accepts[]` (sessions
      become one adapter among several).
- [ ] Express the session method as a spec Adapter — sessions are the first
      real test that the seam holds for a stateful protocol (the in-flight
      open/voucher/commit/close lifecycle does not map 1:1 onto one
      `verifyAndSettle` call; likely needs an adapter-owned sub-route or a
      richer result type).
- [ ] `CommitReceipt` → align with the `Payment` noun (add `protocol`,
      `scheme`, `payer`, `settlement_headers`, `raw`).
- [ ] `Payment.payer` is currently `undefined` in the MPP adapter — the mppx
      receipt (`method/reference/status/timestamp`) does not expose the
      settling wallet. Needs a receipt extension upstream.
- [x] Framework shims over the dispatcher: `@solana/pay-kit/express`
      (Express/Connect, typed on `node:http`), `@solana/pay-kit/hono`
      (any `c.req.raw` framework), and `withPayment()` for fetch-style
      runtimes (Workers, Bun, Deno, Next.js).
