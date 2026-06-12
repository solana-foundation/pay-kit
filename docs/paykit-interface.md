# PayKit interface specification

A language-neutral specification of the PayKit SDK surface, derived from the
three most converged implementations (Ruby, Python, PHP). It defines one set of
nouns, one set of verbs, and one protocol-adapter seam so that x402 and MPP —
and any future payment protocol — stay invisible to application code.

The spec has three layers. Application developers only ever touch layer 1.

```
Layer 1  App surface        configure · Pricing/Gate · require_payment / paid? / payment
Layer 2  Protocol-agnostic  Dispatcher · Adapter contract · Challenge · Payment · Store
Layer 3  Protocols          x402 (exact, v1+v2) · MPP (charge) — never imported by apps
```

## Mental model

A **gate** is a priced unit of work attached to a route. When an unpaid request
hits a gate, the server answers `402` with a **challenge** that advertises every
acceptable way to pay (`accepts[]`: one entry per protocol). The client picks
one, attaches a credential to its retry, and the server verifies, settles
on-chain, and hands the handler a **payment** — a protocol-neutral receipt.
Application code never sees which protocol settled.

## Layer 1 — application surface

### Nouns

One canonical name per concept. Languages adapt casing only
(`pay_to` / `payTo` / `$payTo`), never the word.

| Concept | Name | Fields / notes |
|---|---|---|
| Boot config | `Config` | `network`, `accept`, `stablecoins`, `rpc_url`, `operator`, `x402`, `mpp`, `preflight` |
| Merchant identity | `Operator` | `recipient`, `signer`, `fee_payer` (bool) |
| Key material | `Signer` | static factory, see below |
| Denominated amount | `Price` | `currency`, `amount` (decimal string), `settlements` |
| Fee line | `Fee` | `recipient`, `price`, `kind: within \| on_top` |
| Priced unit | `Gate` | `name`, `amount`, `pay_to`, `accept`, `description`, `external_id`, `fees` |
| Gate catalogue | `Pricing` | named collection of gates |
| Verified receipt | `Payment` | `protocol`, `scheme`, `transaction`, `payer`, `gate_name`, `settlement_headers`, `raw` |
| 402 material | `Challenge` | `resource`, `accepts[]`, `headers` |
| Replay store | `Store` | `MemoryStore` (dev), `FileStore` (single host); interface for anything else |

Normative field decisions (these resolve current cross-SDK drift):

- **`Gate` carries `name` in every language.** PHP currently omits it and
  recovers it by reflection in `Pricing`; the name must be a first-class field
  because it appears in `Payment.gate_name` and in telemetry.
- **`Payment` gains `payer`** (the settling wallet address). All three
  protocols already know it at settlement time; today only the x402 response
  envelope exposes it.
- **`Payment.scheme`** is present everywhere (`exact` for x402, `charge` for
  MPP). Ruby has it; Python and PHP must add it.
- **`Store` is named `FileStore`**, not `FileReplayStore` (Python renames).

### Verbs — the trio

Three primitives, always these three, nothing else at layer 1:

| Canonical | Behavior |
|---|---|
| `require_payment(gate)` | Verify-or-halt. Returns `Payment` on success; raises/halts with a 402 challenge otherwise. |
| `paid?(gate)` | Predicate. Never halts, never settles a new payment — only reports whether this request already carries a verified payment for `gate`. |
| `payment()` | Accessor. The verified `Payment` for this request, or none. |

`gate` accepts the same union everywhere: a `Gate`, a gate name (string/symbol)
resolved against the configured `Pricing`, a bare `Price` (anonymous inline
gate), or a resolver function of the request (dynamic gate).

Per-language idiom:

| | Ruby | Python | PHP |
|---|---|---|---|
| verify-or-halt | `require_payment!(:report)` | `require_payment(request, "report")` / `Depends(RequirePayment("report"))` | `RequirePayment` PSR-15 middleware / `#[RequirePayment('report')]` attribute |
| predicate | `paid?(:report)` | `is_paid(request, "report")` | `paid($request, 'report')` |
| accessor | `payment` | `payment(request)` | `payment($request)` |

This collapses Python's `is_paid` / `is_paid_for` pair into one
`is_paid(request, gate=None)` — no gate argument means "any verified payment on
this request", which is what `is_paid` does today.

### Configuration

Canonical entry points, all three required in every SDK:

```
configure(network:, accept:, stablecoins:, rpc_url:, operator:, x402:, mpp:, preflight:)
configure_from_env(prefix = "PAY_KIT_")
config()        # read-only after boot
```

Ruby keeps its block form of `configure`; PHP exposes `Config::fromEnv()` and
`new Config(...)` (plus the Laravel/Symfony config files it already has) —
the names map, the shapes are idiomatic.

Canonical defaults (today they drift):

| Setting | Default |
|---|---|
| `network` | localnet |
| `accept` | `[x402, mpp]` — order is the advertised preference order |
| `stablecoins` | `[USDC]` — the supported set is `USDC, USDT, USDG, PYUSD, CASH` in every SDK |
| `operator.signer` | `Signer.demo` (refused on mainnet at boot) |
| `operator.fee_payer` | `true` |
| `mpp.realm` | `"App"` |
| `mpp.expires_in` | **120 seconds** (Ruby currently says 300 — align down) |
| `x402.scheme` | `"exact"` |
| `preflight` | `true` |

### Signer

One static factory, eight constructors, identical names everywhere:

```
Signer.demo  ·  Signer.file(path)  ·  Signer.env(name)  ·  Signer.json(str)
Signer.hex(str)  ·  Signer.base58(str)  ·  Signer.bytes(seq)  ·  Signer.generate
```

The signer contract (duck type / protocol / interface, per language):

```
pubkey() -> string          # base58
sign(message) -> bytes      # 64-byte Ed25519 signature
fee_payer?() -> bool
demo?() -> bool
```

KMS backends (`Kms.gcp / aws / vault`) are a reserved namespace returning the
same contract. Anything satisfying the contract is accepted wherever a signer
is accepted — this is the only extension point wallets need.

In TypeScript the contract is delivered by Solana Keychain: local
constructors ride on `@solana/keychain-memory`, and `Signer.from(...)` wraps
any `@solana/keychain-*` backend (AWS KMS, GCP KMS, Vault, Privy, Turnkey,
...), making the reserved KMS namespace real rather than stubbed.

### Pricing and gates

A `Pricing` is a named, boot-frozen collection of gates. Each language uses its
natural declaration style — Ruby a DSL, Python and PHP class attributes — but
the gate fields and semantics are identical:

```ruby
gate :marketplace,
  amount:     usd("10.00"),
  pay_to:     SELLER,
  fee_within: { PLATFORM => usd("0.30") },   # taken out of amount
  fee_on_top: { PLATFORM => usd("0.50") },   # added to the customer total
  accept:     :mpp,
  description: "Marketplace sale"
```

Gate methods, everywhere: `total()` (amount + on-top fees), `payout(address)`,
`has_fees()`, `accepts?(protocol)`.

`accepts?(protocol)` replaces the per-protocol predicates (`x402_accepted?`,
`mpp_accepted?`) so adding a protocol never grows the `Gate` API.

**Dynamic gates** are one shape in all languages: a function of the request
that returns a `Gate` or a `Price`. Ruby's block DSL, Python's
`@pay_kit.gate("name")` decorator, and PHP's closure are surface sugar over
that single shape.

**Fee/protocol interaction is a rule, not a surprise:** a gate with fees and an
explicit `accept` including x402 fails at boot
(`ProtocolIncompatibleError`); a gate with fees and inherited `accept`
silently narrows to MPP. Same rule, every SDK.

### Errors

One taxonomy; languages add only their conventional suffix
(`InvalidProof` / `InvalidProofError` / `InvalidProofException`):

```
PayKitError
├── ConfigurationError               # boot
│   ├── DemoSignerOnMainnetError
│   ├── MixedCurrenciesError
│   ├── ProtocolIncompatibleError
│   └── UnknownGateError
├── InvalidKeyError                  # signer parsing
├── PaymentRequiredError             # http 402 — no proof; carries Challenge
├── InvalidProofError                # http 402 — bad proof; carries code
│   └── ChallengeExpiredError
└── ProtocolNotSupportedError        # http 406
```

`InvalidProofError.code` is a canonical machine string shared across SDKs and
asserted by the conformance suite (`charge_request_mismatch`,
`signature_consumed`, `challenge_expired`, …). The Python list is the
reference; Ruby's `spec_code` and PHP's codes align to it.

## Layer 2 — the protocol seam

This is the whole abstraction. Both x402 and MPP are instances of one loop:

```
challenge (402) → client credential → verify → settle → receipt headers (2xx)
```

so a protocol is exactly one object implementing the **Adapter contract**:

```
detect?(request)                 -> bool       # does this request carry my credential?
accepts_entry(gate, request)     -> dict       # my entry in the 402 accepts[] array
challenge_headers(gate, request) -> headers    # my protocol-specific 402 headers
verify_and_settle(gate, request) -> Payment    # or raise InvalidProofError
```

All three SDKs already implement this contract internally; the spec makes it
the *public* extension point. The **Dispatcher** (the per-request object the
middleware installs) is pure mechanism and identical everywhere:

1. Resolve the gate reference (name → registry, price → anonymous gate,
   function → call it).
2. Ask each accepted adapter `detect?`; at most one may claim a request.
3. If none claims it: build a `Challenge` by collecting every adapter's
   `accepts_entry` + `challenge_headers`, render 402.
4. If one claims it: `verify_and_settle`, stash the `Payment` on the request,
   merge `settlement_headers` into the 2xx response.

Adding a protocol (sessions, subscriptions, an EVM scheme) is then: write an
adapter, register it in `accept`. No change to `Gate`, the trio, or any
framework shim.

The shared **wire invariants** the adapters must honor (already true, now
normative):

- `accepts[]` entries always carry `protocol`, `scheme`, `network` (CAIP-2),
  `amount` (base-unit integer string), `payTo`.
- x402: `Payment-Required` / `Payment-Signature` / `Payment-Response` headers
  (v2), with `X-Payment` v1 accepted on read; scheme `exact`; extensions echoed.
- MPP: `WWW-Authenticate: Payment …` challenge, `Authorization: Payment …`
  credential; intent `charge`; HMAC-bound stateless challenges.
- Both: settlement mirrored in `x-payment-settlement-signature`.

## Layer 3 — protocols and the client side

Protocol packages (`protocols/x402`, `protocols/mpp`) are implementation
detail on the server: applications must never need an import from them. The
test is simple — if a README snippet mentions `x402` or `mpp` outside of
`configure(accept: ...)` and `Gate(accept: ...)`, the abstraction has leaked.

**Client surface** (paying for requests) is a separate, optional tier. Python
ships one today; Ruby and PHP do not. When an SDK ships it, the canonical
shape wraps the language's standard HTTP client and handles both protocols
behind one factory:

```
client = PayKit.client(signer:, rpc_url:)   # wraps httpx / Faraday / PSR-18
resp   = client.get(url)                    # transparently answers 402s
resp.payment                                # Payment receipt, same noun as server side
```

Python's current `x402_async_client(signer, rpc)` is protocol-named and
x402-only; it becomes `pay_kit.client(...)` with protocol selection driven by
the server's `accepts[]`, preferring the first entry the client can satisfy.
The protocol-level builders (`parse_challenge`, `build_payment_header`,
`build_credential_header`) remain available under `protocols/` for power users.

## Migration deltas

What each SDK changes to meet this spec. Everything not listed is already
conformant.

**Ruby**
- `mpp.expires_in` default 300 → 120.
- Add `accepts?(protocol)` on `Gate`; keep `x402_accepted?` / `mpp_accepted?`
  as deprecated aliases for one release.
- Add `payer` and ensure `scheme` on `Payment`.
- Add `PayKit.configure_from_env`.
- Stablecoin set: add `USDG`, `CASH`.
- Wire `external_id` through every flow (currently inconsistent).

**Python**
- Collapse `is_paid` / `is_paid_for` → `is_paid(request, gate=None)`.
- Rename `FileReplayStore` → `FileStore` (alias for one release).
- Rename `x402_async_client` / `X402Client` → `pay_kit.client(...)`; make it
  protocol-agnostic (MPP charge support behind the same transport).
- Move `seconds/minutes/hours/...` expiry helpers out of the top-level
  exports (they are MPP internals masquerading as core).
- Type `PaymentRequiredError.challenge` properly instead of stashing
  `challenge_headers` / `body` as untyped attributes.
- Add `payer` and `scheme` to `Payment`.
- Drop the deprecated `configure()` kwargs (`pay_to`, `facilitator`,
  `facilitator_secret_key`, `secret`) on the next minor.

**PHP**
- Add `name` to `Gate`; `Pricing` injects it from the property name at
  construction instead of reflecting at lookup.
- Add the imperative trio (`require_payment` / `paid` / `payment` helper
  functions over the request attribute) so non-middleware code paths exist,
  matching Ruby and Python.
- Add `Config::fromEnv()`.
- Add `accepts(Protocol $p): bool` on `Gate`.
- Add `payer` to `Payment`.
- Simplify `MppConfig::resolveExpiresIn` (plain int + dedicated
  `EXPIRES_NEVER = 0` constant).
- Expose `gate->feeWithin()` / `gate->feeOnTop()` accessors instead of making
  callers filter `fees` by kind (then mirror these in Ruby and Python).

## Conformance

The cross-SDK contract is enforced, not aspirational: the conformance suites
(`ruby/conformance`, `python/*conformance_runner.py`, `php/conformance`)
assert the wire invariants, the canonical error codes, and the default table
above. A new SDK is "done" when it passes conformance, ships the layer-1
surface verbatim, and implements the Adapter contract for both protocols.
