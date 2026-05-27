<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Ruby.
One gem, one surface, two protocols underneath: [x402](https://x402.org)
and the [Machine Payments Protocol](https://mpp.dev). Sinatra and Rails
sit on top of a pure Rack middleware.

You do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)]()
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)]()

## Quick start

```ruby
require "sinatra/base"
require "solana_pay_kit"

PayKit.configure do |c|
  c.mpp.challenge_binding_secret = ENV.fetch("MPP_SECRET")
end

class App < Sinatra::Base
  get("/report") { require_payment!(usd("0.10")); "ok" }
end
```

That is the whole demo. Zero-config boot uses the published demo
signer as recipient and fee-payer (the gem refuses to start with it
on `:solana_mainnet`); the gem auto-detects Sinatra and mounts the
`PayKit::Sinatra` helpers plus `PayKit::Rack::PaymentRequired`
middleware in both load orders.

Production apps name an operator, point at a private RPC, and lift
gate definitions into a `PayKit::Pricing` class - the full walkthrough
is below.

Three primitives, mirroring Clearance's `require_login` / `signed_in?` /
`current_user`:

| Method | Purpose |
|--------|---------|
| `require_payment! :gate_name` | bang form, halts with 402 if unpaid |
| `paid? :gate_name`            | predicate, never halts |
| `payment`                     | the verified `PayKit::Payment` proof, `nil` until paid |

## Vocabulary

| Term         | Meaning                                                              |
|--------------|----------------------------------------------------------------------|
| **gate**     | A protected unit. Has an amount, optional fees, accepted protocols.  |
| **amount**   | The base amount a gate charges, before any `fee_on_top`.             |
| **total**    | What the customer pays: `amount + sum(fee_on_top)`. Derived.         |
| **price**    | Value object returned by `usd(...)`: number + denom + settlement.    |
| **fee_within** | Fee taken out of the amount. `pay_to` recipient nets less.         |
| **fee_on_top** | Fee added to the amount. Customer pays more; `pay_to` nets full.   |
| **payment**  | Proof submitted by the client to pass a gate.                        |
| **protocol** | `:x402` or `:mpp` (top-level dispatch).                              |
| **scheme**   | x402 sub-form: `:exact`. MPP sub-form: `:charge`.                    |
| **accept**   | Ordered preference list (protocols and stablecoins both).            |
| **denom**    | Fiat unit a price is quoted in (`:USD`, `:EUR`).                     |
| **settlement** | On-chain asset that actually transfers (`:USDC`, `:USDT`).         |

## Gates

The `Pricing` class is the registry. Each gate is a frozen value object
with a fixed amount, an ordered list of accepted protocols, and zero or
more named fees.

```ruby
class Pricing < PayKit::Pricing
  SELLER   = "Ay..."
  PLATFORM = "CX..."
  GATEWAY  = "9r..."

  def build_gates
    # Simple. Customer pays $0.10, pay_to nets $0.10.
    gate :report, amount: usd("0.10"), description: "Premium report"

    # x402-only.
    gate :api_call, amount: usd("0.001"), accept: :x402

    # Stripe Connect "application fee" pattern. Customer pays $10.00,
    # SELLER nets $9.70, PLATFORM nets $0.30. x402 auto-disabled because
    # stock x402 facilitators settle to one address.
    gate :marketplace_sale,
      amount:     usd("10.00"),
      pay_to:     SELLER,
      fee_within: { PLATFORM => usd("0.30") }

    # Surcharge. Customer pays $10.50, SELLER nets $10.00, PLATFORM $0.50.
    gate :ticket,
      amount:     usd("10.00"),
      pay_to:     SELLER,
      fee_on_top: { PLATFORM => usd("0.50") }

    # Dynamic per-request pricing.
    gate :tiered do |request|
      amount usd(request.params["tier"] == "premium" ? "5.00" : "0.10")
    end
  end
end
```

Boot validations (all `PayKit::ConfigurationError`):

- `pay_to` is required (gate kwarg or `PayKit.config.pay_to`).
- Fee recipient must differ from `pay_to`. Fold the fee into the amount instead.
- All fee prices share one denomination with the amount.
- `sum(fee_within) <= amount`.
- `accept: :x402` on a fee-bearing gate raises (defense in depth above the silent strip).

## Inline pricing

For one-off endpoints that do not warrant a registry entry:

```ruby
get "/oneoff" do
  require_payment! usd("0.25"), description: "One-off"
  content_type :json
  JSON.generate(ok: true)
end
```

## Rack-first

The Sinatra helper is a thin shim over `PayKit::Rack::PaymentRequired`.
Rails uses the same middleware with `include PayKit::Controller` (a
generator scaffolds the initializer and pricing files). The Sinatra
auto-detect at gem boot calls `helpers PayKit::Sinatra` and
`use PayKit::Rack::PaymentRequired` on `Sinatra::Base` for you; you
only mount the middleware by hand when you bypass the helpers (raw
Rack, a non-Sinatra framework, or a hand-rolled controller layer).

```ruby
# Raw Rack
use PayKit::Rack::PaymentRequired
```

The middleware installs a per-request dispatcher on `env`, rescues
`PayKit::PaymentRequired` into 402, and merges settlement headers from
a verified `Payment` into the success response. Gate selection and
verification live in the helper, not the middleware. Long-lived state
that survives across requests (the x402 SettlementCache and the MPP
method cache keyed on recipient/currency/network/rpc/secret/realm
/expires_in/fee_payer) lives on the middleware instance, so two
requests through the same `use` line share both caches.

## Protocol compatibility

| Protocol  | Scheme        | Server | Notes |
|-----------|---------------|:------:|-------|
| `mpp`     | `charge/pull` | pass   | Full lifecycle: challenge, verify, broadcast, confirm, receipt. |
| `mpp`     | `charge/push` | pass   | Server fetches the on-chain transaction by signature, consumes through replay store. |
| `mpp`     | `session`     | ---    | Out of scope; mpp client/server session lives in the Rust spine for now. |
| `x402`    | `exact`       | pass   | Verifies the 11-rule spine verifier, broadcasts via the configured facilitator, namespaced replay key. |
| `x402`    | `upto`        | ---    | Pending the spine binding decision. |
| `x402`    | `batch`       | ---    | Pending the spine binding decision. |

This package ships server support only. Use a TypeScript, Rust, Go, or
Python client to drive payment flows against a Ruby-hosted endpoint.

## Example

[`examples/sinatra/`](examples/sinatra) is the runnable PayKit demo:
registry, opportunistic gating, inline form, dynamic pricing,
multi-recipient fees, before-filter, both protocols.

### Run it

```bash
cd ruby/examples/sinatra
bundle exec rackup -p 4567

curl  http://127.0.0.1:4567/report   # 402 + WWW-Authenticate Payment
pay curl http://127.0.0.1:4567/report # pays and succeeds
```

`pay curl` is available via `brew install pay`. The example boots
zero-config on the published demo signer (recipient = signer pubkey,
fee_payer = true). Override either via env:

```bash
PAY_KIT_PAY_TO="<your recipient>" \
PAY_KIT_OPERATOR_KEY="[1,2,...,64]" \
PAY_KIT_RPC_URL="https://api.devnet.solana.com" \
bundle exec rackup -p 4567
```

`PAY_KIT_OPERATOR_KEY` accepts the Solana CLI keypair JSON array, a
base58 string, or 128-char hex. `PayKit::Signer.env(name)` auto-detects
the format and treats unset/empty as no-op so partial overrides leave
the demo defaults in place.

## Coverage

```bash
cd ruby
just lint
just audit
just test-cover
```

`just test-cover` runs SimpleCov with line and branch coverage enabled,
enforces the local coverage gates, and refreshes the README badges from
`coverage/.resultset.json`.

Coverage gates:

- line coverage: at least 92 percent
- branch coverage: at least 90 percent

## Interop

The Ruby server has direct harness adapters at
[`harness/ruby-server/server.rb`](../harness/ruby-server/server.rb)
(MPP) and [`bin/x402-interop-server`](bin/x402-interop-server)
(x402 exact). Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=ruby pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=ruby pnpm test
X402_INTEROP_SERVERS=ruby-x402-server pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org)
plus the x402 exact scheme on Solana.

## Repo layout

```text
ruby/
├── lib/solana_pay_kit.rb       # Gem entry (require "solana_pay_kit")
├── lib/pay_kit/                # PayKit surface
│   ├── config.rb, pricing.rb, gate.rb, price.rb, fee.rb, ...
│   ├── protocols/{x402,mpp}.rb # Protocol adapters
│   └── rack/payment_required.rb
├── lib/mpp/                    # MPP layer (Mpp.create + protocol/server/sinatra)
│   ├── protocol/{core,intents,solana}/
│   └── server/{charge,middleware,decorator}.rb
├── lib/x402/                   # x402 layer (X402::Server::Exact)
│   ├── protocol/schemes/exact/
│   └── server/exact.rb
├── lib/pay_core/               # Shared Solana primitives (JCS, headers, base58, ...)
├── examples/sinatra/            # Runnable PayKit demo
└── test/                       # Minitest suite with line + branch coverage gates
```

## Coding convention

Standard Ruby plus the
[`skills.sh/mindrally/skills/ruby`](https://skills.sh/mindrally/skills/ruby)
best-practice skill. Small objects, explicit errors, deterministic wire
serialization, defensive payment verification, branch tests on
security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust spec wire format first, Ruby idioms second.

## License

MIT
