<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-ruby-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-ruby-light.png">
    <img alt="Solana pay-kit — Ruby" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-ruby-light.png">
  </picture>
</div>

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Ruby.
One gem, one surface, two protocols underneath: [x402](https://x402.org)
and the [Machine Payments Protocol](https://paymentauth.org). Sinatra and
Rails ride on top of a pure Rack middleware.

[![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)]()
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)]()

---

## Quick start

Three progressively-realistic snippets. Each one runs as-is — copy, paste,
hit the URL. Sinatra is the framework here; the same surface works in
Rails and bare Rack.

### 1. Smallest possible app

Gate one route with an inline price. Save the snippet as `config.ru`
and boot with `bundle exec rackup`. Zero-config: the gem uses a
published demo keypair as the recipient and the hosted Surfpool
sandbox at `https://402.surfnet.dev:8899` as the RPC.

```ruby
# config.ru
require "sinatra/base"
require "solana_pay_kit"

class App < Sinatra::Base
  get("/report") do
    require_payment! usd("0.10")
    "premium content"
  end
end

run App
```

`require "solana_pay_kit"` auto-detects Sinatra and mounts the helpers
plus middleware. `require_payment!` halts the request with a 402 if no
valid payment was sent, or returns the verified proof if one was.

Hit `/report` with [`pay curl`](#run-the-example) and the customer walks
through Touch ID and a USDC payment.

### 2. Multiple gates via a registry

When more than one route is paid, lift the prices into a single
`PayKit::Pricing` class — the same pattern as CanCanCan's `Ability` or
Clearance's `current_user`. Routes reference gates by symbol.

```ruby
# config.ru
require "sinatra/base"
require "solana_pay_kit"

class Pricing < PayKit::Pricing
  def build_gates
    gate :report,   amount: usd("0.10"), description: "Premium report"
    gate :api_call, amount: usd("0.001"), accept: :x402
  end
end
PayKit.pricing = Pricing.new

class App < Sinatra::Base
  get("/report")    { require_payment! :report;   "premium content" }
  get("/api/data")  { require_payment! :api_call; '{"data":[]}' }
end

run App
```

Gates are validated at boot — wrong currency, missing recipient,
fee math that doesn't add up — so configuration errors surface before
any traffic. `accept:` is an allowlist; the `:api_call` gate here
refuses to settle over MPP.

### 3. Production-shape config

Snippet 2's demo recipient and public Sandbox Network are fine for poking
around. Production wants explicit keys, a dedicated RPC, and a list of
accepted stablecoins. The Sinatra app is unchanged — only the
`PayKit.configure` block grows.

```ruby
# config.ru — same `class App < Sinatra::Base` block as snippet 2.
require "sinatra/base"
require "solana_pay_kit"

PLATFORM = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

PayKit.configure do |c|
  c.network     = :solana_mainnet
  c.stablecoins = %i[USDC PYUSD]
  c.operator do |op|
    op.signer = PayKit::Signer.file("config/operator.json")
  end
  c.rpc_url = "https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY"
end

class Pricing < PayKit::Pricing
  def build_gates
    gate :report, amount: usd("0.10"), description: "Premium report"

    # Platform-fee pattern: 
    # Customer pays $10.00,
    # Operator nets $9.70, PLATFORM nets $0.30.
    gate :marketplace_sale,
      amount:     usd("10.00"),
      fee_within: { PLATFORM => usd("0.30") }
  end
end
PayKit.pricing = Pricing.new
```

Two safety rails fire at boot:

- `:solana_mainnet` plus the published demo signer raises — no real
  funds get routed to a publicly known address by accident.
- Missing `c.mpp.challenge_binding_secret`? Preflight generates one
  and writes it to `./.env` so the HMAC stays stable across restarts.
  Override via `PAY_KIT_MPP_CHALLENGE_BINDING_SECRET` to control it
  from your secret manager.

---

## Run the example

Two runnable demos:
[`examples/simple-server/`](examples/simple-server) is the smallest
possible app (plain Rack, one gated endpoint), and
[`examples/sinatra/`](examples/sinatra) shows the registry, inline
pricing, dynamic pricing, and multi-recipient fees across both
protocols.

**Boot the server:**

```bash
git clone https://github.com/solana-foundation/pay-kit
cd ruby/examples/sinatra
bundle install
bundle exec rackup -p 4567
```

The server logs preflight output as it boots — it provisions the demo
recipient's USDC account on Surfpool via cheatcodes the first time,
then settles real on-chain payments after that.

**Consume with `pay curl`:**

```bash
# Install the pay CLI:
brew install pay
# or npm install -g @solana/pay

# Fail with 402 - payment required
curl -i http://127.0.0.1:4567/report

# Succeed with 200 - payment provided
pay curl -i http://127.0.0.1:4567/report
```

---

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required` as a
client-server payment handshake. Your server gates a route; a paying
client receives the 402 with payment instructions, signs a Solana
transaction off-chain, and replays the same request with a
`PAYMENT-SIGNATURE` header. The Ruby server verifies the signature,
broadcasts the transaction, and returns the original response with a
`PAYMENT-RESPONSE` header carrying the on-chain settlement signature.

x402 is **single-recipient by design**: the server's facilitator pays
the network fees, the customer's signed transaction settles funds to
`pay_to`. Gates with `fee_within:` or `fee_on_top:` recipients
auto-disable x402 because stock x402 facilitators settle to one
address.

Supported on the Ruby server:

| Intent             | Status |
|--------------------|--------|
| `exact`            | ✅      |
| `upto`             | —      |
| `batch-settlement` | —      |

## MPP

The [Machine Payments Protocol](https://paymentauth.org) is the broader
HTTP Payment Authentication scheme — same 402 handshake, but the
challenge carries a richer intent shape that supports multi-recipient
splits, server-side fee accounting, and a separate fee-payer signer.

Use MPP when:
- Your gate has a platform or gateway fee (Stripe-Connect "application
  fee" pattern).
- You want the server to subsidize the customer's network fee.
- You want one challenge per gate instead of per-mint-quoted offers.

Supported on the Ruby server:

| Intent         | Status |
|----------------|--------|
| `charge/pull`  | ✅      |
| `charge/push`  | ✅      |
| `session`      | —      |
| `subscription` | —      |

---

## Server-only

This gem ships **server support only**. The pay-kit server emits
challenges, verifies proofs, and broadcasts settlement transactions —
it does not pay. Drive the client side from:

- `pay curl` ([install](https://github.com/solana-foundation/pay))
- The Rust, TypeScript, Go, or Python pay-kit client SDKs

---

## Vocabulary

| Term         | Meaning |
|--------------|---------|
| **gate**     | A protected unit. Has an amount, optional fees, accepted protocols. |
| **amount**   | The base amount a gate charges, before any `fee_on_top`. |
| **total**    | What the customer pays: `amount + sum(fee_on_top)`. Derived. |
| **price**    | Value object returned by `usd(…)`: number + currency + settlement. |
| **fee_within** | Fee taken out of the amount. `pay_to` nets less. |
| **fee_on_top** | Fee added to the amount. Customer pays more; `pay_to` nets full. |
| **payment**  | Proof submitted by the client to pass a gate. |
| **protocol** | `:x402` or `:mpp` (top-level dispatch). |
| **scheme**   | x402 sub-form: `:exact`. MPP sub-form: `:charge`. |
| **accept**   | Ordered preference list (protocols and stablecoins both). |
| **currency** | Fiat unit a price is quoted in (`:USD`, `:EUR`). |
| **settlement** | On-chain asset that actually transfers (`:USDC`, `:USDT`). |

## Three primitives

Mirrors Clearance's `require_login` / `signed_in?` / `current_user`:

| Method | Purpose |
|--------|---------|
| `require_payment! :gate_name` | Bang form, halts with 402 if unpaid |
| `paid? :gate_name`            | Predicate, never halts |
| `payment`                     | The verified `PayKit::Payment` proof, `nil` until paid |

## Inline pricing

For one-off endpoints that don't warrant a registry entry, skip the
gate name and pass a price directly:

```ruby
get "/oneoff" do
  require_payment! usd("0.25"), description: "One-off"
  content_type :json
  JSON.generate(ok: true)
end
```

## Gate DSL

Each gate is a frozen value object with an amount, an ordered list of
accepted protocols, and zero or more named fees.

```ruby
class Pricing < PayKit::Pricing
  SELLER   = "Ay…"
  PLATFORM = "CX…"

  def build_gates
    # Simple. Customer pays $0.10, pay_to nets $0.10.
    gate :report, amount: usd("0.10"), description: "Premium report"

    # x402-only.
    gate :api_call, amount: usd("0.001"), accept: :x402

    # Stripe-Connect "application fee". Customer pays $10.00,
    # SELLER nets $9.70, PLATFORM nets $0.30. x402 auto-disabled.
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

Boot-time validations (all raise `PayKit::ConfigurationError`):

- `pay_to` is required (gate kwarg or `c.operator.recipient`).
- Fee recipient must differ from `pay_to`. Fold the fee into the amount instead.
- All fee prices share one currency with the amount.
- `sum(fee_within) <= amount`.
- `accept: :x402` on a fee-bearing gate raises.

## Rack-first

The Sinatra helper is a thin shim over `PayKit::Rack::PaymentRequired`.
Rails uses the same middleware with `include PayKit::Controller` (a
generator scaffolds the initializer and pricing files). The auto-detect
at gem boot calls `helpers PayKit::Sinatra` and `use PayKit::Rack::PaymentRequired`
on `Sinatra::Base` for you. You only mount the middleware by hand when
bypassing the helpers — raw Rack, a non-Sinatra framework, or a
hand-rolled controller layer.

```ruby
# Raw Rack
use PayKit::Rack::PaymentRequired
```

The middleware installs a per-request dispatcher on `env`, rescues
`PayKit::PaymentRequired` into 402, and merges settlement headers
from a verified `Payment` into the success response. Long-lived state
that survives across requests (the x402 settlement cache, the MPP
method cache) lives on the middleware instance, so requests through
the same `use` line share both caches.

---

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

Gates:

- Line coverage: at least 92 percent
- Branch coverage: at least 90 percent

## Harness

The Ruby server has direct harness adapters at
[`harness/ruby-server/server.rb`](../harness/ruby-server/server.rb) (MPP)
and [`harness/ruby-x402-server/server.rb`](../harness/ruby-x402-server/server.rb) (x402 exact).
Focused harness commands:

```bash
cd harness
MPP_HARNESS_CLIENTS=typescript MPP_HARNESS_SERVERS=ruby pnpm test
MPP_HARNESS_CLIENTS=rust       MPP_HARNESS_SERVERS=ruby pnpm test
X402_HARNESS_SERVERS=ruby-x402-server pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org),
plus the x402 exact scheme on Solana.

---

## Repo layout

```text
ruby/
├── lib/solana_pay_kit.rb           # Gem entry (require "solana_pay_kit")
├── lib/pay_core/                   # PayCore: protocol-agnostic primitives
│   ├── base64_url.rb, json.rb, headers.rb, rfc3339_parser.rb, error_codes.rb
│   └── solana/                     # base58, ata, mints, programs, rpc, transaction
├── lib/pay_kit/                    # PayKit umbrella: the one public surface
│   ├── config.rb, pricing.rb, gate.rb, price.rb, fee.rb, operator.rb, …
│   ├── preflight.rb                # Boot-time soundness check + autobootstrap
│   ├── rack/payment_required.rb    # Rack middleware + dispatcher
│   └── protocols/                  # Protocol layer (server-only)
│       ├── protocols.rb            # ProtocolRef
│       ├── mpp.rb, x402.rb         # Gate adapters (MppAdapter, X402Adapter)
│       ├── mpp/                    # MPP protocol: protocol/{core,intents,solana}, server
│       └── x402/                   # x402 protocol: protocol/schemes/exact, server
├── examples/simple-server/         # Plain-Rack demo, one gated endpoint
├── examples/sinatra/               # Sinatra demo (registry, fees, dynamic pricing)
└── test/                           # Minitest suite mirroring the lib tiers
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
