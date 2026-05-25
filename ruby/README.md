<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, …) for any HTTP endpoint, in Ruby.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
don't need to know anything about Solana to use this library — pick a
currency, give it your wallet address, and gate a route in two lines.

[![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)]()
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)]()

## Repo layout

```text
ruby/
├── lib/mpp.rb                # Top-level Mpp.create factory
├── lib/mpp/methods/solana/   # Solana charge method (RPC, account, verifier, mints)
├── lib/mpp/server/           # Server::Instance, Middleware, Decorator
├── lib/mpp/sinatra.rb        # Optional Sinatra helper (mpp_charge!)
├── lib/mpp/core/             # Payment headers, credentials, receipts, base64url JSON
├── examples/                 # Simple server and Sinatra app examples
└── test/                     # Minitest suite with line and branch coverage gates
```

## Quick start — server

```ruby
require "mpp"

server = Mpp.create(
  method: Mpp::Methods::Solana.charge(
    recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
    currency: "USDC",
    network: "localnet",
    rpc: "https://402.surfnet.dev:8899"
  ),
  secret_key: "local-dev-secret",
  realm: "Ruby MPP Example"
)

# In your request handler (WEBrick, Sinatra, Rails, Rack, etc.):
result = server.charge(authorization_header, amount: "1000", description: "Paid endpoint")

case result
when Mpp::Challenge
  status, headers, body = Mpp::Server::Decorator.make_challenge_response(result, server.realm)
  # render 402
when Mpp::Settlement
  # result.signature       — on-chain transaction signature
  # result.receipt_header  — Payment-Receipt header value
  # result.headers         — merge these into your 200 response
end
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`, or `"CASH"` —
the SDK looks up the mint address, token program, and decimals from a built-in
table. You can also pass a raw mint pubkey for tokens not in the table.

For an endpoint that accepts a different currency per request, pass `currency:`
to `server.charge`:

```ruby
result = server.charge(auth, amount: "1000", description: "...", currency: "USDT")
```

The method object owns every static knob (recipient, default currency, network,
RPC, optional fee payer). Per-request you only pass `amount` and `description`.
The blockhash is fetched lazily and cached for 2 seconds inside the method so a
busy endpoint doesn't pay an RPC round-trip on every protected request.

### Rack middleware

```ruby
use Mpp::Server::Middleware, handler: server

get "/paid" do
  env["mpp.charge"] = { amount: "1000", description: "Paid endpoint" }
  content_type :json
  JSON.generate(ok: true)
end
```

The middleware lets routes declare their own price by setting `env["mpp.charge"]`
before returning. If the request hasn't paid, the middleware replaces the
response with a 402 challenge; if it has paid, the middleware settles on-chain
and injects the receipt and signature headers into the route's response.

### Sinatra helper

For expensive routes that shouldn't run before payment is verified, use the
`mpp_charge!` helper, which halts with 402 immediately on a missing/invalid
credential:

```ruby
require "mpp/sinatra"

class App < Sinatra::Base
  helpers Mpp::Sinatra::Helpers
  set :mpp_server, server

  get "/paid" do
    mpp_charge!(amount: "1000", description: "Paid endpoint")
    # only reached on successful payment; receipt header auto-injected
    content_type :json
    JSON.generate(ok: true)
  end
end
```

## Running the examples

```bash
cd ruby
bundle install

# Bare WEBrick server, manual case/when on Challenge/Settlement
bundle exec ruby examples/simple-server/app.rb

# Sinatra app using mpp_charge!
PORT=4568 bundle exec ruby examples/sinatra/app.rb
```

In another terminal:

```bash
brew install pay
curl http://localhost:4567/paid       # 402 payment required
pay curl http://localhost:4567/paid   # pays and succeeds
```

The simple server defaults to Surfpool localnet (`https://402.surfnet.dev:8899`),
`USDC`, and a local example recipient. Override `MPP_RPC_URL`, `MPP_CURRENCY`,
`MPP_PAY_TO`, `MPP_AMOUNT`, or `MPP_FEE_PAYER_SECRET_KEY` for a different
localnet fixture.

## Client compatibility matrix

Ruby is server-side only for the current MPP roadmap.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | — |
| `mpp/charge/push` | — |
| `mpp/session` | — |
| `mpp/subscription` | — |

## Server compatibility matrix

Split into two phases because an MPP server first verifies the credential and
then settles or confirms the payment on-chain.

| Intent | Status |
|---|:---:|
| `x402/exact` | — |
| `x402/upto` | — |
| `x402/batch-settlement` | — |
| `mpp/charge/pull` | ✅ |
| `mpp/charge/push` | ✅ |
| `mpp/session` | — |
| `mpp/subscription` | — |

For `mpp/charge/pull`: the server owns the full lifecycle — issue signed
challenges with a fresh `recentBlockhash`, parse and validate the
`Authorization: Payment` credential, pin the echoed charge request, decode the
client-signed transaction and check recipient/amount/mint/splits/ATA/memos/
compute budget, reject Surfpool-signed transactions on non-localnet networks,
optionally fee-payer co-sign, broadcast via `sendTransaction`, poll
`getSignatureStatuses` to `confirmed`/`finalized`, and emit `payment-receipt`
with the on-chain signature.

For `mpp/charge/push`: the server fetches the transaction by signature with
`getTransaction`, rejects failed or missing metadata, reuses the same structural
transaction verifier as pull mode, consumes the signature through replay
storage, and emits the same receipt shape.

The direct Ruby interop server at
[`tests/interop/ruby-server/server.rb`](../tests/interop/ruby-server/server.rb)
exercises this end-to-end through Surfpool in CI for both TypeScript and Rust
clients.

## Examples

Two examples ship with this package:

- [`examples/simple-server/`](examples/simple-server) — bare WEBrick
  server that calls `server.charge` directly and renders the
  `Mpp::Challenge` / `Mpp::Settlement` tagged union by hand.
- [`examples/sinatra/`](examples/sinatra) — Sinatra app using the
  `mpp_charge!` helper, split into `config.rb` (env defaults), `server.rb`
  (the `Mpp.create` factory call), and `app.rb` (Sinatra routes).

Both expose `/health` (free) and `/paid` (gated). Use the interop harness for
the full Surfpool-backed transaction flow.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `ed25519` | fee-payer transaction signing and PDA curve checks | `~> 1.4` |
| `rack` | Rack integration surface used by Ruby web frameworks | `~> 3.1` |
| `rackup` | Rack server launcher required by Sinatra 4 | `~> 2.2` |
| `puma` | local Sinatra example server handler | `~> 7.1` |
| `sinatra` | runnable local Sinatra app example | `~> 4.2` |
| `webrick` | runnable local simple-server example | `~> 1.8` |
| internal Base58 helper | avoid extra runtime dependency for account/signature encoding | in package |
| internal canonical JSON helper | RFC 8785-style sorted JSON before base64url | in package |

The Ruby server keeps Solana dependencies intentionally small. It parses legacy
and v0 transaction messages, verifies transfer instructions structurally, signs
optional fee-payer pull transactions, and uses JSON-RPC directly for
simulation, submission, confirmation, and push-mode transaction lookup.

## Coding convention

This SDK follows Standard Ruby and the
[`skills.sh/mindrally/skills/ruby`](https://skills.sh/mindrally/skills/ruby)
best-practice skill selected for this PR. The implementation pass focuses on
small objects, explicit errors, deterministic wire serialization, defensive
payment verification, and branch/condition tests on security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol source of
truth: Rust/spec wire format first, Ruby idioms second. Stripe's `mpp-rb`
package layout was used as Ruby ecosystem inspiration, not as protocol source
truth.

## Code coverage

```bash
cd ruby
just lint
just audit
just test-cover
```

`just test-cover` runs SimpleCov with line and branch coverage enabled, enforces
the local coverage gates, and refreshes the README badges from
`coverage/.resultset.json`.

Coverage gates:

- line coverage: at least 92 percent
- branch coverage: at least 90 percent

The branch gate is still meaningful because the branch tests cover the payment
verifier's critical decisions: valid/invalid credentials, cross-route replay,
split accounting, ATA creation, compute budget limits, fee-payer abuse, pull
settlement, push settlement, transaction failures, missing metadata, timeouts,
and replay consumption.

## Interop

The Ruby server has a direct harness adapter at
`tests/interop/ruby-server/server.rb`. It is server-side only in this pass.

Focused harness commands:

```bash
cd tests/interop
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=ruby pnpm test
MPP_INTEROP_CLIENTS=rust MPP_INTEROP_SERVERS=ruby pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
