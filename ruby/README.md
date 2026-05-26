<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Ruby.
Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev) and serves as a Sinatra / Rack /
Rails-friendly building block for `402 Payment Required` flows.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)]()
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)]()

## Quick start

Gate a Sinatra route in two lines using the `mpp_charge!` helper from
[`examples/sinatra/app.rb`](examples/sinatra/app.rb):

```ruby
require "mpp"
require "mpp/sinatra"

class App < Sinatra::Base
  helpers Mpp::Sinatra::Helpers
  set :mpp_server, Mpp.create(
    method: Mpp::Methods::Solana.charge(
      recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
      currency: "USDC",
      network: "localnet",
      rpc: "https://402.surfnet.dev:8899"
    ),
    secret_key: "local-dev-secret",
    realm: "Ruby MPP Example"
  )

  get "/paid" do
    mpp_charge!(amount: "1000", description: "Paid endpoint")
    content_type :json
    JSON.generate(ok: true)
  end
end
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address, token program, and
decimals from a built-in table. You can also pass a raw mint pubkey for
tokens not in the table.

The method object owns every static knob (recipient, default currency,
network, RPC, optional fee payer). Per-request you only pass `amount` and
`description`. The blockhash is fetched lazily and cached for 2 seconds
inside the method so a busy endpoint does not pay an RPC round-trip on
every protected request.

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
before returning. If the request has not paid, the middleware replaces the
response with a 402 challenge; if it has paid, the middleware settles on-chain
and injects the receipt and signature headers into the route's response.

## Protocol compatibility matrix

### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | --- | pass |
| `mpp/charge/push` | --- | pass |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | --- | --- |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |

This package ships server support only. Use a TypeScript, Rust, Go, or
Python client to drive payment flows against a Ruby-hosted endpoint.

For `mpp/charge/pull`: the server owns the full lifecycle. It issues
signed challenges with a fresh `recentBlockhash`, parses and validates
the `Authorization: Payment` credential, pins the echoed charge request,
decodes the client-signed transaction and checks recipient, amount,
mint, splits, ATA, memos, and compute budget, rejects Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-signs,
broadcasts via `sendTransaction`, polls `getSignatureStatuses` to
`confirmed` / `finalized`, and emits `payment-receipt` with the on-chain
signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature through replay storage, and emits the same receipt shape.

## Examples

Two runnable examples ship with this package:

- [`examples/simple-server/`](examples/simple-server) - bare WEBrick
  server that calls `server.charge` directly and renders the
  `Mpp::Challenge` / `Mpp::Settlement` tagged union by hand.
- [`examples/sinatra/`](examples/sinatra) - Sinatra app using the
  `mpp_charge!` helper.

### Run the Sinatra example

```bash
cd ruby
bundle install
bundle exec ruby examples/sinatra/app.rb     # listens on 127.0.0.1:4568
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:4568/paid       # 402 payment required
pay curl http://127.0.0.1:4568/paid    # pays and succeeds
```

The simple-server example defaults to Surfpool localnet
(`https://402.surfnet.dev:8899`), `USDC`, and a local example recipient.
Override `MPP_RPC_URL`, `MPP_CURRENCY`, `MPP_PAY_TO`, `MPP_AMOUNT`, or
`MPP_FEE_PAYER_SECRET_KEY` for a different localnet fixture.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `ed25519` | fee-payer transaction signing and PDA curve checks | `~> 1.4` |
| `rack` | Rack integration surface used by Ruby web frameworks | `~> 3.1` |
| `rackup` | Rack server launcher required by Sinatra 4 | `~> 2.2` |
| `puma` | local Sinatra example server handler | `~> 7.1` |
| `sinatra` | runnable local Sinatra app example | `~> 4.2` |
| `webrick` | runnable local simple-server example | `~> 1.8` |
| internal Base58 helper | account / signature encoding without a runtime dependency | in package |
| internal canonical JSON helper | RFC 8785-style sorted JSON before base64url | in package |

The Ruby server keeps Solana dependencies intentionally small. It parses
legacy and v0 transaction messages, verifies transfer instructions
structurally, signs optional fee-payer pull transactions, and uses
JSON-RPC directly for simulation, submission, confirmation, and push-mode
transaction lookup.

## Coding convention

This SDK follows Standard Ruby and the
[`skills.sh/mindrally/skills/ruby`](https://skills.sh/mindrally/skills/ruby)
best-practice skill. The implementation pass focuses on small objects,
explicit errors, deterministic wire serialization, defensive payment
verification, and branch / condition tests on security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol source
of truth: Rust / spec wire format first, Ruby idioms second.

## Code coverage

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

The Ruby server has a direct harness adapter at
[`harness/ruby-server/server.rb`](../harness/ruby-server/server.rb).
Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=ruby pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=ruby pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

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

## License

MIT
