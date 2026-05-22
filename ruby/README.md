<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-mpp

Solana payment method for the [Machine Payments Protocol](https://mpp.dev),
for Ruby.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow.

[![Ruby](https://img.shields.io/badge/ruby-3.2%2B-red)]()
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)]()

## Repo layout

```text
ruby/
├── lib/solana_mpp/core/       # Payment headers, credentials, receipts, base64url JSON
├── lib/solana_mpp/intent/     # Charge intent request model
├── lib/solana_mpp/server/     # 402 challenge issuance, verification, settlement
├── lib/solana_mpp/solana/     # Minimal Solana parser, signer, RPC, ATA helpers
├── examples/                  # Simple server and Sinatra app examples
└── test/                      # Minitest suite with line and branch coverage gates
```

## Quick start — server (charge)

```ruby
require "json"
require "solana_mpp"

rpc = SolanaMpp::Solana::RpcClient.new("https://402.surfnet.dev:8899")
challenges = SolanaMpp::Server::ChargeServer.new(
  secret_key: "local-dev-secret",
  realm: "Ruby MPP Example"
)
handler = SolanaMpp::Server::ChargeHandler.new(
  challenges: challenges,
  rpc: rpc,
  replay_store: SolanaMpp::MemoryStore.new,
  network: "localnet"
)
request = SolanaMpp::Intent::ChargeRequest.new(
  amount: "1000",
  currency: "USDC",
  recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
  method_details: {
    "network" => "localnet",
    "decimals" => 6,
    "tokenProgram" => SolanaMpp::Common::StablecoinMints.token_program_for("USDC", "localnet"),
    "recentBlockhash" => rpc.latest_blockhash
  }
)

result = handler.handle(ENV["HTTP_AUTHORIZATION"], request)
puts result.status
puts JSON.generate(result.body)
```

`SolanaMpp::Server::ChargeHandler#handle` returns either a
`PaymentRequiredResponse` (402, missing/invalid credential) or a
`ChargeSettlement` (200, with the on-chain signature). Both expose the same
`status` / `headers` / `body` shape so the HTTP layer can project either path
uniformly.

## Quick start

Launch the bare Ruby server from `examples/simple-server.rb`:

```bash
# Install dependencies
bundle install

# Launch server
bundle exec ruby examples/simple-server.rb
```

In another terminal, send requests using `curl` and `pay`:

```bash
brew install pay

# payment required
curl http://localhost:4567/paid

# payment successful
pay curl http://localhost:4567/paid
```

For a Sinatra integration that wires the same SDK handler into a web app, see
[`examples/sinatra-app.rb`](examples/sinatra-app.rb).

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

For `mpp/charge/pull`: `ChargeHandler` owns the full lifecycle — issue signed
challenges with a fresh `recentBlockhash`, parse and validate the
`Authorization: Payment` credential, pin the echoed `ChargeRequest`, decode the
client-signed transaction and check recipient/amount/mint/splits/ATA/memos/
compute budget, reject Surfpool-signed transactions on non-localnet networks,
optionally fee-payer co-sign, broadcast via `sendTransaction`, poll
`getSignatureStatuses` to `confirmed`/`finalized`, and emit `payment-receipt`
with the on-chain signature.

For `mpp/charge/push`: the handler fetches the transaction by signature with
`getTransaction`, rejects failed or missing metadata, reuses the same structural
transaction verifier as pull mode, consumes the signature through replay
storage, and emits the same receipt shape.

The direct Ruby interop server at
[`tests/interop/ruby-server/server.rb`](../tests/interop/ruby-server/server.rb)
exercises this end-to-end through Surfpool in CI for both TypeScript and Rust
clients.

## Roadmap

- **Ruby client.** This PR is intentionally server-only. A future client pass
  should construct credentials from a challenge, sign transactions, and run the
  inverse interop direction against Rust and TypeScript servers.
- **Framework integrations.** The current framework example is Sinatra. Future
  examples can add Rails or Rack-native middleware adapters once the server API
  is stable.
- **Other intents.** `x402/*`, `mpp/session`, and `mpp/subscription` are not
  scoped on the Ruby side.

## How to use the library

```bash
cd ruby
bundle install
```

```ruby
require "solana_mpp"
```

Public surface is documented inline; every public type/function carries a
summary so Ruby LSP hover can show intent, inputs, and outputs without
round-tripping to source.

## How to use the examples

Two examples ship with this package:

- [`examples/simple-server.rb`](examples/simple-server.rb) — a single-file Ruby
  server demonstrating the raw protocol on top of the SDK helpers.
- [`examples/sinatra-app.rb`](examples/sinatra-app.rb) — a Sinatra app with one
  protected route using the same `ChargeHandler`.

### Simple Ruby server

```bash
cd ruby
bundle install
bundle exec ruby examples/simple-server.rb

# In another terminal:
brew install pay

# payment required
curl -i http://127.0.0.1:4567/paid

# payment successful
pay curl http://127.0.0.1:4567/paid
```

The simple server defaults to Surfpool localnet (`https://402.surfnet.dev:8899`),
`USDC`, and a local example recipient. Override `MPP_RPC_URL`, `MPP_MINT`,
`MPP_PAY_TO`, `MPP_AMOUNT`, or `MPP_FEE_PAYER_SECRET_KEY` when you need a
different localnet fixture.

### Sinatra server

```bash
cd ruby
bundle install
PORT=4568 bundle exec ruby examples/sinatra-app.rb

# Same curl / pay flow as above on port 4568.
```

Both examples expose one protected endpoint at `/paid`. Use the interop harness
for the full Surfpool-backed transaction flow.

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
