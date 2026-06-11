<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-python-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-python-light.png">
    <img alt="Solana pay-kit — Python" width="100%" style="border-top-left-radius: 8px; border-top-right-radius: 8px; margin-bottom: 16px;" src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner-python-light.png">
  </picture>
</div>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in Python.
One package, one surface, two protocols underneath:
[x402](https://x402.org) and the
[Machine Payments Protocol](https://paymentauth.org). FastAPI, Flask, and
Django ride on top of a framework-agnostic core.

You do not need to know anything about Solana to use this. Pick a currency,
give it your wallet address, gate a route in two lines. The SDK handles the
challenge, the on-chain verification, the broadcast, and the settlement.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-tracked-blue)]()

---

## Quick start

Three progressively-realistic snippets. Each one runs as-is, copy, paste,
hit the URL. Flask is the framework here; the same surface works in FastAPI
and Django (see [Examples](#examples)).

### 1. Smallest possible app

Gate one route with an inline price. Save the snippet as `app.py` and boot
with `python app.py`. Zero-config: the package uses a published demo
keypair as the recipient and the hosted Surfpool sandbox at
`https://402.surfnet.dev:8899` as the RPC.

```python
# app.py
from flask import Flask, jsonify

import pay_kit
from pay_kit import usd
from pay_kit.flask import require_payment

pay_kit.configure(network="solana_localnet")

app = Flask(__name__)

@app.get("/report")
@require_payment(usd("0.10"))
def report():
    return jsonify(content="premium content")

app.run(host="127.0.0.1", port=8000)
```

`pay_kit.configure(...)` builds the process-wide config once at boot.
`@require_payment(usd("0.10"))` answers a 402 with a payment challenge when
no valid proof was sent, or runs the view if one was.

Hit `/report` with [`pay curl`](#run-the-example) and the customer walks
through a USDC payment.

### 2. Multiple gates via a registry

When more than one route is paid, lift the prices into a single
:class:`Pricing` registry. Routes reference gates by string handle.

```python
# app.py
from flask import Flask, jsonify

import pay_kit
from pay_kit import Gate, Protocol, Pricing, usd
from pay_kit.flask import require_payment

pay_kit.configure(network="solana_localnet")

class Catalog(Pricing):
    def __init__(self):
        defaults = {
            "default_pay_to": pay_kit.config().effective_recipient(),
            "accept_default": pay_kit.config().accept,
        }
        self.report = Gate.build(name="report", amount=usd("0.10"),
                                 description="Premium report", **defaults)
        self.api_call = Gate.build(name="api_call", amount=usd("0.001"),
                                   accept=(Protocol.X402,), **defaults)

catalog = Catalog()
app = Flask(__name__)

@app.get("/report")
@require_payment("report", pricing=catalog)
def report():
    return jsonify(content="premium content")

@app.get("/api/data")
@require_payment("api_call", pricing=catalog)
def api_data():
    return jsonify(data=[])

app.run(host="127.0.0.1", port=8000)
```

Gates are validated in `Gate.build` at boot, wrong currency, missing
recipient, fee math that doesn't add up, so configuration errors surface
before any traffic. `accept=` is an allowlist; the `api_call` gate here
refuses to settle over MPP.

### 3. Production-shape config

Snippet 2's demo recipient and public sandbox are fine for poking around.
Production wants explicit keys, a dedicated RPC, and a list of accepted
stablecoins. The Flask app is unchanged, only the `configure` call grows.

```python
# app.py, same routes as snippet 2.
import pay_kit
from pay_kit import Gate, Operator, Pricing, Signer, Stablecoin, usd

PLATFORM = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

pay_kit.configure(
    network="solana_mainnet",
    stablecoins=(Stablecoin.USDC, Stablecoin.PYUSD),
    operator=Operator(signer=Signer.file("operator.json")),
    rpc_url="https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY",
)

class Catalog(Pricing):
    def __init__(self):
        defaults = {"default_pay_to": pay_kit.config().effective_recipient()}
        self.report = Gate.build(name="report", amount=usd("0.10"),
                                 description="Premium report", **defaults)
        # Platform-fee pattern: customer pays $10.00,
        # operator nets $9.70, PLATFORM nets $0.30. x402 auto-disabled.
        self.marketplace_sale = Gate.build(
            name="marketplace_sale",
            amount=usd("10.00"),
            fee_within={PLATFORM: usd("0.30")},
            **defaults,
        )
```

`configure` reads literal values here; in real deployments pull the signer
and RPC URL from your environment (`Signer.env("OPERATOR_KEY")`,
`os.getenv("RPC_URL")`) or drive the whole thing from env vars with
`pay_kit.configure_from()`.

Two safety rails fire at boot:

- `network="solana_mainnet"` plus the published demo signer raises
  `DemoSignerOnMainnetError`, no real funds get routed to a publicly known
  address by accident.
- Missing `mpp.challenge_binding_secret`? Preflight resolves one from the
  environment, falling back to `./.env`, generating and persisting one if
  neither exists, so the HMAC stays stable across restarts. Override via
  `PAY_KIT_MPP_CHALLENGE_BINDING_SECRET` to control it from your secret
  manager.

---

## Run the example

Three runnable examples ship with this package, one per framework. Each one
boots zero-config against the Surfpool sandbox.

**Boot the server:**

```bash
git clone https://github.com/solana-foundation/pay-kit
cd pay-kit/python
pip install -e ".[flask]"
python examples/flask/app.py
```

**Consume with `pay curl`:**

```bash
# Install the pay CLI:
brew install pay
# or npm install -g @solana/pay

# Fail with 402, payment required
curl -i http://127.0.0.1:8000/report

# Succeed with 200, payment provided
pay curl -i http://127.0.0.1:8000/report
```

---

## x402

[x402](https://x402.org) revives HTTP `402 Payment Required` as a
client-server payment handshake. Your server gates a route; a paying client
receives the 402 with payment instructions, signs a Solana transaction
off-chain, and replays the same request with a `PAYMENT-SIGNATURE` header.
The server verifies the signature, broadcasts the transaction, and returns
the original response with a `PAYMENT-RESPONSE` header carrying the on-chain
settlement signature.

x402 is single-recipient by design: the server's facilitator pays the
network fees, the customer's signed transaction settles funds to `pay_to`.
Gates with `fee_within` or `fee_on_top` recipients auto-disable x402,
because stock x402 facilitators settle to one address.

| Scheme  | Client | Server |
|---------|:------:|:------:|
| `exact` | ✅     | ✅     |
| `upto`  | —      | —      |
| `batch` | —      | —      |

### Client

Pay an x402-gated endpoint with the auto-pay transport (the Go `NewClient`
ergonomics): hand it a signer and an RPC and you get back an
`httpx.AsyncClient` that replays any `402` with a signed `PAYMENT-SIGNATURE`
payment, then returns the paid response.

```python
import asyncio

from pay_kit import Signer
from pay_kit._paycore.rpc import SolanaRpc
from pay_kit.protocols.x402.client import x402_async_client

async def main():
    signer = Signer.file("payer.json")  # the payer's keypair
    rpc = SolanaRpc("https://api.devnet.solana.com")
    async with x402_async_client(signer, rpc) as http:
        resp = await http.get("https://api.example/report")  # 402 -> pay -> 200
        print(resp.status_code, resp.headers.get("payment-response"))

asyncio.run(main())
```

The low-level building blocks are exposed too, mirroring the Rust/Go client:
`parse_x402_challenge(headers, body, selection)` selects an offer, and
`build_payment_header(signer, rpc, offer)` returns the base64 `PAYMENT-SIGNATURE`
value for callers that drive their own HTTP. See
[`examples/x402-client/`](examples/x402-client).

## MPP

The [Machine Payments Protocol](https://paymentauth.org) is the broader HTTP
Payment Authentication scheme, the same 402 handshake, but the challenge
carries a richer intent shape that supports multi-recipient splits,
server-side fee accounting, and a separate fee-payer signer.

Use MPP when:

- Your gate has a platform or gateway fee (the Stripe-Connect "application
  fee" pattern).
- You want the server to subsidize the customer's network fee.
- You want one challenge per gate instead of per-mint-quoted offers.

| Scheme        | Status |
|---------------|--------|
| `charge/pull` | ✅      |
| `charge/push` | ✅      |
| `session`     | —      |

The MPP server owns the full lifecycle: it issues signed challenges with a
fresh `recentBlockhash`, parses and validates the `Authorization: Payment`
credential, pins the echoed charge request, decodes the client-signed
transaction and checks recipient, amount, mint, splits, ATA, memos, and
compute budget, rejects Surfpool-signed transactions on non-localnet
networks, optionally fee-payer co-signs (legacy + v0), broadcasts via
`sendTransaction`, consumes the signature in the replay store, awaits
confirmation, and emits `payment-receipt` with the on-chain signature.

---

## Vocabulary

| Term         | Meaning |
|--------------|---------|
| **gate**     | A protected unit. Has an amount, optional fees, accepted protocols. |
| **amount**   | The base amount a gate charges, before any `fee_on_top`. |
| **total**    | What the customer pays: `amount + sum(fee_on_top)`. Derived via `Gate.total()`. |
| **price**    | Value object returned by `usd(...)`: number + currency + settlement. |
| **fee_within** | Fee taken out of the amount. `pay_to` nets less. |
| **fee_on_top** | Fee added to the amount. Customer pays more; `pay_to` nets full. |
| **payment**  | Proof submitted by the client to pass a gate. |
| **protocol** | `Protocol.X402` or `Protocol.MPP` (top-level dispatch). |
| **scheme**   | x402 sub-form: `exact`. MPP sub-form: `charge`. |
| **currency** | Fiat unit a price is quoted in (`USD`, `EUR`, `GBP`). |
| **accept**   | Ordered preference list (protocols and stablecoins both). |
| **settlement** | On-chain asset that actually transfers (`USDC`, `USDT`). |

## Three primitives

The framework-agnostic trio, importable from the top level for imperative
gating inside a handler, mirrored by the per-framework shims:

| Function | Purpose |
|----------|---------|
| `require_payment(request)` | Returns the verified `Payment`, raises `PaymentRequiredError` if unpaid |
| `is_paid(request)`         | Predicate, never raises |
| `get_payment(request)`     | The verified `Payment`, `None` until paid |

Each framework shim also exposes its own decorator/dependency form:
`pay_kit.flask.require_payment`, `pay_kit.fastapi.RequirePayment`, and
`pay_kit.django.require_payment`.

## Inline pricing

For one-off endpoints that don't warrant a registry entry, skip the gate
name and pass a price directly:

```python
@app.get("/oneoff")
@require_payment(usd("0.25"))
def oneoff():
    return jsonify(ok=True)
```

The bare `Price` is wrapped into an inline `Gate` using the configured
default recipient and accept list.

## Gate DSL

Each gate is a frozen value object built via `Gate.build` with an amount, an
ordered list of accepted protocols, and zero or more named fees.

```python
SELLER = "Ay..."
PLATFORM = "CX..."

# Simple. Customer pays $0.10, pay_to nets $0.10.
Gate.build(name="report", amount=usd("0.10"), description="Premium report")

# x402-only.
Gate.build(name="api_call", amount=usd("0.001"), accept=(Protocol.X402,))

# Stripe-Connect "application fee". Customer pays $10.00,
# SELLER nets $9.70, PLATFORM nets $0.30. x402 auto-disabled.
Gate.build(name="marketplace_sale", amount=usd("10.00"),
           pay_to=SELLER, fee_within={PLATFORM: usd("0.30")})

# Surcharge. Customer pays $10.50, SELLER nets $10.00, PLATFORM nets $0.50.
Gate.build(name="ticket", amount=usd("10.00"),
           pay_to=SELLER, fee_on_top={PLATFORM: usd("0.50")})

# Dynamic per-request pricing.
@gate("tiered")
def tiered(request):
    tier = request.args.get("tier")
    return usd("5.00") if tier == "premium" else usd("0.10")
```

Boot-time validations (all raise `ConfigurationError` or a subclass):

- `pay_to` is required (gate kwarg or a configured operator recipient).
- Fee recipient must differ from `pay_to`. Fold the fee into the amount instead.
- All fee prices share one denomination with the amount.
- `sum(fee_within) <= amount`.
- `accept=(Protocol.X402,)` on a fee-bearing gate raises `ProtocolIncompatibleError`.

## Framework-first

`pay_kit` carries no web-framework dependency in the base install. The
framework shims live in optional submodules imported on demand:

- `pay_kit.flask` (install `pay_kit[flask]`), a `@require_payment` view
  decorator plus `is_paid` / `payment` request accessors.
- `pay_kit.fastapi` (install `pay_kit[fastapi]`), a `RequirePayment`
  dependency for `Depends(...)` plus `install_exception_handler(app)`.
- `pay_kit.django` (install `pay_kit[django]`), a `require_payment` view
  decorator and an optional `PaymentMiddleware` stack form.

Every shim delegates protocol/scheme dispatch and 402-challenge assembly to
the host-neutral `PayCore`; the shim only translates the outcome into its
framework's response idioms. A verified `Payment` is attached to the request
(`request.state` on FastAPI, `flask.g` on Flask, `request.payment` on
Django) and its settlement headers are merged onto the success response.

```python
# Imperative gating, no decorator, any framework:
from pay_kit import require_payment

def view(request):
    payment = require_payment(request)  # raises PaymentRequiredError if unpaid
    ...
```

---

## Examples

Runnable examples ship with this package:

- [`examples/simple-server/server.py`](examples/simple-server/server.py), the
  smallest pay_kit server: stdlib `http.server` with one gated endpoint over
  the unified `pay_kit` surface, no web framework.
- [`examples/fastapi/app.py`](examples/fastapi/app.py), FastAPI server using
  the `RequirePayment` dependency and `install_exception_handler`.
- [`examples/flask/app.py`](examples/flask/app.py), Flask server gated with
  the unified `pay_kit` surface (`@require_payment` decorator and the
  `Pricing` registry).
- [`examples/django/views.py`](examples/django/views.py), Django views +
  URLconf snippet using the `@require_payment` decorator.

All examples default to `solana_localnet`, `USDC`, and the demo recipient.
Override the RPC with `rpc_url=` / `PAY_KIT_RPC_URL`.

## Coverage

```bash
cd python
pip install -e ".[dev]"
ruff check src tests
ruff format --check src tests
pyright
pytest --cov=pay_kit --cov-fail-under=90
```

The `pay_kit` surface is gated at 90 percent line coverage in CI. The
`pay_kit.preflight` module is omitted from the gate: it wraps live Solana
RPC + Surfnet cheatcodes that cannot run inside the offline unit suite, and
its two opt-out knobs are covered separately against a stubbed run/RPC.

## Harness

The Python server has a direct harness adapter at
[`harness/python-server/server.py`](../harness/python-server/server.py), a
dual-protocol server that settles both MPP charge and x402-exact. Focused
harness commands:

```bash
cd harness
MPP_HARNESS_CLIENTS=typescript MPP_HARNESS_SERVERS=python pnpm test
MPP_HARNESS_CLIENTS=rust       MPP_HARNESS_SERVERS=python pnpm test
```

## Spec

This SDK implements the
[Solana Charge Intent](https://paymentauth.org/draft-solana-charge-00.html) for
the [HTTP Payment Authentication Scheme](https://paymentauth.org), plus the
x402 exact scheme on Solana. The wire format, error grammar, and challenge /
credential shape are all defined at [paymentauth.org](https://paymentauth.org).

---

## Repo layout

```text
python/
├── src/pay_kit/                              unified surface over x402 + MPP
│   ├── config.py, operator.py, signer.py, price.py, fee.py, gate.py,
│   │   pricing.py, payment.py, preflight.py, errors.py    # umbrella surface
│   ├── _paycore/                             Currency / Network / Protocol / Stablecoin / Mints / Solana
│   ├── _middleware.py                        host-neutral resolver + require_payment/is_paid/get_payment
│   ├── fastapi.py, flask.py, django.py       framework shims
│   ├── kms.py                                reserved remote-enclave signer namespace
│   └── protocols/
│       ├── x402/                             x402-exact adapter (__init__) + verifier/wire shapes (verify.py)
│       └── mpp/                              MPP-charge adapter (__init__) over the consolidated wire layer
│           ├── core/                         canonical JSON, headers, challenge, types, errors, RPC, store
│           ├── intents/charge.py             charge intent
│           ├── server/                       charge handler, middleware, network check, defaults, payment page
│           └── client/                       charge + transport
├── examples/simple-server/                   stdlib http.server, one gated endpoint
├── examples/{fastapi,flask,django}/          pay_kit framework examples
├── tests/                                    pytest suite
└── pyproject.toml
```

## Coding convention

This SDK follows the
[`skills.sh/mindrally/skills/python`](https://skills.sh/mindrally/skills/python)
best-practice skill. Small modules, frozen pydantic value objects, explicit
error types with canonical codes, deterministic wire serialization (RFC 8785
canonical JSON), defensive payment verification, and branch tests on
security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol source of
truth: Rust spec wire format first, Python idioms second.

## License

MIT
