<p align="center">
  <img src="https://github.com/solana-foundation/pay-kit/raw/main/docs/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-pay-kit

Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP endpoint, in
Python. Implements the Solana payment method for the
[Machine Payments Protocol](https://mpp.dev) and ships a Flask-friendly
decorator for `402 Payment Required` flows.

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets
any HTTP API accept payments using the `402 Payment Required` flow. You
do not need to know anything about Solana to use this library: pick a
currency, give it your wallet address, and gate a route in two lines.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-yellow)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-tracked-blue)]()

## Quick start

Gate a Flask route with the `@mpp_charge` decorator (from
[`examples/flask/app.py`](examples/flask/app.py)):

```python
from flask import Flask, jsonify

from solana_mpp.server.mpp import Mpp
from config import mpp_config_from_env, server_settings_from_env
from middleware import mpp_charge

settings = server_settings_from_env()
mpp = Mpp(mpp_config_from_env())
app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.get("/paid")
@mpp_charge(mpp, amount=settings.amount, description="Paid endpoint")
def paid():
    return jsonify(ok=True, message="thanks for paying!")

if __name__ == "__main__":
    app.run(host=settings.host, port=settings.port)
```

The decorator handles the 402 flow end to end: it builds the challenge,
parses any `Authorization: Payment` header, runs route-aware verification
through `verify_credential_with_expected`, and emits a structured
`application/problem+json` body with the L6 canonical error code
(`payment_invalid`, `signature_consumed`, ...) on any 402.

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address and the right SPL token
program (Token vs Token-2022). You can also pass a raw mint pubkey for
tokens not in the table.

### Raw SDK usage

```python
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp
from solana_mpp.store import MemoryStore
from solana_mpp._rpc import SolanaRpc

mpp = Mpp(Config(
    recipient="CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
    currency="USDC",
    decimals=6,
    network="localnet",
    rpc_url="https://402.surfnet.dev:8899",
    secret_key="local-dev-secret",
    realm="Python MPP Example",
    store=MemoryStore(),
    rpc=SolanaRpc("https://402.surfnet.dev:8899"),
))

challenge = mpp.charge_with_options("0.001", ChargeOptions(description="Paid endpoint"))
```

The Mpp handler owns every static knob (recipient, default currency,
network, RPC, optional fee payer). Per-request you only pass `amount`
and `description`. An explicit replay store is required; `MemoryStore()`
is fine for tests and single-process deployments, `FileReplayStore(path)`
persists the consumed-signature set across restarts.

## Protocol compatibility matrix

### MPP

| Intent | Client | Server |
|---|:---:|:---:|
| `mpp/charge/pull` | pass | pass |
| `mpp/charge/push` | pass | pass |
| `mpp/session` | --- | --- |
| `mpp/subscription` | --- | --- |

### x402

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | --- | --- |
| `x402/upto` | --- | --- |
| `x402/batch-settlement` | --- | --- |

For `mpp/charge/pull`: the server owns the full lifecycle. Issue signed
challenges with a fresh `recentBlockhash`, parse and validate the
`Authorization: Payment` credential, pin the echoed charge request,
decode the client-signed transaction and check recipient, amount, mint,
splits, ATA, memos, and compute budget, reject Surfpool-signed
transactions on non-localnet networks, optionally fee-payer co-sign
(legacy + v0), broadcast via `sendTransaction`, consume the signature
in the replay store, await confirmation, and emit `payment-receipt` with
the on-chain signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature in replay storage only after the on-chain shape is known to
be correct, and emits the same receipt shape.

## Examples

Two runnable examples ship with this package:

- [`examples/flask/`](examples/flask) - Flask app with an app factory,
  `config.py`, and a `middleware.py` charge decorator. Exposes
  `/health` (free) and `/paid` (gated).
- [`examples/payment-links/server.py`](examples/payment-links/server.py)
  - runs the same flow against a local Surfpool, serves a payment-page
  HTML fallback, and is the adapter used by the interop harness.

### Run the Flask example

```bash
cd python
pip install -e ".[dev]"
pip install flask
python examples/flask/app.py
```

### Drive it from a client

```bash
brew install pay
curl  http://127.0.0.1:8000/paid       # 402 payment required
pay curl http://127.0.0.1:8000/paid    # pays and succeeds
```

The examples default to `localnet`, `USDC`, and a local recipient.
Override `RPC_URL` (or `MPP_RPC_URL` for the Flask example) for a
different endpoint.

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `solders` | Ed25519 signer, transaction codec, base58 helpers | `>=0.22` |
| `solana` | tests use `solana.rpc.async_api.AsyncClient` for compatibility | `>=0.35` |
| `httpx` | async JSON-RPC HTTP client (`SolanaRpc`) | `>=0.27` |
| internal canonical JSON helper | RFC 8785 byte-equal output across SDKs | `_canonical_json.py` |
| internal base64url helper | URL-safe base64 without padding | `_base64url.py` |

The Python server keeps Solana dependencies intentionally small. It
parses legacy and v0 transaction messages via `solders`, verifies
transfer instructions structurally, signs optional fee-payer pull
transactions, and uses JSON-RPC directly for submission, confirmation,
and push-mode transaction lookup.

## Coding convention

This SDK follows the
[`skills.sh/mindrally/skills/python`](https://skills.sh/mindrally/skills/python)
best-practice skill. The implementation pass focuses on small modules,
explicit error types with canonical L6 codes, deterministic wire
serialization (RFC 8785 canonical JSON), defensive payment verification
(instruction allowlist + memo v2 enforcement), and branch tests on
security-sensitive paths.

The repo-level `pay-sdk-implementation` skill remains the protocol source
of truth: Rust / spec wire format first, Python idioms second.

## Test, lint, coverage

```bash
cd python
pip install -e ".[dev]"
pytest -q --ignore=tests/test_server_html.py
ruff check src tests
pyright
pytest --cov=solana_mpp --cov-branch --cov-fail-under=80 \
       --ignore=tests/test_server_html.py
```

Coverage gates in CI: at least 80 percent line + branch coverage (raised
to 90 after the HTML render path and `_rpc.py` get backfilled).

## Interop

The Python server has a direct harness adapter at
[`harness/python-server/main.py`](../harness/python-server/main.py).
Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=python pnpm test
MPP_INTEROP_CLIENTS=rust       MPP_INTEROP_SERVERS=python pnpm test
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).
The wire format, error grammar, and challenge / credential shape are all
defined at [paymentauth.org](https://paymentauth.org).

## Repo layout

```text
python/
├── src/solana_mpp/
│   ├── __init__.py
│   ├── _base64url.py            base64url + canonical JSON wrapper
│   ├── _canonical_json.py       RFC 8785 JSON encoder (UTF-16 sort, ES6 numbers)
│   ├── _challenge.py            HMAC challenge id + constant-time compare
│   ├── _errors.py               PaymentError hierarchy + canonical L6 codes
│   ├── _expires.py              RFC 3339 timestamp helpers
│   ├── _headers.py              WWW-Authenticate / Authorization / Receipt
│   ├── _rpc.py                  thin async Solana JSON-RPC client
│   ├── _types.py                PaymentChallenge / Credential / Receipt
│   ├── store.py                 MemoryStore + FileReplayStore
│   ├── client/                  charge client + HTTP transport
│   ├── protocol/                ChargeRequest + Solana protocol helpers
│   └── server/                  Mpp handler + middleware + payment page
├── examples/flask/              Flask app + middleware example
├── examples/payment-links/      Surfpool-backed payment-page example
├── tests/                       pytest suite
└── pyproject.toml
```

## License

MIT
