<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# solana-mpp

Charge stablecoins (USDC, USDT, PYUSD, USDG, CASH) for any HTTP endpoint,
in Python. Implements the Solana payment method for the
[HTTP Payment Authentication Scheme](https://paymentauth.org).

The wire format, error grammar, and challenge / credential shape are
all defined at [paymentauth.org](https://paymentauth.org). This SDK
follows that spec — pick a currency, give it your wallet address, and
gate a route in two lines.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)]()
[![Coverage](https://img.shields.io/badge/coverage-81%25-yellow)]()
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-tracked-blue)]()

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
├── examples/payment-links/server.py
├── tests/                       pytest suite (324 cases)
└── pyproject.toml
```

## Quick start, server

```python
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp
from solana_mpp.store import MemoryStore
from solana_mpp._rpc import SolanaRpc

mpp = Mpp(Config(
    recipient="CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
    currency="USDC",                    # symbol or raw mint address
    decimals=6,
    network="localnet",                 # "mainnet" (canonical), "devnet", "localnet"
    rpc_url="https://402.surfnet.dev:8899",
    secret_key="local-dev-secret",
    realm="Python MPP Example",
    store=MemoryStore(),                # required, no silent default (L4 lock)
    rpc=SolanaRpc("https://402.surfnet.dev:8899"),
))

challenge = mpp.charge_with_options("0.001", ChargeOptions(description="Paid endpoint"))
# Render `format_www_authenticate(challenge)` in the WWW-Authenticate response header.

# After a client sends an Authorization: Payment <credential> header:
from solana_mpp._headers import parse_authorization
from solana_mpp.protocol.intents import ChargeRequest

credential = parse_authorization(authorization_header)
expected = ChargeRequest.from_dict(challenge.decode_request())
receipt = await mpp.verify_credential_with_expected(credential, expected)
# Emit `receipt.reference` (the on-chain signature) on a `Payment-Receipt` header.
```

`currency` accepts a symbol like `"USDC"`, `"USDT"`, `"USDG"`, `"PYUSD"`,
or `"CASH"`. The SDK looks up the mint address and the right SPL token
program (Token vs Token-2022). You can also pass a raw mint pubkey for
tokens not in the table.

The L4 lock (PR #96 / #102 cross-SDK) requires an explicit replay
store. `MemoryStore()` is fine for tests and single-process deployments;
`FileReplayStore(path)` persists the consumed-signature set across
restarts (it flushes the on-disk write before committing the in-memory
consumed set, so a crash mid-settlement can never lose a replay record).

Pass `fee_payer_signer=<solders.Keypair>` on `Config` to opt into
server-side fee-payer co-sign for pull mode. The server then advertises
`feePayer=true` on the challenge, validates the client-signed transaction
against a strict instruction allowlist (SPL transferChecked / System
transfer / Memo v2 matching expected memos / ATA idempotent create /
ComputeBudget), refuses to sign anything off-list, and pins the fee-payer
pubkey to `account_keys[0]` before splicing the signature. Servers that
swap RPC endpoints per request can use `async with mpp.using_rpc(rpc):`
to scope a transport for the duration of a single verification call.

### ASGI / Starlette middleware

```python
from solana_mpp.server.middleware import pay

@app.get("/paid")
@pay(mpp, amount="0.001", description="Paid endpoint")
async def handler(request, credential, receipt):
    return {"ok": True}
```

The decorator handles the 402 flow end to end: it builds the challenge,
parses any `Authorization: Payment` header, runs route-aware
verification through `verify_credential_with_expected`, and emits a
structured `application/problem+json` body with the L6 canonical
error code (`payment_invalid`, `signature_consumed`, ...) on any 402.

## Running the examples

A clean Flask example with an app factory, `config.py`, and a
`middleware.py` charge decorator lives at
[`examples/flask/app.py`](./examples/flask/app.py).
It exposes `GET /health` (free) and `GET /paid` (gated by an
`@mpp_charge` decorator).

```bash
cd python
pip install -e ".[dev]"
pip install flask
python examples/flask/app.py
```

In another terminal:

```bash
curl -i http://127.0.0.1:8000/paid
# HTTP/1.1 402 Payment Required
# WWW-Authenticate: Payment realm="Python Flask Example", ...
```

A second `examples/payment-links/server.py` runs the same flow against
a local Surfpool on `127.0.0.1:8899`, serves a payment-page HTML
fallback, and is the adapter used by the interop harness:

```bash
brew install pay
python examples/payment-links/server.py &
pay --local curl http://localhost:3004/fortune  # pays and succeeds
```

The examples default to `localnet`, `USDC`, and a local recipient.
Override `RPC_URL` (or `MPP_RPC_URL` for the Flask example) for a
different endpoint.

## Client compatibility matrix

The Python SDK ships both the charge client and server.

| Intent | Client | Server |
|---|:---:|:---:|
| `x402/exact` | — | — |
| `x402/upto` | — | — |
| `x402/batch-settlement` | — | — |
| `mpp/charge/pull` | ✅ | ✅ |
| `mpp/charge/push` | ✅ | ✅ |
| `mpp/session` | — | — |
| `mpp/subscription` | — | — |

`mpp/charge/push` server mode is supported including the B34 lock:
when a challenge advertises `feePayer=true`, a `type=signature`
credential is rejected before any RPC call. Pull mode includes
server-side fee-payer co-sign for both legacy and v0 transactions.

## Server compatibility matrix

Split into two phases because an MPP server first verifies the
credential and then settles or confirms the payment on-chain.

For `mpp/charge/pull`: the server owns the full lifecycle. Issue
signed challenges with a fresh `recentBlockhash`, parse and validate
the `Authorization: Payment` credential, pin the echoed charge
request, decode the client-signed transaction and check
recipient / amount / mint / splits / ATA / memos / compute budget,
reject Surfpool-signed transactions on non-localnet networks,
optionally fee-payer co-sign (legacy + v0), broadcast via
`sendTransaction`, consume the signature in the replay store, await
confirmation, and emit `payment-receipt` with the on-chain signature.

For `mpp/charge/push`: the server fetches the transaction by signature
with `getTransaction`, rejects failed or missing metadata, reuses the
same structural transaction verifier as pull mode, consumes the
signature in replay storage only after the on-chain shape is known to
be correct, and emits the same receipt shape.

The direct Python interop server at
[`harness/python-server/main.py`](../harness/python-server/main.py)
exercises this end to end through Surfpool in CI for both TypeScript
and Rust clients.

## Audit v2 + RFC conformance pinned in this SDK

This SDK closes every row from the cross-SDK audit that applies to
Python. Each row has a regression test pinned in `python/tests/`:

| Row | Behavior | Test |
|---|---|---|
| L1 | mainnet canonical, mainnet-beta alias | `test_solana_protocol.py::TestResolveMint` |
| L2 | reject Solana memo v1 | `test_server.py::TestMemoV1Rejected` |
| L4 | explicit replay store required | `test_store.py::TestMppRequiresExplicitStore` |
| L6 | canonical structured error codes in 402 | `test_errors.py::TestCanonicalCodes` |
| L8 | broadcast then consume then await ordering | `test_server.py::TestL8SettlementOrdering` |
| L11 | reject CR / LF in header parameter values | `test_headers.py::TestCRLFRejection` |
| F1 | token-form auth params (RFC 7235) | `test_headers.py::TestAuthParamTokenForm` |
| F2 | canonical JSON UTF-16 key sort | `test_canonical_json.py::TestKeySort` |
| F3 | ES6 ToString number serialization | `test_canonical_json.py::TestNumberSerialization` |
| F4 | lone-surrogate reject | `test_canonical_json.py::TestStringEncoding` |
| F5 | multi-challenge WWW-Authenticate | `test_headers.py::TestMultiChallenge` |
| F6 | strict RFC 3339 expires grammar | `test_expires.py::TestStrictRFC3339` |
| B34 | signature + feePayer reject before RPC | `test_server.py::test_b34_signature_credential_with_fee_payer_rejected_before_rpc` |

## Solana dependencies

| Dependency | Why | Version |
|---|---|---|
| `solders` | Ed25519 signer, transaction codec, base58 helpers | `>=0.22` |
| `solana` | not directly required by the SDK; tests use `solana.rpc.async_api.AsyncClient` for compatibility | `>=0.35` |
| `httpx` | async JSON-RPC HTTP client (`SolanaRpc`) | `>=0.27` |
| internal canonical JSON helper | RFC 8785 byte-equal output across SDKs | `_canonical_json.py` |
| internal base64url helper | URL-safe base64 without padding | `_base64url.py` |

The Python server keeps Solana dependencies intentionally small. It
parses legacy and v0 transaction messages via `solders`, verifies
transfer instructions structurally, signs optional fee-payer pull
transactions, and uses JSON-RPC directly for submission, confirmation,
and push-mode transaction lookup. The thin `SolanaRpc` client bypasses
`solana-py`'s response parser so the server thread never crashes on
upstream error shapes (observed against Surfpool 1.1.1).

## Coding convention

This SDK follows the
[`skills.sh/mindrally/skills/python`](https://skills.sh/mindrally/skills/python)
best-practice skill selected for the M1g port. The implementation pass
focuses on small modules, explicit error types with canonical L6
codes, deterministic wire serialization (RFC 8785 canonical JSON),
defensive payment verification (instruction allowlist + memo v2
enforcement), and branch tests on security-sensitive paths
(broadcast / consume / await ordering, B34 reject, CRLF reject,
lone-surrogate reject).

The repo-level `pay-sdk-implementation` skill remains the protocol
source of truth: Rust / spec wire format first, Python idioms second.

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

Coverage gates in CI:

- line + branch coverage: at least 80 percent (raised to 90 after the
  HTML render path and `_rpc.py` get backfilled in a follow-up).

The newly added L1-L11 / F1-F6 / B34 / L6 surface is well covered:
`_canonical_json` 92 percent, `_errors` 100 percent, `store` 94
percent, `_types` 99 percent, `_headers` 89 percent.

## Interop

The Python server has a direct harness adapter at
[`harness/python-server/main.py`](../harness/python-server/main.py)
mirroring the Ruby and PHP adapters. It is server-side only in this
pass (no client adapter; the Python client ships as a library and is
exercised through unit tests in `python/tests/test_client_charge.py`).

Focused harness commands:

```bash
cd harness
MPP_INTEROP_CLIENTS=typescript MPP_INTEROP_SERVERS=python pnpm test
MPP_INTEROP_CLIENTS=rust MPP_INTEROP_SERVERS=python pnpm test
```

Both matrices are green at the M1g closure: 11 + 9 = 20 scenarios
across TS-to-Python and Rust-to-Python.

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188)
for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
