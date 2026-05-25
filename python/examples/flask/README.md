# Python Flask MPP example

A minimal Flask app with one MPP-protected endpoint, organized as an
app factory with separate `config` and `middleware` modules so it can
double as a Flask best-practice template.

Layout:

- `app.py` builds the Flask app via a `create_app(mpp, settings)` factory
- `config.py` reads `ServerSettings` and the MPP `Config` from env vars
- `middleware.py` exposes the `mpp_charge(mpp, amount, description)` decorator

Two routes:

- `GET /health` is free and returns `{"ok": true}`
- `GET /paid` is gated by an `@mpp_charge(...)` decorator that inspects
  the `Authorization: Payment` header, returns a 402 with a signed
  challenge when none is supplied, and otherwise lets the view render
  any body while attaching the on-chain `Payment-Receipt` header.

## Run

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

## Environment

`HOST`, `PORT`, `MPP_RPC_URL`, `MPP_NETWORK`, `MPP_CURRENCY`,
`MPP_PAY_TO`, `MPP_SECRET_KEY`, `MPP_AMOUNT`. Defaults match the other
language examples so cross-language clients can hit either server with
the same configuration.
