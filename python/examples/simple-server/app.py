"""Flask app with one MPP-protected endpoint.

Mirrors the Ruby Sinatra example (`ruby/examples/sinatra/app.rb`):

    GET /health -> free, returns {"ok": true}
    GET /paid   -> gated by the @mpp_charge decorator. The decorator
                   inspects the Authorization: Payment header, returns
                   a 402 with a WWW-Authenticate challenge when no valid
                   credential is supplied, and otherwise lets the route
                   render any body it likes while emitting the
                   Payment-Receipt header.

Override the defaults via env vars:

    HOST, PORT, MPP_RPC_URL, MPP_NETWORK, MPP_CURRENCY,
    MPP_PAY_TO, MPP_SECRET_KEY, MPP_AMOUNT,
    MPP_FEE_PAYER_SECRET_KEY (optional JSON-array secret key).

Run:

    pip install flask
    python examples/simple-server/app.py

In another terminal:

    curl -i http://127.0.0.1:8000/paid
    # 402 Payment Required with WWW-Authenticate: Payment ... challenge
"""

from __future__ import annotations

import asyncio
import json
import os
from functools import wraps

from flask import Flask, Response, jsonify, request

from solana_mpp._headers import format_www_authenticate, parse_authorization
from solana_mpp._rpc import SolanaRpc
from solana_mpp.protocol.intents import ChargeRequest
from solana_mpp.server.mpp import ChargeOptions, Config, Mpp
from solana_mpp.store import MemoryStore

DEFAULT_RPC_URL = "https://402.surfnet.dev:8899"
DEFAULT_CURRENCY = "USDC"
DEFAULT_PAY_TO = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"


def _config_from_env() -> Config:
    rpc_url = os.environ.get("MPP_RPC_URL", DEFAULT_RPC_URL)
    return Config(
        recipient=os.environ.get("MPP_PAY_TO", DEFAULT_PAY_TO),
        currency=os.environ.get("MPP_CURRENCY", DEFAULT_CURRENCY),
        decimals=6,
        network=os.environ.get("MPP_NETWORK", "localnet"),
        rpc_url=rpc_url,
        secret_key=os.environ.get("MPP_SECRET_KEY", "python-mpp-dev-secret"),
        realm="Python Flask Example",
        store=MemoryStore(),
        rpc=SolanaRpc(rpc_url),
    )


mpp = Mpp(_config_from_env())
AMOUNT = os.environ.get("MPP_AMOUNT", "0.001")


def mpp_charge(amount: str, description: str = ""):
    """Flask middleware mirroring the Sinatra `mpp_charge!` helper.

    Verifies an Authorization: Payment header against a route-aware
    expected charge. Returns a 402 with WWW-Authenticate on miss; on hit,
    invokes the wrapped view and attaches a Payment-Receipt header.
    """

    options = ChargeOptions(description=description)

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            challenge = mpp.charge_with_options(amount, options)
            auth_header = request.headers.get("Authorization")
            if auth_header:
                try:
                    credential = parse_authorization(auth_header)
                    expected = ChargeRequest.from_dict(challenge.decode_request())
                    receipt = asyncio.run(
                        mpp.verify_credential_with_expected(credential, expected)
                    )
                    response = view(*args, **kwargs)
                    if not isinstance(response, Response):
                        response = jsonify(response)
                    response.headers["Payment-Receipt"] = receipt.reference
                    return response
                except Exception:  # noqa: BLE001
                    pass  # Fall through to a fresh challenge.

            body = json.dumps(
                {
                    "type": "https://paymentauth.org/problems/payment-required",
                    "title": "Payment Required",
                    "status": 402,
                }
            )
            return Response(
                body,
                status=402,
                headers={
                    "Content-Type": "application/json",
                    "WWW-Authenticate": format_www_authenticate(challenge),
                    "Cache-Control": "no-store",
                },
            )

        return wrapper

    return decorator


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/paid")
@mpp_charge(amount=AMOUNT, description="Paid endpoint")
def paid():
    return jsonify(ok=True, message="thanks for paying!")


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port)
