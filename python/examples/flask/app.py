"""Flask app with one MPP-protected endpoint.

Routes:

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
    python examples/flask/app.py

In another terminal:

    curl -i http://127.0.0.1:8000/paid
    # 402 Payment Required with WWW-Authenticate: Payment ... challenge
"""

from __future__ import annotations

from flask import Flask, jsonify

from solana_mpp.server.mpp import Mpp

from config import ServerSettings, mpp_config_from_env, server_settings_from_env
from middleware import mpp_charge


def create_app(mpp: Mpp, settings: ServerSettings) -> Flask:
    """Flask app factory wiring the MPP charge decorator onto /paid."""
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify(ok=True)

    @app.get("/paid")
    @mpp_charge(mpp, amount=settings.amount, description="Paid endpoint")
    def paid():
        return jsonify(ok=True, message="thanks for paying!")

    return app


def main() -> None:
    settings = server_settings_from_env()
    mpp = Mpp(mpp_config_from_env())
    app = create_app(mpp, settings)
    app.run(host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
