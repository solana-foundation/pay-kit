# examples/flask/app.py
"""Flask server gated with the unified solana_pay_kit surface.

Zero-config: ``solana_pay_kit.configure()`` boots against solana_localnet (the
hosted Surfpool sandbox at https://402.surfnet.dev:8899) with the shipped
demo signer as the recipient.

This example uses the solana_pay_kit Flask shim (``solana_pay_kit.flask``), the unified
surface over x402 and MPP. For a framework-free server on the same surface,
see ../simple-server/server.py instead.

Three routes:

    GET /health   -> free, returns {"ok": true}
    GET /report   -> gated by an inline price, both protocols accepted
    GET /api/data -> gated, x402-only via accept=

Run:

    pip install -e ".[flask]"
    python examples/flask/app.py

Drive it from a client:

    curl -i http://127.0.0.1:8000/report     # 402 payment required
    pay curl http://127.0.0.1:8000/report    # pays and succeeds
"""

from __future__ import annotations

from flask import Flask, jsonify

import solana_pay_kit
from solana_pay_kit import Gate, Protocol, usd
from solana_pay_kit.flask import payment, require_payment

solana_pay_kit.configure(network="solana_localnet")

_defaults = {
    "pay_to": solana_pay_kit.config().effective_recipient(),
    "accept": solana_pay_kit.config().accept,
}

report_gate = Gate.build(
    name="report",
    amount=usd("0.10"),
    description="Premium report",
    default_pay_to=_defaults["pay_to"],
    accept_default=_defaults["accept"],
)

api_gate = Gate.build(
    name="api_call",
    amount=usd("0.001"),
    accept=(Protocol.X402,),
    default_pay_to=_defaults["pay_to"],
)

app = Flask(__name__)


@app.get("/health")
def health():
    """Free liveness probe."""
    return jsonify(ok=True)


@app.get("/report")
@require_payment(report_gate)
def report():
    """Paid route. The verified proof is readable via solana_pay_kit.flask.payment()."""
    proof = payment()
    return jsonify(ok=True, tx=proof.transaction, protocol=proof.protocol.value)


@app.get("/api/data")
@require_payment(api_gate)
def api_data():
    """x402-only route: this gate refuses to settle over MPP."""
    return jsonify(data=[])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
