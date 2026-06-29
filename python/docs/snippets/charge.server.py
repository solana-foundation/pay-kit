# Server-side charge: gate a Flask route with the solana_pay_kit shim.
#
# Mirrors examples/flask/app.py. See ../../../docs/snippets-convention.md for the
# snippet:start/end convention — only the marked region is shown; the rest keeps
# the file importable.
import solana_pay_kit
from flask import Flask, jsonify
from solana_pay_kit import Gate, usd
from solana_pay_kit.flask import payment, require_payment

# snippet:start
solana_pay_kit.configure(network="solana_localnet")

gate = Gate.build(
    name="quote",
    amount=usd("0.01"),
    description="Stock quote",
    default_pay_to=solana_pay_kit.config().effective_recipient(),
    accept_default=solana_pay_kit.config().accept,
)

app = Flask(__name__)


# @require_payment settles the 402 (MPP or x402, the client's choice) before
# the view runs; the verified proof is readable via solana_pay_kit.flask.payment().
@app.get("${PATH}")
@require_payment(gate)
def quote():
    return jsonify(ok=True, protocol=payment().protocol.value)


# snippet:end
