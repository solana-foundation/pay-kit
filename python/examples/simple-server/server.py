# examples/simple-server/server.py
"""Gate one HTTP endpoint with the unified solana_pay_kit surface, no framework.

This is the smallest possible solana_pay_kit server: the Python standard-library
``http.server`` plus the framework-agnostic ``PayCore`` umbrella core. One
gated route, sensible defaults, both protocols (x402 and MPP) accepted.

Zero-config: ``solana_pay_kit.configure()`` boots against solana_localnet (the
hosted Surfpool sandbox) with the shipped demo signer as the recipient, so
the example runs without any wallet setup.

Run:

    pip install -e .
    python examples/simple-server/server.py

Drive it from a client:

    curl -i http://127.0.0.1:8000/report     # 402 payment required
    pay curl http://127.0.0.1:8000/report    # pays and succeeds
"""

from __future__ import annotations

import asyncio
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import solana_pay_kit
from solana_pay_kit import Gate, PayCore, usd
from solana_pay_kit.errors import InvalidProofError, PaymentRequiredError

solana_pay_kit.configure(network="solana_localnet")

_core = PayCore.for_config(solana_pay_kit.config())

report_gate = Gate.build(
    name="report",
    amount=usd("0.10"),
    description="Premium report",
    default_pay_to=solana_pay_kit.config().effective_recipient(),
    accept_default=solana_pay_kit.config().accept,
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server callback name
        if self.path.split("?", 1)[0] != "/report":
            self._json(404, {"error": "not_found"})
            return
        request = {"path": self.path, "headers": dict(self.headers.items())}
        try:
            payment = asyncio.run(_core.process(report_gate, None, request))
        except PaymentRequiredError as exc:
            self._json(402, exc.body, extra_headers=exc.challenge_headers)
            return
        except InvalidProofError as exc:
            self._json(402, {"error": exc.code or "payment_invalid", "detail": str(exc)})
            return
        self._json(
            200,
            {"ok": True, "tx": payment.transaction, "protocol": payment.protocol.value},
            extra_headers=payment.settlement_headers,
        )

    def _json(self, status: int, body: object, extra_headers: dict[str, str] | None = None) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args: object) -> None:
        """Silence the default stderr access log."""


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
