# examples/django/views.py
"""Django views + URLconf gated with pay_kit (snippet, not a full project).

Zero-config: ``pay_kit.configure()`` boots against solana_localnet (the
hosted Surfpool sandbox at https://402.surfnet.dev:8899) with the shipped
demo signer as the recipient.

Wire this into any Django project: drop the gate definitions and views
below into an app, then ``path("report/", views.report)`` in your URLconf
(the ``urlpatterns`` at the bottom of this file is ready to ``include()``).
``pay_kit.configure(...)`` belongs in ``settings.py`` or ``apps.py.ready()``
so it runs once at startup.

Two routes:

    GET /health  -> free, returns {"ok": true}
    GET /report  -> gated. require_payment returns 402 with the challenge
                    until a valid proof arrives, then sets request.payment.

Drive it from a client once the project is running:

    curl -i http://127.0.0.1:8000/report     # 402 payment required
    pay curl http://127.0.0.1:8000/report    # pays and succeeds
"""

from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.urls import path

import pay_kit
from pay_kit import Gate, usd
from pay_kit.django import require_payment

pay_kit.configure(network="solana_localnet")

report_gate = Gate.build(
    name="report",
    amount=usd("0.10"),
    description="Premium report",
    default_pay_to=pay_kit.config().effective_recipient(),
    accept_default=pay_kit.config().accept,
)


def health(_request: HttpRequest) -> JsonResponse:
    """Free liveness probe."""
    return JsonResponse({"ok": True})


@require_payment(report_gate)
def report(request: HttpRequest) -> JsonResponse:
    """Paid route. The verified proof is on request.payment after gating."""
    proof = request.payment  # type: ignore[attr-defined]
    return JsonResponse({"ok": True, "tx": proof.transaction, "protocol": proof.protocol.value})


urlpatterns = [
    path("health/", health),
    path("report/", report),
]
