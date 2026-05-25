"""Flask middleware that gates a view behind an MPP charge.

Exposes :func:`mpp_charge`, a decorator factory that:

- builds a route-aware charge challenge,
- returns a 402 with a ``WWW-Authenticate: Payment ...`` header when the
  request has no valid ``Authorization: Payment`` credential,
- otherwise verifies the credential and attaches the on-chain
  ``Payment-Receipt`` header to the wrapped view's response.
"""

from __future__ import annotations

import asyncio
import json
from functools import wraps

from flask import Response, jsonify, request

from solana_mpp._headers import format_www_authenticate, parse_authorization
from solana_mpp.protocol.intents import ChargeRequest
from solana_mpp.server.mpp import ChargeOptions, Mpp


def mpp_charge(mpp: Mpp, amount: str, description: str = ""):
    """Return a Flask view decorator that requires a paid MPP credential."""

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
