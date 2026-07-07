"""Payment decorator for ASGI/Starlette-style handlers."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from solana_pay_kit._paycore.errors import PaymentError, payment_required_response
from solana_pay_kit.protocols.mpp.core.headers import format_www_authenticate, parse_authorization
from solana_pay_kit.protocols.mpp.server.charge import Mpp


def pay(mpp_handler: Mpp, amount: str, **options: Any) -> Callable:
    """Decorator for ASGI/Starlette-style handlers.

    Wraps a handler to automatically handle 402 Payment Required flows.
    The decorated handler receives (request, credential, receipt) when
    payment is verified.

    Example:
        @app.get("/paid")
        @pay(mpp, amount="0.50")
        async def handler(request, credential, receipt):
            return {"data": "paid content"}
    """
    from solana_pay_kit.protocols.mpp.intents.charge import ChargeRequest
    from solana_pay_kit.protocols.mpp.server.charge import ChargeOptions

    charge_options = ChargeOptions(
        description=options.get("description", ""),
        external_id=options.get("external_id", ""),
        expires=options.get("expires", ""),
        fee_payer=options.get("fee_payer", False),
        splits=options.get("splits", []),
    )

    def decorator(handler: Callable) -> Callable:
        @functools.wraps(handler)
        async def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
            # Build the route's expected charge first so verification can be
            # route-aware: the credential's claimed amount is compared to this
            # route's expected amount, not just to itself.
            challenge = mpp_handler.charge_with_options(amount, charge_options)

            # Try to get Authorization header
            auth_header = None
            if hasattr(request, "headers"):
                auth_header = request.headers.get("authorization")

            verification_error: PaymentError | None = None
            if auth_header:
                try:
                    credential = parse_authorization(auth_header)
                    expected = ChargeRequest.from_dict(challenge.decode_request())
                    receipt = await mpp_handler.verify_credential_with_expected(credential, expected)
                    return await handler(request, credential, receipt, *args, **kwargs)
                except PaymentError as err:
                    verification_error = err
                except Exception as err:  # noqa: BLE001 (catch-all for framework parse errors)
                    verification_error = PaymentError(str(err), code="payment_invalid")

            # Issue (or re-issue) a 402 with a canonical L6 code in the body.
            www_auth = format_www_authenticate(challenge)
            if verification_error is None:
                response = payment_required_response(
                    "Payment required",
                    code="payment_invalid",
                    challenge_header=www_auth,
                )
            else:
                response = payment_required_response(
                    str(verification_error) or "Payment required",
                    code=verification_error.code or "payment_invalid",
                    challenge_header=www_auth,
                )
            response["__mpp_challenge"] = True
            response["challenge"] = challenge
            return response

        return wrapper

    return decorator
