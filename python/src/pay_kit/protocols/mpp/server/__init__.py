"""Server-side Solana MPP handler."""

from __future__ import annotations

from pay_kit.protocols.mpp.server.charge import ChargeOptions, Config, Mpp
from pay_kit.protocols.mpp.server.defaults import detect_realm, detect_secret_key
from pay_kit.protocols.mpp.server.payment_page import (
    accepts_html,
    challenge_to_html,
    is_service_worker_request,
    service_worker_js,
)

__all__ = [
    "ChargeOptions",
    "Config",
    "Mpp",
    "accepts_html",
    "challenge_to_html",
    "detect_realm",
    "detect_secret_key",
    "is_service_worker_request",
    "service_worker_js",
]
