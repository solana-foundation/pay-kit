"""x402 ``exact`` client: challenge parsing, payment building, auto-pay transport."""

from __future__ import annotations

from pay_kit._paycore.rpc import SolanaRpc
from pay_kit.protocols.x402.client.exact import (
    PAYMENT_SIGNATURE_HEADER,
    ChallengeSelection,
    PaymentTransport,
    X402Client,
    build_payment,
    build_payment_header,
    parse_x402_challenge,
    x402_async_client,
)

__all__ = [
    "ChallengeSelection",
    "parse_x402_challenge",
    "build_payment",
    "build_payment_header",
    "PaymentTransport",
    "X402Client",
    "x402_async_client",
    "PAYMENT_SIGNATURE_HEADER",
    # RPC client for the auto-pay transport's required ``rpc`` argument
    "SolanaRpc",
]
