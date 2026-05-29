"""x402 ``exact`` (Solana) protocol package.

Public surface mirrors the former flat ``pay_kit.protocols.x402`` module:
the ``X402Adapter`` server adapter plus the ``ExactVerifier`` structural
verifier and the ``X402_VERSION`` constant. The verifier, adapter, and the
``X402*`` wire TypedDicts live in :mod:`pay_kit.protocols.x402.verify`.
"""

from __future__ import annotations

from pay_kit.protocols.x402.verify import X402_VERSION, ExactVerifier, X402Adapter

__all__ = ["X402Adapter", "ExactVerifier", "X402_VERSION"]
