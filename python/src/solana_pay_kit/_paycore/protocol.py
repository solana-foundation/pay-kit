"""Wire-level payment protocol a credential proves.

The backing string is what crosses the wire (lowercase, matching the Rust
spine and the cross-SDK matrix tables). Mirrors PHP ``PayKit\\Protocol`` and
Ruby ``PayKit::Protocol``.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["Protocol"]


class Protocol(StrEnum):
    """Payment protocol advertised in an accepts entry and proven by a proof."""

    X402 = "x402"
    MPP = "mpp"
