"""Protocol adapters that bridge gates to the pay_kit.protocols.mpp wire layer."""

from __future__ import annotations

from pay_kit.protocols.mpp import MppAdapter, SecretResolver

__all__ = ["MppAdapter", "SecretResolver"]
