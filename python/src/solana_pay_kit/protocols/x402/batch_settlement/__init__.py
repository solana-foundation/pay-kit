"""x402 ``batch-settlement`` (Solana) scheme: deposit once, pay per request with cumulative vouchers.

The client escrows funds in a payment-channels channel, then signs a
cumulative Ed25519 voucher per request; the server verifies it off-chain,
serves, and redeems the latest voucher on-chain later, in batches. Wire types
and parsers live in :mod:`.types`, failure codes in :mod:`.errors`, signed
encodings in :mod:`.signatures`.

Byte and field compatible with the Rust ``x402::protocol::schemes::batch_settlement``
for client-signed vouchers; the server-signed mode (``voucherSigner: "server"``)
follows the x402 PR #23 spec and is Python-to-Python only.
"""

from __future__ import annotations

import weakref
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from solana_pay_kit.config import Config
    from solana_pay_kit.protocols.x402.batch_settlement.engine import X402BatchSettlement

__all__ = ["batch_engine"]

# One engine per Config: it owns the channel store, the reservations and the
# redemption worker, so the framework shims and ``x402_batch()`` must share it.
_ENGINES: weakref.WeakKeyDictionary[Config, X402BatchSettlement] = weakref.WeakKeyDictionary()


def batch_engine(config: Config) -> X402BatchSettlement:
    """The per-``Config`` ``batch-settlement`` engine, built on first use."""
    engine = _ENGINES.get(config)
    if engine is None:
        # Imported here: the engine loads config, gate and pricing, which must
        # not load when only the wire types are needed.
        from solana_pay_kit.protocols.x402.batch_settlement.engine import X402BatchSettlement
        from solana_pay_kit.usage import fetch_recent_blockhash_and_slot

        engine = X402BatchSettlement(
            config, recent_state_provider=lambda: fetch_recent_blockhash_and_slot(config.effective_rpc_url())
        )
        _ENGINES[config] = engine
    return engine
