"""x402 ``batch-settlement`` (SVM) scheme: wire types, stateless checks, the
sponsor's transaction policy, the channel store and the resource-server engine.

See ``scheme_batch_settlement_svm.md``. The client builders live in
:mod:`solana_pay_kit.protocols.x402.client.batch_settlement`.
"""

from __future__ import annotations

from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError, classify, leading_code
from solana_pay_kit.protocols.x402.batch_settlement.server import (
    BatchAccess,
    BatchAccessKind,
    BatchConfig,
    BatchOutcome,
    InvalidPaymentRequiredError,
    UnsupportedSchemeError,
    X402BatchSettlement,
)
from solana_pay_kit.protocols.x402.batch_settlement.store import (
    BatchChannelRecord,
    BatchChannelStore,
    ChannelBinding,
    MemoryBatchChannelStore,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BATCH_SETTLEMENT_SCHEME,
    BatchChannelConfig,
    BatchPayload,
    BatchPaymentPayload,
    BatchRequiredEnvelope,
    BatchRequirements,
    BatchSettlementResponse,
    BatchVoucher,
    BatchWireError,
)

__all__ = [
    "BATCH_SETTLEMENT_SCHEME",
    "BatchAccess",
    "BatchAccessKind",
    "BatchChannelConfig",
    "BatchChannelRecord",
    "BatchChannelStore",
    "BatchConfig",
    "BatchOutcome",
    "BatchPayload",
    "BatchPaymentPayload",
    "BatchRequiredEnvelope",
    "BatchRequirements",
    "BatchSettlementError",
    "BatchSettlementResponse",
    "BatchVoucher",
    "BatchWireError",
    "ChannelBinding",
    "InvalidPaymentRequiredError",
    "MemoryBatchChannelStore",
    "UnsupportedSchemeError",
    "X402BatchSettlement",
    "classify",
    "leading_code",
]
