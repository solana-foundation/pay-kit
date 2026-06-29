import pytest

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp


class _LegacyClientLackingAwaitConfirmation:
    async def send_raw_transaction(self, raw):
        pass

    async def get_transaction(self, sig, **kw):
        pass


def test_config_rpc_missing_method_rejected_at_init():
    cfg = Config(
        recipient="11111111111111111111111111111112",
        # Audit #24: secret must be >=32 bytes; use a valid one so the RPC
        # contract check is what fires, not the secret-length gate.
        secret_key="test-secret-key-that-is-long-enough-for-hmac-sha256",
        rpc=_LegacyClientLackingAwaitConfirmation(),
        store=MemoryStore(),
    )
    with pytest.raises(PaymentError) as exc:
        Mpp(cfg)
    assert "await_confirmation" in str(exc.value)
