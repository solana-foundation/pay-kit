import pytest

from solana_mpp._errors import PaymentError
from solana_mpp.server.mpp import Config, Mpp
from solana_mpp.store import MemoryStore


class _LegacyClientLackingAwaitConfirmation:
    async def send_raw_transaction(self, raw):
        pass

    async def get_transaction(self, sig, **kw):
        pass


def test_config_rpc_missing_method_rejected_at_init():
    cfg = Config(
        recipient="11111111111111111111111111111112",
        secret_key="s",
        rpc=_LegacyClientLackingAwaitConfirmation(),
        store=MemoryStore(),
    )
    with pytest.raises(PaymentError) as exc:
        Mpp(cfg)
    assert "await_confirmation" in str(exc.value)
