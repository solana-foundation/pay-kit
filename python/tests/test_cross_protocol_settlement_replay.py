"""One Solana settlement must be consumable by only one payment protocol."""

from __future__ import annotations

import asyncio
import base64
import json
import struct

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey

import solana_pay_kit.protocols.mpp as mpp_module
import solana_pay_kit.protocols.x402 as x402_module
from solana_pay_kit import Gate, LocalSigner, MppConfig, Operator, Price, Protocol, Stablecoin, configure
from solana_pay_kit._middleware import PayCore
from solana_pay_kit._paycore.mints import derive_ata, resolve, token_program_for
from solana_pay_kit.config import reset
from solana_pay_kit.errors import InvalidProofError
from solana_pay_kit.payment import Payment
from solana_pay_kit.protocols.mpp.core.headers import format_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentCredential
from solana_pay_kit.protocols.x402.exact.verify import COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM
from tests.replay_store_test_support import NominalProductionReplayStore

_BLOCKHASH = "4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs"
_SETTLEMENT_SIGNATURE = "3Jf7XJ7pPqxwQzSg4QQy84B6YHf4fEo1RZxS4mZuewZdF4fG5xkGFB5h2sNWae1eS"
_MPP_SECRET = "cross-protocol-replay-fence-test-secret"
_resolved_mint = resolve("USDC", "devnet")
assert _resolved_mint is not None
_MINT: str = _resolved_mint
_TOKEN_PROGRAM: str = token_program_for("USDC", "devnet")
_AMOUNT = 100_000


class _Response:
    def __init__(self, value: object) -> None:
        self.value = value


class _RecordingProductionReplayStore(NominalProductionReplayStore):
    """Production-capable store double that retains the reservation identities."""

    def __init__(self) -> None:
        super().__init__()
        self.keys: list[str] = []
        self.deletes: list[str] = []

    async def put_if_absent(self, key: str, value: object) -> bool:
        self.keys.append(key)
        return await super().put_if_absent(key, value)

    async def delete(self, key: str) -> None:
        self.deletes.append(key)
        await super().delete(key)


class _InterleavingRpc:
    """Yield at broadcast so both real verifier paths reach the replay fence."""

    def __init__(self, wires: list[bytes], confirmed_transaction: dict[str, object]) -> None:
        self._wires = wires
        self._confirmed_transaction = confirmed_transaction

    async def send_raw_transaction(self, wire: bytes) -> _Response:
        self._wires.append(bytes(wire))
        await asyncio.sleep(0)
        return _Response(_SETTLEMENT_SIGNATURE)

    async def await_confirmation(self, _signature: str) -> None:
        await asyncio.sleep(0)

    async def get_transaction(self, _signature: str, **_kwargs: object) -> _Response:
        return _Response(self._confirmed_transaction)

    async def aclose(self) -> None:
        return None


class _Request:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers
        self.path = "/report"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    reset()
    monkeypatch.setenv("PAY_KIT_DISABLE_PREFLIGHT", "1")
    yield
    reset()


def _gate(config) -> Gate:
    return Gate.build(
        name="report",
        amount=Price.usd("0.10", Stablecoin.USDC),
        default_pay_to=config.effective_recipient(),
        accept=(Protocol.X402, Protocol.MPP),
        # x402 binds the path as a Memo; MPP accepts the same memo when it is
        # the route's external_id, so this one wire is valid under both schemes.
        external_id="/report",
    )


def _transaction_b64(operator: Keypair, gate: Gate, config) -> str:
    assert gate.external_id is not None
    customer = Keypair()
    destination = derive_ata(config.effective_recipient(), _MINT, _TOKEN_PROGRAM)
    source = derive_ata(str(customer.pubkey()), _MINT, _TOKEN_PROGRAM)
    compute_limit = Instruction(
        Pubkey.from_string(COMPUTE_BUDGET_PROGRAM),
        bytes([2]) + struct.pack("<I", 200_000),
        [],
    )
    compute_price = Instruction(
        Pubkey.from_string(COMPUTE_BUDGET_PROGRAM),
        bytes([3]) + struct.pack("<Q", 1_000),
        [],
    )
    transfer = Instruction(
        Pubkey.from_string(_TOKEN_PROGRAM),
        bytes([12]) + struct.pack("<Q", _AMOUNT) + bytes([6]),
        [
            AccountMeta(Pubkey.from_string(source), False, True),
            AccountMeta(Pubkey.from_string(_MINT), False, False),
            AccountMeta(Pubkey.from_string(destination), False, True),
            AccountMeta(customer.pubkey(), True, False),
        ],
    )
    memo = Instruction(Pubkey.from_string(MEMO_PROGRAM), gate.external_id.encode("utf-8"), [])
    message = MessageV0.try_compile(
        operator.pubkey(), [compute_limit, compute_price, transfer, memo], [], Hash.from_string(_BLOCKHASH)
    )
    num_signatures = int(message.header.num_required_signatures)
    wire = bytes([num_signatures]) + bytes(64 * num_signatures) + bytes(message)
    return base64.b64encode(wire).decode("ascii")


def _x402_header(core: PayCore, gate: Gate, transaction: str) -> str:
    assert core._x402 is not None
    accepted = core._x402.accepts_entry(gate, _Request({}))
    envelope = {
        "x402Version": 2,
        "accepted": accepted,
        "payload": {"transaction": transaction, "transactionHash": "test"},
    }
    return base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")


def _mpp_header(core: PayCore, gate: Gate, transaction: str) -> str:
    assert core._mpp is not None
    challenge = core._mpp._server_for(gate).charge_with_options(
        core._mpp._human_amount(gate), core._mpp._charge_options(gate)
    )
    return format_authorization(
        PaymentCredential(challenge=challenge.to_echo(), payload={"type": "transaction", "transaction": transaction})
    )


def _confirmed_transaction(config) -> dict[str, object]:
    destination = derive_ata(config.effective_recipient(), _MINT, _TOKEN_PROGRAM)
    return {
        "meta": {"err": None},
        "transaction": {
            "message": {
                "instructions": [
                    {
                        "programId": _TOKEN_PROGRAM,
                        "parsed": {
                            "type": "transferChecked",
                            "info": {
                                "destination": destination,
                                "mint": _MINT,
                                "tokenAmount": {"amount": str(_AMOUNT), "decimals": 6},
                            },
                        },
                    },
                    {"programId": MEMO_PROGRAM, "parsed": "/report"},
                ]
            }
        },
    }


@pytest.mark.asyncio
async def test_concurrent_cross_protocol_replay_consumes_one_network_qualified_settlement(
    monkeypatch: pytest.MonkeyPatch,
):
    operator_keypair = Keypair()
    config = configure(
        network="solana_devnet",
        preflight=False,
        accept=(Protocol.X402, Protocol.MPP),
        rpc_url="http://127.0.0.1:8899",
        mpp=MppConfig(challenge_binding_secret=_MPP_SECRET),
        operator=Operator(
            signer=LocalSigner.from_keypair(operator_keypair),
            recipient=str(Keypair().pubkey()),
            fee_payer=True,
        ),
    )
    store = _RecordingProductionReplayStore()
    core = PayCore(config, replay_store=store)
    gate = _gate(config)
    transaction = _transaction_b64(operator_keypair, gate, config)
    x402_header = _x402_header(core, gate, transaction)
    mpp_header = _mpp_header(core, gate, transaction)
    wires: list[bytes] = []

    def rpc_factory(*_args: object, **_kwargs: object) -> _InterleavingRpc:
        return _InterleavingRpc(wires, _confirmed_transaction(config))

    monkeypatch.setattr(x402_module, "SolanaRpc", rpc_factory)
    monkeypatch.setattr(mpp_module, "SolanaRpc", rpc_factory)

    results = await asyncio.gather(
        core.process(gate, None, _Request({"payment-signature": x402_header})),
        core.process(gate, None, _Request({"authorization": mpp_header})),
        return_exceptions=True,
    )

    payments = [result for result in results if isinstance(result, Payment)]
    replay_errors = [result for result in results if isinstance(result, InvalidProofError)]
    other_errors = [
        result for result in results if isinstance(result, BaseException) and not isinstance(result, InvalidProofError)
    ]

    assert not other_errors
    assert len(payments) == 1
    assert payments[0].transaction == _SETTLEMENT_SIGNATURE
    assert len(replay_errors) == 1
    assert replay_errors[0].code == "signature_consumed"
    assert len(wires) == 2
    assert wires[0] == wires[1]
    canonical_key = f"solana-settlement:consumed:{config.network.caip2()}:{_SETTLEMENT_SIGNATURE}"
    legacy_charge_key = f"solana-charge:consumed:{_SETTLEMENT_SIGNATURE}"
    legacy_x402_key = f"x402-svm-exact:consumed:{_SETTLEMENT_SIGNATURE}"
    # Both workers race the canonical key first; only the winner goes on to
    # claim the rolling-upgrade legacy markers.
    assert sorted(store.keys) == sorted([canonical_key, canonical_key, legacy_charge_key, legacy_x402_key])
    for key in (canonical_key, legacy_charge_key, legacy_x402_key):
        assert await store.get(key) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_prefix", ["solana-charge:consumed:", "x402-svm-exact:consumed:"])
@pytest.mark.parametrize("protocol_header", ["x402", "mpp"])
async def test_legacy_settlement_marker_blocks_upgraded_workers(
    monkeypatch: pytest.MonkeyPatch, legacy_prefix: str, protocol_header: str
):
    """Rolling upgrade: a signature consumed by a not-yet-upgraded worker
    (which wrote only its protocol's legacy un-qualified marker) must not
    settle again through an upgraded worker of either protocol."""
    operator_keypair = Keypair()
    config = configure(
        network="solana_devnet",
        preflight=False,
        accept=(Protocol.X402, Protocol.MPP),
        rpc_url="http://127.0.0.1:8899",
        mpp=MppConfig(challenge_binding_secret=_MPP_SECRET),
        operator=Operator(
            signer=LocalSigner.from_keypair(operator_keypair),
            recipient=str(Keypair().pubkey()),
            fee_payer=True,
        ),
    )
    store = _RecordingProductionReplayStore()
    await store.put(f"{legacy_prefix}{_SETTLEMENT_SIGNATURE}", True)
    core = PayCore(config, replay_store=store)
    gate = _gate(config)
    transaction = _transaction_b64(operator_keypair, gate, config)
    wires: list[bytes] = []

    def rpc_factory(*_args: object, **_kwargs: object) -> _InterleavingRpc:
        return _InterleavingRpc(wires, _confirmed_transaction(config))

    monkeypatch.setattr(x402_module, "SolanaRpc", rpc_factory)
    monkeypatch.setattr(mpp_module, "SolanaRpc", rpc_factory)

    if protocol_header == "x402":
        request = _Request({"payment-signature": _x402_header(core, gate, transaction)})
    else:
        request = _Request({"authorization": _mpp_header(core, gate, transaction)})

    with pytest.raises(InvalidProofError) as exc_info:
        await core.process(gate, None, request)
    assert exc_info.value.code == "signature_consumed"
    # A losing claim must never delete another worker's marker: that would
    # reopen the signature the old worker already settled.
    assert store.deletes == []
    assert await store.get(f"{legacy_prefix}{_SETTLEMENT_SIGNATURE}") is True
