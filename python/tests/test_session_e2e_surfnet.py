"""Surfnet-gated end-to-end session lifecycle test.

Exercises the real on-chain paths against the hosted Solana Payment Sandbox:
a server-broadcast payment-channel open (openTxSubmitter=server, the A4 path),
an in-band voucher, and the on-chain settle-at-close (the A2 path), asserting
the open and settle transactions confirm on-chain. Mirrors Go's
session_e2e_test.go. Skips explicitly (never silently passes) when the sandbox
is unreachable, so CI without the sandbox stays green.

Run against the sandbox:
    MPP_RUN_SURFNET_E2E=1 uv run pytest tests/test_session_e2e_surfnet.py
"""

from __future__ import annotations

import os

import pytest
from solders.keypair import Keypair  # type: ignore[import-untyped]
from solders.signature import Signature  # type: ignore[import-untyped]

from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM, resolve_mint
from solana_pay_kit.protocols.mpp.client.payment_channels import create_payment_channel_session_opener
from solana_pay_kit.protocols.mpp.intents.session import ClosePayload, SessionRequest, VoucherPayload
from solana_pay_kit.protocols.mpp.server import SessionOptions, new_session
from solana_pay_kit.signer import LocalSigner

_RPC_URL = os.environ.get("MPP_HARNESS_RPC_URL", "https://402.surfnet.dev:8899")
_USDC = resolve_mint("USDC", "localnet")
pytestmark = pytest.mark.asyncio


async def _reachable(rpc: SolanaRpc) -> bool:
    if os.environ.get("MPP_RUN_SURFNET_E2E") != "1":
        return False
    try:
        await rpc._call("getHealth", [])
        return True
    except Exception:
        return False


async def _set_account(rpc: SolanaRpc, owner: str, lamports: int) -> None:
    await rpc._call(
        "surfnet_setAccount",
        [
            owner,
            {
                "lamports": lamports,
                "data": "",
                "executable": False,
                "owner": "11111111111111111111111111111111",
                "rentEpoch": 0,
            },
        ],
    )


async def _set_token_account(rpc: SolanaRpc, owner: str, amount: int) -> None:
    await rpc._call(
        "surfnet_setTokenAccount", [owner, _USDC, {"amount": amount, "state": "initialized"}, TOKEN_PROGRAM]
    )


async def test_session_lifecycle_settles_on_chain() -> None:
    rpc = SolanaRpc(_RPC_URL)
    try:
        if not await _reachable(rpc):
            pytest.skip("surfnet sandbox unreachable or MPP_RUN_SURFNET_E2E not set")

        # operator: fee-payer + settlement signer (proceeds recipient).
        # payer: funds the channel deposit and partial-signs the open.
        operator = Keypair()
        payer = Keypair()
        await _set_account(rpc, str(operator.pubkey()), 10_000_000_000)
        await _set_account(rpc, str(payer.pubkey()), 10_000_000_000)
        await _set_token_account(rpc, str(payer.pubkey()), 100_000_000)
        await _set_token_account(rpc, str(operator.pubkey()), 0)

        session = new_session(
            SessionOptions(
                operator=str(operator.pubkey()),
                recipient=str(operator.pubkey()),
                amount=250,
                currency="USDC",
                decimals=6,
                network="localnet",
                secret_key="session-e2e-secret-key-32-bytes-min!!",
                suggested_deposit=1_000_000,
                fee_payer=True,
                signer=LocalSigner.from_keypair(operator),
                rpc=rpc,
            )
        )

        challenge = await session.challenge()
        request = SessionRequest.from_dict(challenge.decode_request())
        # The challenge advertises the open-transaction context
        # (recentBlockhash/recentSlot); the client never fetches its own — the
        # open transaction and openSlot default to the challenged values.
        assert request.method_details.recent_blockhash
        assert request.method_details.recent_slot is not None
        # The client builds the open and partial-signs as the payer; the server
        # completes the operator fee-payer signature and broadcasts.
        opener = create_payment_channel_session_opener(
            request,
            payer,
            Keypair(),
        )
        payload = opener.action.open
        assert payload is not None

        # 1. The server co-signs, broadcasts, confirms, and verifies the exact open.
        open_signature = await session._handle_open(payload, challenge)
        Signature.from_string(open_signature)  # valid on-chain signature
        channel_id = opener.open.channel_id
        state = await session._core.store().get_channel(str(channel_id))
        assert state is not None

        # 2. In-band voucher advances the watermark.
        voucher = opener.session.prepare_increment(250)
        opener.session.record_voucher(voucher)
        await session._handle_voucher(VoucherPayload(voucher.data.channel_id, voucher))

        # 3. Close settles the highest voucher on-chain and seals.
        close_reference = await session._handle_close(ClosePayload(channel_id=str(channel_id), voucher=voucher))
        settled = await session._core.store().get_channel(str(channel_id))
        assert settled is not None and settled.sealed and settled.settled_signature
        # The settle transaction confirmed on-chain.
        statuses = await rpc._call(
            "getSignatureStatuses", [[settled.settled_signature], {"searchTransactionHistory": True}]
        )
        status = statuses["value"][0]
        assert status is not None and status.get("err") is None
        assert close_reference == settled.settled_signature
    finally:
        await rpc.aclose()
