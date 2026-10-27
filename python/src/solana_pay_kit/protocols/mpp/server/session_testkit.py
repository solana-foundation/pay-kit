"""Conformance hooks for the session server: the offline checks it makes on
``open`` and ``topUp`` credentials before broadcasting.

Not a payment verifier: nothing here binds the challenge HMAC, stores the
channel, or broadcasts. Use :class:`~solana_pay_kit.protocols.mpp.server.session.SessionServer`
(through :func:`~solana_pay_kit.protocols.mpp.server.session_method.new_session`)
to accept payments. Mirrors ``mpp::server::session::testkit`` in the Rust kit.
"""

from __future__ import annotations

import base64

from solana_pay_kit._paycore.errors import PaymentError
from solana_pay_kit.protocols.mpp.intents.session import OpenPayload, TopUpPayload
from solana_pay_kit.protocols.mpp.server.session import SessionOpenContext, SessionServer
from solana_pay_kit.protocols.mpp.server.session_onchain import (
    cosign_session_transaction,
    open_tx_expected,
    prepare_topup_transaction,
    verify_open_tx,
)

__all__ = [
    "verify_open_pre_broadcast",
    "verify_open_transaction_pre_broadcast",
    "verify_topup_pre_broadcast",
]


async def _prepare_open(server: SessionServer, payload: OpenPayload, recent_blockhash: str) -> bytes:
    """The transaction half of the open checks: accepted version and budget,
    the challenged blockhash, the fee payer, exactly the declared open
    instruction with matching privileges, and the client's signatures, then
    the sponsor's co-signature in memory. Returns the transaction the server
    would broadcast."""
    config = server.config
    expected = open_tx_expected(config, payload, recent_blockhash)
    await verify_open_tx(expected, payload, None)
    raw = base64.b64decode(payload.transaction, validate=True)
    if config.fee_payer:
        if config.fee_payer_signer is None:
            raise PaymentError("fee-payer signing requires a configured signer", code="invalid-config")
        raw = await cosign_session_transaction(raw, config.fee_payer_signer)
    return raw


async def verify_open_transaction_pre_broadcast(
    server: SessionServer, payload: OpenPayload, challenged_blockhash: str
) -> None:
    """The open parameters the payload declares, against the server's
    configuration (:meth:`SessionServer.payment_channel_open_params`), then
    the transaction checks against ``challenged_blockhash``."""
    server.payment_channel_open_params(payload)
    await _prepare_open(server, payload, challenged_blockhash)


async def verify_open_pre_broadcast(server: SessionServer, payload: OpenPayload, context: SessionOpenContext) -> None:
    """Every check :meth:`SessionServer.process_open` makes on an ``open``
    credential before it broadcasts, in its order: the credential (challenge
    expiry, idle timeout, deposit, the open parameters, the ``openSlot``
    window against ``context.recent_slot``, the voucher-signer mode and
    bearer proof), then the transaction. The window against the live cluster
    slot needs RPC and is not part of it."""
    server._validate_open_request(payload, context)
    await _prepare_open(server, payload, context.recent_blockhash)


async def verify_topup_pre_broadcast(server: SessionServer, payload: TopUpPayload) -> None:
    """Every check :meth:`SessionServer.process_top_up` makes on a ``topUp``
    credential before it broadcasts: a positive ``additionalAmount`` for a
    stored channel that is still open, then the transaction
    (co-signed in memory when the channel's rent payer is the sponsor)."""
    state = await server.topup_channel(payload)
    await prepare_topup_transaction(payload, state, server.config)
