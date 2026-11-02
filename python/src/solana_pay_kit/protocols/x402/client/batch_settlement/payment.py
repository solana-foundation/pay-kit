"""Client-side payment building for the SVM ``batch-settlement`` scheme.

The client opens one escrow channel, then pays per request by signing a
cumulative voucher; no onchain transaction is in the request path after the
first. :class:`BatchChannel` tracks the cumulative watermark for one channel and
advances only on a confirmed ``PAYMENT-RESPONSE``
(:meth:`BatchChannel.apply_payment_response`): a payment payload is an
authorization, not a receipt. Mirrors the Rust kit
(``x402/client/batch_settlement/payment.rs``).
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.paymentchannels import (
    OPEN_MAX_COMPUTE_UNIT_LIMIT,
    OPEN_MAX_MEMO_BYTES,
    PROGRAM_ID,
    Distribution,
    OpenChannelParams,
    TopUpParams,
    build_open_instruction,
    build_top_up_instruction,
    find_channel_pda,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.solana import MEMO_PROGRAM
from solana_pay_kit._paycore.transaction import build_partially_signed_transaction
from solana_pay_kit.protocols.x402.batch_settlement.errors import (
    INVALID_CHANNEL_ID_MISMATCH,
    INVALID_CHANNEL_STATE,
    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
    INVALID_FEE_PAYER_MISMATCH,
    INVALID_TOKEN_PROGRAM,
    INVALID_VOUCHER_SIGNATURE,
    BatchSettlementError,
)
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    BATCH_SETTLEMENT_SCHEME,
    VOUCHER_EXPIRES_AT,
    BatchAuthorization,
    BatchChannelConfig,
    BatchDeposit,
    BatchPayload,
    BatchPaymentPayload,
    BatchRequiredEnvelope,
    BatchRequirements,
    BatchSettlementResponse,
    BatchVoucher,
)
from solana_pay_kit.protocols.x402.batch_settlement.verify import (
    authorization_message_bytes,
    check_corrective_voucher_state,
    check_payment_flow,
    check_token_program,
    check_voucher,
    check_withdraw_delay,
    derive_channel_id,
    parse_pubkey,
    receiver_binding_memo,
)

if TYPE_CHECKING:
    from solana_keychain import TransactionSigner

__all__ = [
    "PAYMENT_SIGNATURE_HEADER",
    "BatchChannel",
    "BatchTerms",
    "ServerSignedChannelsPolicy",
    "build_deposit",
    "build_refund",
    "build_refund_request_close",
    "build_top_up",
    "channel_id_for",
    "corrective_channel_id",
    "encode_payment_header",
    "parse_challenge",
    "resolve_terms",
    "resolve_terms_with_token_program",
    "sign_authorization",
    "sign_voucher",
]

PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
_PAYMENT_REQUIRED_HEADER = "payment-required"
_X402_VERSION_V2 = 2
_MEMO_NONCE_BYTES = 16
_REQUEST_CLOSE_DISCRIMINATOR = 5


def _err(code: str, detail: str) -> BatchSettlementError:
    return BatchSettlementError(code, detail)


def _random_hex_nonce() -> str:
    return secrets.token_hex(_MEMO_NONCE_BYTES)


class ServerSignedChannelsPolicy:
    """Explicit, local trust grants for server-signed channels.

    In server mode the operator becomes the channel's onchain
    ``authorized_signer`` and can claim up to the full deposit, so a 402 is
    never sufficient authority by itself: the caller allowlists the exact
    operator and bounds the escrow it may control.
    """

    def __init__(self) -> None:
        self._operators: dict[Pubkey, int] = {}

    def allow_operator(self, operator: Pubkey, max_deposit: int) -> ServerSignedChannelsPolicy:
        if max_deposit <= 0:
            raise ValueError("server-signed max_deposit must be positive")
        self._operators[operator] = max_deposit
        return self

    def max_deposit_for(self, operator: Pubkey) -> int | None:
        return self._operators.get(operator)


@dataclass(frozen=True)
class BatchTerms:
    """A challenge's terms, after the checks the client owes itself."""

    fee_payer: Pubkey
    mint: Pubkey
    token_program: Pubkey
    receiver: Pubkey
    withdraw_delay: int
    amount: int
    #: ``extra.memo``, or a fresh hex nonce when the seller declared none.
    memo: str
    #: The receiver-binding Memo every ``open`` carries beside :attr:`memo`.
    binding_memo: str
    #: The message version to build: the highest advertised one the signer signs.
    tx_version: int
    operator: Pubkey | None = None
    server_signed_max_deposit: int | None = None
    authorization_ttl_seconds: int = 300

    @property
    def continuation_memo(self) -> str:
        """Memo for top-ups and refunds: the same text (binding is open-only)."""
        return self.memo


def resolve_terms_with_token_program(
    requirements: BatchRequirements,
    token_program: Pubkey,
    max_tx_version: int | None = None,
    policy: ServerSignedChannelsPolicy | None = None,
) -> BatchTerms:
    """Validate a challenge's terms offline; ``token_program`` must already be
    the mint's confirmed onchain owner (see :func:`resolve_terms`)."""
    extra = requirements.extra
    check_payment_flow(extra.payment_flow)
    operator: Pubkey | None = None
    max_deposit: int | None = None
    if extra.voucher_signer in (None, "client"):
        if extra.operator is not None:
            raise ValueError('extra.operator is only valid when extra.voucherSigner is "server"')
    elif extra.voucher_signer == "server":
        if extra.operator is None:
            raise ValueError('extra.operator is required when extra.voucherSigner is "server"')
        operator = parse_pubkey(extra.operator)
        max_deposit = policy.max_deposit_for(operator) if policy is not None else None
        if max_deposit is None:
            raise ValueError(
                f"server-signed batch operator {extra.operator} is not trusted; add an explicit local operator "
                "grant with a maximum deposit"
            )
    else:
        raise ValueError(f'extra.voucherSigner must be "client" or "server", got {extra.voucher_signer!r}')
    check_withdraw_delay(extra.withdraw_delay, requirements.max_timeout_seconds)
    declared = check_token_program(extra.token_program)
    if declared != token_program:
        raise _err(
            INVALID_TOKEN_PROGRAM, f"extra.tokenProgram {extra.token_program} does not own asset {requirements.asset}"
        )
    if extra.receiver_authorizer is None:
        raise ValueError("batch-settlement challenge carries no extra.receiverAuthorizer")
    return BatchTerms(
        fee_payer=parse_pubkey(extra.fee_payer),
        mint=parse_pubkey(requirements.asset),
        token_program=token_program,
        receiver=parse_pubkey(requirements.pay_to),
        withdraw_delay=extra.withdraw_delay,
        amount=requirements.amount_units(),
        memo=extra.memo if extra.memo is not None else _random_hex_nonce(),
        binding_memo=receiver_binding_memo(parse_pubkey(extra.receiver_authorizer)),
        tx_version=txv1.negotiate(extra.transaction_versions, max_tx_version),
        operator=operator,
        server_signed_max_deposit=max_deposit,
        authorization_ttl_seconds=max(requirements.max_timeout_seconds, 1),
    )


async def resolve_terms(
    rpc: SolanaRpc,
    requirements: BatchRequirements,
    max_tx_version: int | None = None,
    policy: ServerSignedChannelsPolicy | None = None,
) -> BatchTerms:
    """Validate a challenge's terms, confirming the advertised token program
    really owns the asset (every ATA in the ``open`` derives from it)."""
    mint = parse_pubkey(requirements.asset)
    account = await rpc.get_account_info(str(mint))
    if account is None:
        raise ValueError(f"mint fetch failed: account {mint} not found")
    return resolve_terms_with_token_program(requirements, parse_pubkey(account[1]), max_tx_version, policy)


async def sign_voucher(signer: TransactionSigner, channel_id: Pubkey, max_claimable: int) -> BatchVoucher:
    """Sign a never-expiring cumulative voucher over the 50-byte message."""
    message = voucher_message_bytes(channel_id, max_claimable, VOUCHER_EXPIRES_AT)
    signature = await signer.sign_message(message)
    return BatchVoucher(
        channel_id=str(channel_id),
        max_claimable_amount=str(max_claimable),
        expires_at=VOUCHER_EXPIRES_AT,
        signature=str(signature),
    )


async def sign_authorization(
    signer: TransactionSigner,
    channel_id: Pubkey,
    operator: Pubkey,
    request_id: str,
    authorized_amount: int,
    expires_at: int,
) -> BatchAuthorization:
    """Sign an expiring, single-request payer proof for ``operator`` (server mode)."""
    payer = signer.pubkey
    message = authorization_message_bytes(channel_id, payer, operator, request_id, authorized_amount, expires_at)
    signature = await signer.sign_message(message)
    return BatchAuthorization(
        channel_id=str(channel_id),
        payer=str(payer),
        request_id=request_id,
        authorized_amount=str(authorized_amount),
        expires_at=expires_at,
        signature=str(signature),
    )


def _authorization_expires_at(ttl_seconds: int) -> int:
    return int(time.time()) + max(ttl_seconds, 1)


def _int(value: str | None, code: str, label: str) -> int:
    try:
        if value is None or not value.isascii() or not value.isdigit():
            raise ValueError
        return int(value, 10)
    except ValueError as exc:
        raise _err(code, f"invalid {label}") from exc


class BatchChannel:
    """A client's view of one channel: its configuration and the cumulative the
    server has confirmed charging."""

    def __init__(
        self,
        channel_id: Pubkey,
        config: BatchChannelConfig,
        charged_cumulative_amount: int,
        deposit: int,
        *,
        history_complete: bool = True,
    ) -> None:
        self.channel_id = channel_id
        self.config = config
        self.charged_cumulative_amount = charged_cumulative_amount
        self.deposit = deposit
        self._history_complete = history_complete

    def can_cover(self, amount: int) -> bool:
        """Whether one more request still fits under the deposit (else top up)."""
        return self.charged_cumulative_amount + amount <= self.deposit

    async def sign_next_voucher(self, signer: TransactionSigner, amount: int) -> BatchVoucher:
        """Sign the next cumulative voucher without advancing local state."""
        return await sign_voucher(signer, self.channel_id, self.charged_cumulative_amount + amount)

    async def voucher_payload(self, signer: TransactionSigner, amount: int) -> BatchPayload:
        """A steady-state ``voucher`` payload for one request."""
        return BatchPayload(
            type="voucher", channel_config=self.config, voucher=await self.sign_next_voucher(signer, amount)
        )

    async def authorization_payload(self, signer: TransactionSigner, amount: int, expires_at: int) -> BatchPayload:
        """A single-use payer proof for a server-signed channel."""
        if self.config.voucher_signer != "server":
            raise ValueError("client-signed channels do not use payer authorizations")
        authorization = await sign_authorization(
            signer, self.channel_id, parse_pubkey(self.config.payer_authorizer), _random_hex_nonce(), amount, expires_at
        )
        return BatchPayload(type="authorization", channel_config=self.config, authorization=authorization)

    def apply_payment_response(
        self, response: BatchSettlementResponse, requirements: BatchRequirements, submitted: BatchVoucher
    ) -> None:
        """Adopt the server's confirmed state from a successful ``PAYMENT-RESPONSE``.

        The response must confirm the exact commitment sent: a non-empty
        ``commitmentId``, the advertised price, and a cumulative equal to the
        voucher this client signed.
        """
        if not response.success:
            raise _err(INVALID_CHANNEL_STATE, response.error_reason or "settlement failed")
        extra = response.extra
        if extra is None:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE has no extra")
        if not extra.commitment_id:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE carries no commitmentId")
        if extra.charged_amount != requirements.amount:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE charged an amount other than the advertised price")
        state = extra.channel_state
        if state is None:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE has no channelState")
        if state.charged_cumulative_amount is None:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE channelState has no chargedCumulativeAmount")
        charged = _int(state.charged_cumulative_amount, INVALID_CHANNEL_STATE, "chargedCumulativeAmount")
        submitted_cumulative = submitted.max_claimable()
        if charged != submitted_cumulative:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH, f"server charged {charged}, submitted {submitted_cumulative}"
            )
        self.deposit = _int(state.balance, INVALID_CHANNEL_STATE, "channelState.balance")
        self.charged_cumulative_amount = charged

    def apply_authorization_response(
        self,
        response: BatchSettlementResponse,
        authorization: BatchAuthorization,
        confirmed_deposit: int | None = None,
    ) -> None:
        """Adopt a metered server-signed response: the server's signed voucher must
        stay within this request's payer-signed ceiling and advance the confirmed
        cumulative by exactly the charged amount."""
        if not response.success:
            raise _err(INVALID_CHANNEL_STATE, response.error_reason or "settlement failed")
        if authorization.channel_id != str(self.channel_id) or authorization.payer != self.config.payer:
            raise _err(
                INVALID_CHANNEL_ID_MISMATCH, "PAYMENT-RESPONSE does not correspond to the submitted authorization"
            )
        authorized = _int(authorization.authorized_amount, INVALID_CHANNEL_STATE, "authorizedAmount")
        extra = response.extra
        if extra is None:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE has no extra")
        if not extra.commitment_id:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE carries no commitmentId")
        if extra.voucher is None:
            raise _err(INVALID_VOUCHER_SIGNATURE, "server-signed PAYMENT-RESPONSE carries no voucher")
        cumulative = check_voucher(extra.voucher, self.config, self.channel_id)
        if cumulative < self.charged_cumulative_amount:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                f"server voucher cumulative {cumulative} is below local cumulative {self.charged_cumulative_amount}",
            )
        if extra.charged_amount is None:
            raise _err(INVALID_CHANNEL_STATE, "PAYMENT-RESPONSE has no chargedAmount")
        charged = _int(extra.charged_amount, INVALID_CHANNEL_STATE, "chargedAmount")
        delta = cumulative - self.charged_cumulative_amount
        if self._history_complete and delta != charged:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                f"server voucher advanced by {delta}, but chargedAmount is {charged}",
            )
        if charged > authorized:
            raise _err(
                INVALID_CUMULATIVE_AMOUNT_MISMATCH, f"server charged {charged}, above authorized ceiling {authorized}"
            )
        reported = extra.channel_state.charged_cumulative_amount if extra.channel_state is not None else None
        if reported is not None:
            value = _int(reported, INVALID_CHANNEL_STATE, "chargedCumulativeAmount")
            if value != cumulative:
                raise _err(
                    INVALID_CUMULATIVE_AMOUNT_MISMATCH,
                    f"server reported cumulative {value}, signed voucher confirms {cumulative}",
                )
        deposit = confirmed_deposit if confirmed_deposit is not None else self.deposit
        if cumulative > deposit:
            raise _err(
                INVALID_CHANNEL_STATE, f"server voucher cumulative {cumulative} exceeds escrow ceiling {deposit}"
            )
        if confirmed_deposit is not None:
            if deposit < self.deposit:
                raise _err(INVALID_CHANNEL_STATE, "confirmed deposit is below the current escrow ceiling")
            self.deposit = deposit
        self.charged_cumulative_amount = cumulative
        self._history_complete = True

    def adopt_corrective_state(self, requirements: BatchRequirements) -> int:
        """Resynchronize from a corrective 402, only against a voucher this
        channel's ``payerAuthorizer`` signed at that amount. Returns the adopted
        cumulative; the deposit ceiling never moves."""
        state = requirements.extra.channel_state
        if state is None:
            raise _err(INVALID_CUMULATIVE_AMOUNT_MISMATCH, "corrective challenge carries no channelState")
        if state.channel_id != str(self.channel_id):
            raise _err(INVALID_CHANNEL_ID_MISMATCH, "corrective channelState names a different channel")
        charged = _int(
            state.charged_cumulative_amount if state.charged_cumulative_amount is not None else "0",
            INVALID_CUMULATIVE_AMOUNT_MISMATCH,
            "chargedCumulativeAmount",
        )
        proof = requirements.extra.voucher_state
        if proof is None:
            raise _err(INVALID_CUMULATIVE_AMOUNT_MISMATCH, "corrective challenge carries no voucherState proof")
        adopted = check_corrective_voucher_state(proof, state.channel_id, self.config.payer_authorizer, charged)
        if adopted > self.deposit:
            raise _err(
                INVALID_CHANNEL_STATE, f"corrective cumulative {adopted} exceeds local escrow ceiling {self.deposit}"
            )
        self.charged_cumulative_amount = adopted
        return adopted


def _memo_instruction(memo: str) -> Instruction:
    data = memo.encode("utf-8")
    if len(data) > OPEN_MAX_MEMO_BYTES:
        raise ValueError(f"memo is {len(data)} bytes, over the {OPEN_MAX_MEMO_BYTES}-byte maximum")
    return Instruction(Pubkey.from_string(MEMO_PROGRAM), data, [])


async def _sign_sponsored(
    signer: TransactionSigner,
    version: int,
    fee_payer: Pubkey,
    instructions: list[Instruction],
    blockhash: Hash,
    *,
    unit_limit_cap: int | None = None,
) -> str:
    """Compile with the sponsor as fee payer, sign the payer slot, base64."""
    config = None
    if version == 1:
        limit = txv1.runtime_default_unit_limit(len(instructions))
        if unit_limit_cap is not None:
            limit = min(limit, unit_limit_cap)
        config = txv1.v1_config(limit, 0)
    wire = await build_partially_signed_transaction(
        instructions, fee_payer, blockhash, signer, version=version, config=config
    )
    tx = txv1.decode_transaction(wire)
    txv1.check_limits(tx, version)
    return base64.b64encode(wire).decode("ascii")


async def build_deposit(
    signer: TransactionSigner,
    requirements: BatchRequirements,
    terms: BatchTerms,
    deposit_amount: int,
    blockhash: Hash,
    open_slot: int,
    *,
    salt: int | None = None,
) -> tuple[BatchChannel, BatchPayload]:
    """The first ``deposit`` payload: a channel ``open`` plus the first voucher.

    The payer key doubles as ``payerAuthorizer`` (client mode). The sponsor is
    the transaction fee payer and channel ``rent_payer``.
    """
    if deposit_amount < terms.amount:
        raise ValueError("deposit must cover at least one request")
    if terms.server_signed_max_deposit is not None and deposit_amount > terms.server_signed_max_deposit:
        raise ValueError(
            f"deposit {deposit_amount} exceeds server-signed operator grant {terms.server_signed_max_deposit}"
        )
    payer = signer.pubkey
    if payer == terms.fee_payer:
        raise _err(INVALID_FEE_PAYER_MISMATCH, "the channel payer must not be the sponsor")
    payer_authorizer = terms.operator if terms.operator is not None else payer
    if payer_authorizer == terms.fee_payer:
        raise _err(INVALID_FEE_PAYER_MISMATCH, "the channel voucher signer must not be the sponsor")
    channel_salt = secrets.randbits(64) if salt is None else salt
    channel_id, _ = find_channel_pda(
        payer, terms.fee_payer, terms.mint, payer_authorizer, channel_salt, open_slot, PROGRAM_ID
    )
    open_ix = build_open_instruction(
        OpenChannelParams(
            payer=payer,
            rent_payer=terms.fee_payer,
            payee=terms.fee_payer,
            mint=terms.mint,
            authorized_signer=payer_authorizer,
            salt=channel_salt,
            deposit=deposit_amount,
            grace_period=terms.withdraw_delay,
            open_slot=open_slot,
            recipients=[Distribution(recipient=terms.receiver, bps=10_000)],
            token_program=terms.token_program,
            program_id=PROGRAM_ID,
        )
    )
    instructions = [open_ix, _memo_instruction(terms.memo), _memo_instruction(terms.binding_memo)]
    transaction = await _sign_sponsored(
        signer, terms.tx_version, terms.fee_payer, instructions, blockhash, unit_limit_cap=OPEN_MAX_COMPUTE_UNIT_LIMIT
    )
    config = BatchChannelConfig(
        payer=str(payer),
        payer_authorizer=str(payer_authorizer),
        receiver=requirements.pay_to,
        receiver_authorizer=requirements.extra.receiver_authorizer,
        token=requirements.asset,
        withdraw_delay=terms.withdraw_delay,
        salt=str(channel_salt),
        open_slot=open_slot,
        voucher_signer="server" if terms.operator is not None else None,
    )
    voucher: BatchVoucher | None = None
    authorization: BatchAuthorization | None = None
    if terms.operator is not None:
        authorization = await sign_authorization(
            signer,
            channel_id,
            terms.operator,
            _random_hex_nonce(),
            terms.amount,
            _authorization_expires_at(terms.authorization_ttl_seconds),
        )
    else:
        voucher = await sign_voucher(signer, channel_id, terms.amount)
    channel = BatchChannel(channel_id, config, 0, deposit_amount)
    payload = BatchPayload(
        type="deposit",
        channel_config=config,
        voucher=voucher,
        deposit=BatchDeposit(amount=str(deposit_amount), transaction=transaction),
        authorization=authorization,
    )
    return channel, payload


async def build_top_up(
    signer: TransactionSigner,
    channel: BatchChannel,
    terms: BatchTerms,
    top_up_amount: int,
    blockhash: Hash,
) -> BatchPayload:
    """A ``deposit`` payload topping up an existing channel and authorizing
    this request (used when the next voucher would exceed the deposit)."""
    if (
        terms.server_signed_max_deposit is not None
        and channel.deposit + top_up_amount > terms.server_signed_max_deposit
    ):
        raise ValueError(
            f"top-up would raise server-signed escrow to {channel.deposit + top_up_amount}, above operator grant "
            f"{terms.server_signed_max_deposit}"
        )
    instructions = [
        build_top_up_instruction(
            TopUpParams(
                payer=signer.pubkey,
                channel=channel.channel_id,
                mint=terms.mint,
                amount=top_up_amount,
                token_program=terms.token_program,
                program_id=PROGRAM_ID,
            )
        ),
        _memo_instruction(terms.continuation_memo),
    ]
    transaction = await _sign_sponsored(signer, terms.tx_version, terms.fee_payer, instructions, blockhash)
    voucher: BatchVoucher | None = None
    authorization: BatchAuthorization | None = None
    if terms.operator is not None:
        authorization = await sign_authorization(
            signer,
            channel.channel_id,
            terms.operator,
            _random_hex_nonce(),
            terms.amount,
            _authorization_expires_at(terms.authorization_ttl_seconds),
        )
    else:
        voucher = await channel.sign_next_voucher(signer, terms.amount)
    return BatchPayload(
        type="deposit",
        channel_config=channel.config,
        voucher=voucher,
        deposit=BatchDeposit(amount=str(top_up_amount), transaction=transaction),
        authorization=authorization,
    )


async def build_refund(signer: TransactionSigner, channel: BatchChannel, terms: BatchTerms) -> BatchPayload:
    """The default cooperative ``refund``: the server's accepted cumulative as a
    voucher (client mode) or the payer's close-intent proof (server mode). The
    channel cannot be reused afterwards."""
    if terms.operator is not None:
        authorization = await sign_authorization(
            signer,
            channel.channel_id,
            terms.operator,
            _random_hex_nonce(),
            0,
            _authorization_expires_at(terms.authorization_ttl_seconds),
        )
        return BatchPayload(type="refund", channel_config=channel.config, authorization=authorization)
    voucher = await sign_voucher(signer, channel.channel_id, channel.charged_cumulative_amount)
    return BatchPayload(type="refund", channel_config=channel.config, voucher=voucher)


async def build_refund_request_close(
    signer: TransactionSigner, channel: BatchChannel, terms: BatchTerms, blockhash: Hash
) -> BatchPayload:
    """The refund retry after ``receiver_binding_unavailable``: the cooperative
    payload plus a payer-signed ``request_close`` (starts the forced close)."""
    refund = await build_refund(signer, channel, terms)
    request_close = Instruction(
        PROGRAM_ID,
        bytes([_REQUEST_CLOSE_DISCRIMINATOR]),
        [AccountMeta(signer.pubkey, is_signer=True, is_writable=False), AccountMeta(channel.channel_id, False, True)],
    )
    instructions = [request_close, _memo_instruction(terms.continuation_memo)]
    transaction = await _sign_sponsored(signer, terms.tx_version, terms.fee_payer, instructions, blockhash)
    return BatchPayload(
        type="refund",
        channel_config=refund.channel_config,
        voucher=refund.voucher,
        authorization=refund.authorization,
        transaction=transaction,
    )


def encode_payment_header(requirements: BatchRequirements, payload: BatchPayload) -> str:
    """Wrap a payload in a ``PAYMENT-SIGNATURE`` envelope (``accepted`` echoes the
    requirements) and base64-encode it."""
    envelope = BatchPaymentPayload(x402_version=_X402_VERSION_V2, accepted=requirements, payload=payload)
    return base64.b64encode(json.dumps(envelope.to_dict(), separators=(",", ":")).encode("utf-8")).decode("ascii")


def parse_challenge(
    headers: Mapping[str, str],
    body: str | None = None,
    policy: ServerSignedChannelsPolicy | None = None,
) -> tuple[BatchRequirements, str | None] | None:
    """The ``batch-settlement`` requirement of a 402 and its corrective error code.

    Server-signed offers are selected only for an operator with a local trust
    grant; otherwise the client-signed offer is.
    """
    envelope: BatchRequiredEnvelope | None = None
    for name, value in headers.items():
        if name.lower() == _PAYMENT_REQUIRED_HEADER:
            try:
                envelope = BatchRequiredEnvelope.from_dict(json.loads(base64.b64decode(value, validate=True)))
            except Exception:  # noqa: BLE001
                envelope = None
            break
    if envelope is None and body:
        try:
            envelope = BatchRequiredEnvelope.from_dict(json.loads(body))
        except Exception:  # noqa: BLE001
            return None
    if envelope is None:
        return None
    accepts = [entry for entry in envelope.accepts if entry.scheme == BATCH_SETTLEMENT_SCHEME]

    def trusted(entry: BatchRequirements) -> bool:
        if entry.extra.voucher_signer != "server" or entry.extra.operator is None or policy is None:
            return False
        try:
            return policy.max_deposit_for(parse_pubkey(entry.extra.operator)) is not None
        except ValueError:
            return False

    chosen = next((entry for entry in accepts if trusted(entry)), None)
    if chosen is None:
        chosen = next(
            (e for e in accepts if e.extra.voucher_signer in (None, "client") and e.extra.operator is None), None
        )
    return None if chosen is None else (chosen, envelope.error)


def corrective_channel_id(requirements: BatchRequirements) -> Pubkey | None:
    """The channel a corrective challenge's snapshot refers to."""
    state = requirements.extra.channel_state
    if state is None:
        return None
    try:
        return parse_pubkey(state.channel_id)
    except ValueError:
        return None


def channel_id_for(config: BatchChannelConfig, requirements: BatchRequirements) -> Pubkey:
    """The channel PDA a configuration addresses."""
    return derive_channel_id(config, requirements.extra.fee_payer, PROGRAM_ID)
