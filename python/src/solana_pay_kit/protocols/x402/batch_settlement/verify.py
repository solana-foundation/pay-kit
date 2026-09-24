"""Pure verification rules for the SVM x402 ``batch-settlement`` scheme.

No RPC and no store: every function takes already-parsed values and raises
:class:`~.errors.BatchSettlementError` with the spec code on rejection. The
obligations come from the SVM ``batch-settlement`` spec: the terms and channel
config of section 4, the PDA derivation of section 4.2, and the voucher
acceptance steps of section 5, phase 3. The server-signed payer proof and the
capacity arithmetic are only written down in x402 PR #23 (its server and
facilitator), which the checks here follow. The Rust
``protocol/schemes/batch_settlement/verify.rs`` covers the same stateless half
and is the file to diff against for byte parity.
"""

from __future__ import annotations

from collections.abc import Collection

from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    CHANNEL_ACCOUNT_SIZE,
    PROGRAM_ID,
    Distribution,
    distribution_hash,
    find_channel_pda,
)
from solana_pay_kit._paycore.solana import TOKEN_2022_PROGRAM, TOKEN_PROGRAM
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.batch_settlement import errors
from solana_pay_kit.protocols.x402.batch_settlement.errors import BatchSettlementError
from solana_pay_kit.protocols.x402.batch_settlement.signatures import verify_authorization, verify_voucher
from solana_pay_kit.protocols.x402.batch_settlement.types import (
    MAX_WITHDRAW_DELAY_SECONDS,
    MIN_WITHDRAW_DELAY_SECONDS,
    PAYMENT_FLOW_AUTHORIZATION,
    VOUCHER_EXPIRES_AT,
    BatchAuthorization,
    BatchChannelConfig,
    BatchPayload,
    BatchRequirements,
    BatchVoucher,
)

__all__ = [
    "CHANNEL_STATUS_CLOSING",
    "CHANNEL_STATUS_DISTRIBUTED",
    "CHANNEL_STATUS_OPEN",
    "CHANNEL_STATUS_SEALED",
    "check_authorization",
    "check_capacity",
    "check_channel_binding",
    "check_channel_config",
    "check_cumulative",
    "check_no_cooperative_close",
    "check_terms",
    "check_voucher",
    "check_withdraw_delay",
    "decode_channel",
    "derive_channel_id",
]

#: ``Channel.status`` values (IDL ``channelStatus``).
CHANNEL_STATUS_OPEN = 0
CHANNEL_STATUS_SEALED = 1
CHANNEL_STATUS_CLOSING = 2
CHANNEL_STATUS_DISTRIBUTED = 3

# Program source (Moonsong-Labs/solana-payment-channels@0c07d57,
# program/payment_channels/src/state/common.rs:20) sets Channel = 1; the
# generated Rust/TS/Python enums are ordinal (0) and wrong.
_CHANNEL_ACCOUNT_DISCRIMINATOR = 1
_FULL_SHARE_BPS = 10_000


def _fail(code: str, detail: str) -> BatchSettlementError:
    return BatchSettlementError(code, detail)


def check_withdraw_delay(withdraw_delay: int, max_timeout_seconds: int) -> None:
    """Enforce the 900..=2592000 conformance range and that the delay outlasts the HTTP window."""
    if not MIN_WITHDRAW_DELAY_SECONDS <= withdraw_delay <= MAX_WITHDRAW_DELAY_SECONDS:
        raise _fail(
            errors.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            f"withdrawDelay {withdraw_delay} is outside {MIN_WITHDRAW_DELAY_SECONDS}..={MAX_WITHDRAW_DELAY_SECONDS}",
        )
    if withdraw_delay < max_timeout_seconds:
        raise _fail(
            errors.INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            f"withdrawDelay {withdraw_delay} is shorter than maxTimeoutSeconds {max_timeout_seconds}",
        )


def check_terms(requirements: BatchRequirements, *, fee_payer: str) -> None:
    """Check the requirement's scheme terms: payment flow, withdraw delay, token program shape, our fee payer.

    The token program must additionally equal the mint's on-chain owner; that
    read belongs to the caller.
    """
    extra = requirements["extra"]
    flow = extra.get("paymentFlow", PAYMENT_FLOW_AUTHORIZATION)
    if flow != PAYMENT_FLOW_AUTHORIZATION:
        raise _fail(errors.INVALID_PAYMENT_FLOW, f'extra.paymentFlow must be "authorization", got {flow!r}')
    check_withdraw_delay(extra["withdrawDelay"], requirements["maxTimeoutSeconds"])
    if extra["tokenProgram"] not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise _fail(errors.INVALID_TOKEN_PROGRAM, f"unsupported tokenProgram {extra['tokenProgram']}")
    if extra["feePayer"] != fee_payer:
        raise _fail(errors.INVALID_FEE_PAYER_MISMATCH, f"extra.feePayer {extra['feePayer']} is not this server's")


def check_channel_config(
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    *,
    fee_payer: str,
    operator: str | None,
) -> None:
    """Bind the client's channel configuration to the requirement it answers.

    Runs :func:`check_terms`, then the voucher-signing mode (``operator`` is
    this server's configured operator key, ``None`` when server-signed mode
    is off), the fee-payer collisions, and every immutable field.
    """
    check_terms(requirements, fee_payer=fee_payer)
    extra = requirements["extra"]
    mode = extra.get("voucherSigner", "client")
    if config.get("voucherSigner", "client") != mode:
        raise _fail(errors.INVALID_CHANNEL_STATE, "channelConfig.voucherSigner does not match extra.voucherSigner")
    advertised = extra.get("operator")
    if mode == "server":
        if advertised is None or config["payerAuthorizer"] != advertised or advertised != operator:
            raise _fail(
                errors.INVALID_CHANNEL_STATE,
                "server-signed channel must name this server's operator as extra.operator and payerAuthorizer",
            )
    elif advertised is not None:
        raise _fail(errors.INVALID_CHANNEL_STATE, "extra.operator must be absent in client-signed mode")
    # The program needs distinct payer and payee, and a sponsor that could sign
    # vouchers could author its own claims.
    if fee_payer in (config["payer"], config["payerAuthorizer"]):
        raise _fail(errors.INVALID_FEE_PAYER_MISMATCH, "channelConfig.payer and payerAuthorizer must not be feePayer")
    if config["receiver"] != requirements["payTo"]:
        raise _fail(errors.INVALID_CHANNEL_STATE, f"channelConfig.receiver {config['receiver']} is not payTo")
    if config["token"] != requirements["asset"]:
        raise _fail(errors.INVALID_CHANNEL_STATE, f"channelConfig.token {config['token']} is not the asset")
    if config["withdrawDelay"] != extra["withdrawDelay"]:
        raise _fail(errors.INVALID_WITHDRAW_DELAY_MISMATCH, "channelConfig.withdrawDelay is not extra.withdrawDelay")
    # Both name it or neither does: a key the requirement never advertised is
    # not bound to anything this server controls.
    if config.get("receiverAuthorizer") != extra.get("receiverAuthorizer"):
        raise _fail(
            errors.INVALID_RECEIVER_AUTHORIZER_MISMATCH,
            "channelConfig.receiverAuthorizer must match extra.receiverAuthorizer",
        )


def derive_channel_id(config: BatchChannelConfig, fee_payer: str, program_id: Pubkey = PROGRAM_ID) -> str:
    """The channel PDA over ``[channel, payer, feePayer, token, payerAuthorizer, salt, openSlot]``.

    ``feePayer`` takes the program's ``payee`` seed: the sponsor holds that
    seat with a zero share.
    """
    try:
        pda, _ = find_channel_pda(
            Pubkey.from_string(config["payer"]),
            Pubkey.from_string(fee_payer),
            Pubkey.from_string(config["token"]),
            Pubkey.from_string(config["payerAuthorizer"]),
            int(config["salt"]),
            config["openSlot"],
            program_id,
        )
    except ValueError as exc:
        raise _fail(errors.INVALID_CHANNEL_STATE, f"channel config does not derive a PDA: {exc}") from None
    return str(pda)


def check_voucher(voucher: BatchVoucher, config: BatchChannelConfig, channel_id: str) -> int:
    """Verify a client voucher names ``channel_id``, never expires and is signed by payerAuthorizer; return its amount.

    A malformed signature is ``voucher_signature``, never ``transaction_failed``.
    """
    if voucher["channelId"] != channel_id:
        raise _fail(errors.INVALID_CHANNEL_ID_MISMATCH, f"voucher.channelId is not the derived PDA {channel_id}")
    if voucher["expiresAt"] != VOUCHER_EXPIRES_AT:
        raise _fail(errors.INVALID_VOUCHER_EXPIRY, f"voucher expiresAt must be 0, got {voucher['expiresAt']}")
    if not verify_voucher(voucher, config["payerAuthorizer"]):
        raise _fail(errors.INVALID_VOUCHER_SIGNATURE, "voucher is not signed by channelConfig.payerAuthorizer")
    return int(voucher["maxClaimableAmount"])


def check_authorization(
    authorization: BatchAuthorization,
    config: BatchChannelConfig,
    channel_id: str,
    *,
    amount: str,
    now: int,
) -> None:
    """Verify a server-signed request's payer proof.

    The proof must name the derived channel and the channel payer, authorize
    exactly the requirement ``amount`` (string equality, as the spec binds the
    wire value), be unexpired (``now < expiresAt``), carry a 1..256-byte
    ``requestId``, and be signed by the payer for the operator in
    ``payerAuthorizer``. In-process this is the only proof check: the
    facilitator ``/verify`` check and the resource-server check collapse here.
    """
    if (
        authorization["channelId"] != channel_id
        or authorization["payer"] != config["payer"]
        or authorization["authorizedAmount"] != amount
        or not verify_authorization(authorization, config["payerAuthorizer"], now)
    ):
        raise _fail(errors.INVALID_VOUCHER_SIGNATURE, "invalid payer proof")


def check_no_cooperative_close(payload: BatchPayload) -> None:
    """Refuse a refund carrying a voucher or closeAuthorization: the shortcut needs a trusted binding we lack.

    The interoperable close is the payer-signed ``request_close``; a key that
    merely appears in a request is not a trust anchor.
    """
    if payload["type"] == "refund" and ("voucher" in payload or "closeAuthorization" in payload):
        raise _fail(
            errors.INVALID_CLOSE_AUTHORIZATION,
            "cooperative close is not supported; omit voucher and closeAuthorization and use request_close",
        )


def check_cumulative(
    submitted: int,
    signature: str,
    *,
    charged: int,
    amount: int,
    signed_signature: str | None,
) -> None:
    """Accept only a voucher for exactly ``charged + amount``; an exact replay is ``duplicate_settlement``.

    ``charged`` is the server's accepted watermark and ``signed_signature``
    the signature of the voucher it last committed there. A replay is refused
    before the handler runs: this scheme does not replay responses.
    """
    if signed_signature is not None and submitted == charged and signature == signed_signature:
        raise _fail(errors.DUPLICATE_SETTLEMENT, f"voucher for {submitted} was already accepted")
    expected = charged + amount
    if submitted != expected:
        raise _fail(errors.INVALID_CUMULATIVE_AMOUNT_MISMATCH, f"voucher authorizes {submitted}, expected {expected}")


def check_capacity(*, max_claimable: int, charged: int, reserved: int, ceiling: int, deposit: int) -> None:
    """Refuse when the voucher or ``charged + live reserved ceilings + this ceiling`` would exceed the deposit.

    ``deposit`` includes this request's validated top-up, if any.
    """
    if max_claimable > deposit or charged + reserved + ceiling > deposit:
        raise _fail(
            errors.INVALID_CUMULATIVE_EXCEEDS_DEPOSIT,
            f"voucher {max_claimable} or charged {charged} + reserved {reserved} + {ceiling} exceeds deposit {deposit}",
        )


def decode_channel(data: bytes, owner: str, program_id: Pubkey = PROGRAM_ID) -> Channel:
    """Decode a payment-channels ``Channel`` account, refusing a foreign owner, size or discriminator."""
    if owner != str(program_id):
        raise _fail(errors.INVALID_CHANNEL_STATE, f"channel account is owned by {owner}, not the program")
    if len(data) != CHANNEL_ACCOUNT_SIZE or data[0] != _CHANNEL_ACCOUNT_DISCRIMINATOR:
        raise _fail(errors.INVALID_CHANNEL_STATE, "account is not a payment-channels Channel")
    return Channel.decode(data)


def check_channel_binding(
    channel: Channel,
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    *,
    statuses: Collection[int] = (CHANNEL_STATUS_OPEN,),
) -> None:
    """Bind a confirmed on-chain channel's immutable fields to the payload and requirement that claim it.

    The sponsor holds both ``payee`` and ``rent_payer``; the distribution is
    only committed as a hash, so the single 100% ``payTo`` split is rebuilt
    and compared.
    """
    fee_payer = requirements["extra"]["feePayer"]
    expected_hash = distribution_hash([Distribution(Pubkey.from_string(requirements["payTo"]), _FULL_SHARE_BPS)])
    mismatches = [
        name
        for name, ok in (
            ("status", int(channel.status) in statuses),
            ("payer", str(channel.payer) == config["payer"]),
            ("payee", str(channel.payee) == fee_payer),
            ("rent_payer", str(channel.rentPayer) == fee_payer),
            ("authorized_signer", str(channel.authorizedSigner) == config["payerAuthorizer"]),
            ("mint", str(channel.mint) == requirements["asset"]),
            ("grace_period", int(channel.gracePeriod) == config["withdrawDelay"]),
            ("salt", int(channel.salt) == int(config["salt"])),
            ("open_slot", int(channel.openSlot) == config["openSlot"]),
            ("distribution", bytes(channel.distributionHash) == expected_hash),
        )
        if not ok
    ]
    if mismatches:
        raise _fail(errors.INVALID_CHANNEL_STATE, f"confirmed channel {', '.join(mismatches)} does not match")
