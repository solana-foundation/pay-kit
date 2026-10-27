"""x402 ``upto`` (Solana) server engine - ``payment-channel`` profile.

Self-hosted usage-based authorization. Unlike ``exact`` (one inline transfer
settled before the handler runs), ``upto`` is two-phase: :meth:`X402Upto.verify_open`
broadcasts the client's channel ``open`` (the signed deposit is the ceiling) and
binds the on-chain channel state *before* the resource is served;
:meth:`X402Upto.settle_actual` signs a receiver-authorizer voucher for the metered
amount and submits the fee-payer-signed ``settle_and_seal`` + ATA setup +
``distribute``, refunding ``deposit − actual`` *after* the resource is served.

Channel roles: the receiver authorizer is the voucher signer only (payment
authority). The fee payer is the transaction fee payer, rent payer, and
zero-share channel ``payee`` (lifecycle authority): it signs ``settle_and_seal``
and can always seal an abandoned channel with ``has_voucher = 0`` to recover its
rent, but holds no payment authority — the distribution is always the explicit
single-entry 100% ``payTo`` split, so the payee's implicit remainder is zero.

Mirrors the Rust spine (``server/upto.rs``) and the Go reference
(``go/protocols/x402/upto.go``). The on-chain machinery is reused from
:mod:`solana_pay_kit._paycore.paymentchannels`; the wire types and pure checks live in
:mod:`solana_pay_kit.protocols.x402.upto.types` / ``.verify``.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from spl.token.instructions import (  # type: ignore[import-untyped]
    create_idempotent_associated_token_account,
)

from solana_pay_kit._paycore import txv1
from solana_pay_kit._paycore.currency import parse_units
from solana_pay_kit._paycore.mints import resolve, token_program_for
from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    build_distribute_instruction,
    build_settle_and_seal_instructions,
    decode_channel_account,
    distribution_hash,
    find_associated_token_address,
    treasury_owner,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction
from solana_pay_kit.errors import ConfigurationError, InvalidProofError
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION
from solana_pay_kit.protocols.x402.upto.open import (
    DEFAULT_UPTO_MAX_TIMEOUT_SECONDS,
    PreparedUptoOpen,
    UptoRoute,
    cosign_upto_open,
    prepare_upto_open,
    route_memo,
    upto_requirements,
    verify_upto_open_preflight,
)
from solana_pay_kit.protocols.x402.upto.types import (
    DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS,
    UptoRequirements,
    UptoSettlementResponse,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
    assert_settlement_within_ceiling,
)

if TYPE_CHECKING:
    from solana_keychain import SolanaSigner, TransactionSigner

    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import Gate

__all__ = [
    "PreparedUptoOpen",
    "UptoRoute",
    "VerifiedUptoOpen",
    "X402Upto",
    "cosign_upto_open",
    "prepare_upto_open",
    "route_memo",
    "upto_requirements",
    "verify_upto_open_preflight",
]

# Settlement receipt headers (mirror the exact adapter + Go x402 constants).
_RESPONSE_HEADER = "payment-response"
_SETTLEMENT_HEADER = "x-payment-settlement-signature"
_CHALLENGE_HEADER = "payment-required"

# ChannelStatus::Open discriminant (generated types.channelStatus.Open = 0).
_CHANNEL_STATUS_OPEN = 0


def _empty_distribution() -> list[Distribution]:
    return []


@dataclass
class VerifiedUptoOpen:
    """A confirmed, on-chain-validated channel open carried into settlement.

    Opaque to the usage middleware, which calls :meth:`release` after settlement
    so the per-channel in-flight reservation never leaks. ``release`` is
    idempotent (direct callers and the middleware may both release).
    """

    channel_id: Pubkey
    payer: Pubkey
    payee: Pubkey
    rent_payer: Pubkey
    mint: Pubkey
    token_program: Pubkey
    program_id: Pubkey
    deposit: int
    max_amount: int
    expires_at: int
    network: str
    distribution: list[Distribution] = field(default_factory=_empty_distribution)
    _release_fn: Callable[[], None] | None = field(default=None, repr=False)
    _released: bool = field(default=False, repr=False)

    def release(self) -> None:
        """Free the in-flight channel reservation (idempotent)."""
        if self._released:
            return
        self._released = True
        if self._release_fn is not None:
            self._release_fn()


class X402Upto:
    """Server-side x402 ``upto`` payment-channel engine."""

    def __init__(
        self,
        config: Config,
        *,
        channel_program: str | None = None,
        recent_blockhash_provider: Callable[[], str | None] | None = None,
        recent_state_provider: Callable[[], tuple[str | None, int | None] | None] | None = None,
        receiver_authorizer_signer: SolanaSigner | None = None,
        max_timeout_seconds: int = DEFAULT_UPTO_MAX_TIMEOUT_SECONDS,
        max_channel_lifetime_seconds: int = DEFAULT_MAX_CHANNEL_LIFETIME_SECONDS,
        withdraw_delay: int = DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS,
        transaction_versions: Sequence[int] | None = None,
    ) -> None:
        """Build an engine bound to ``config``; raise for delegated mode.

        ``recent_state_provider`` returns ``(recentBlockhash, recentSlot)``
        from a single ``getLatestBlockhash`` call (the response context
        carries the slot); when set it wins over the blockhash-only
        ``recent_blockhash_provider``, which is kept for embedders that only
        pre-fetch the blockhash. ``recentSlot`` is server-provided in the
        challenge: the client derives the channel PDA from it and never
        fetches the slot itself.

        ``receiver_authorizer_signer`` signs settlement vouchers (the channel
        ``authorized_signer``); it defaults to the fee payer (self-facilitated).
        ``max_channel_lifetime_seconds`` is the facilitator's
        ``maxChannelLifetimeSecs`` and ``transaction_versions`` the open message
        versions accepted and advertised (``None`` accepts version 0 only).
        """
        if config.x402.is_delegated():
            raise NotImplementedError(
                "solana_pay_kit: x402 delegated mode is not yet implemented; "
                "leave X402Config.facilitator_url None for self-hosted"
            )
        if max_channel_lifetime_seconds <= 0:
            raise ConfigurationError("solana_pay_kit: x402 upto maxChannelLifetimeSecs must be positive")
        if withdraw_delay <= 0:
            raise ConfigurationError("solana_pay_kit: x402 upto withdrawDelay must be greater than zero")
        self._config = config
        # The channel program defaults to the canonical deployment; the harness
        # overrides it via the PAYMENT_CHANNELS_PROGRAM_ID env (matching Go/Rust).
        self._channel_program = (
            channel_program or os.environ.get("PAYMENT_CHANNELS_PROGRAM_ID") or PAYMENT_CHANNELS_PROGRAM_ID
        )
        self._recent_blockhash_provider = recent_blockhash_provider
        self._recent_state_provider = recent_state_provider
        self._receiver_authorizer_signer = receiver_authorizer_signer
        self._max_timeout_seconds = max_timeout_seconds
        self._max_channel_lifetime_seconds = max_channel_lifetime_seconds
        self._withdraw_delay = withdraw_delay
        self._accepted_versions = txv1.accepted_versions(
            txv1.parse_transaction_versions(list(transaction_versions) if transaction_versions is not None else None)
        )
        # Per-channel in-flight reservation (verify_open -> settle_actual), guarded
        # so it is safe even under a threaded server (Go uses a mutex here too);
        # do not rely on set() atomicity for the check-then-add.
        self._in_flight: set[str] = set()
        self._in_flight_lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def route(self, gate: Gate, request: Any = None, *, route: str | None = None) -> UptoRoute:
        """The route this engine offers for ``gate``; ``route`` (a canonical
        request identity) binds it with :func:`route_memo`."""
        fee_payer = str(self._signer().pubkey)
        coin = gate.amount.primary_coin()
        coin_value = coin.value if coin is not None else self._config.stablecoins[0].value
        label = self._config.network.mints_label()
        asset = resolve(coin_value, label)
        if not asset:
            raise ConfigurationError(
                "solana_pay_kit: x402 upto requires an SPL token (not native SOL); "
                f"could not resolve mint for {coin_value!r}"
            )
        try:
            amount = parse_units(gate.total().amount_string(), 6)
        except ValueError as exc:
            raise ConfigurationError(
                f"solana_pay_kit: x402 upto price {gate.total().amount_string()!r} "
                "exceeds 6-decimal (micro-unit) precision"
            ) from exc
        return UptoRoute(
            network=self._config.network.caip2(),
            amount=int(amount),
            asset=asset,
            token_program=token_program_for(coin_value, label),
            pay_to=gate.pay_to or self._config.effective_recipient(),
            fee_payer=fee_payer,
            receiver_authorizer=self.receiver_authorizer(),
            withdraw_delay=self._withdraw_delay,
            max_timeout_seconds=self._max_timeout_seconds,
            memo=route_memo(route) if route is not None else None,
            transaction_versions=self._accepted_versions,
            decimals=6,
        )

    def receiver_authorizer(self) -> str:
        """The voucher signer key (base58): the configured receiver
        authorizer, else the fee payer."""
        signer = self._receiver_authorizer_signer or self._signer()
        return str(signer.pubkey)

    def accepts_entry(self, gate: Gate, request: Any, *, route: str | None = None) -> UptoRequirements:
        """Build the route-pinned ``upto`` requirement (the server's offer)."""
        requirements = upto_requirements(self.route(gate, request, route=route))
        blockhash, recent_slot = self._fetch_recent_state()
        if blockhash is not None:
            requirements["extra"]["recentBlockhash"] = blockhash
        if recent_slot is not None:
            # u64-as-string, matching the session challenge convention; the
            # client accepts string or number inbound.
            requirements["extra"]["recentSlot"] = str(recent_slot)
        return requirements

    def challenge_headers(self, gate: Gate, request: Any, *, route: str | None = None) -> dict[str, str]:
        """Build the ``payment-required`` header (base64 JSON challenge)."""
        envelope = {
            "x402Version": X402_VERSION,
            "resource": {"type": "http", "url": _request_path(request)},
            "accepts": [self.accepts_entry(gate, request, route=route)],
        }
        payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        return {_CHALLENGE_HEADER: base64.b64encode(payload).decode("ascii")}

    def detect_usage(self, request: Any) -> bool:
        """Report whether the request carries an ``upto`` usage credential."""
        return bool(_payment_signature_header(request))

    def settlement_headers(self, settlement: UptoSettlementResponse) -> dict[str, str]:
        """Build the ``PAYMENT-RESPONSE`` settlement receipt headers."""
        body = base64.b64encode(json.dumps(settlement, separators=(",", ":")).encode("utf-8")).decode("ascii")
        return {_RESPONSE_HEADER: body, _SETTLEMENT_HEADER: settlement.get("transaction", "")}

    async def verify_open(self, gate: Gate, request: Any, *, route: str | None = None) -> VerifiedUptoOpen:
        """Validate the credential, broadcast + confirm the channel ``open``, and
        bind the on-chain channel state. Reserves the channel until settlement.

        Every pre-broadcast check is :func:`prepare_upto_open` (Phase 3 steps
        0 to 7 and the open acceptance policy); then settlement readiness
        (step 8), the co-signature, the broadcast and the on-chain rebind.
        """
        signer = self._signer()
        fee_payer = str(signer.pubkey)
        receiver_authorizer = self.receiver_authorizer()

        header = _payment_signature_header(request)
        if not header:
            raise InvalidProofError("solana_pay_kit: payment required", code="payment_required")
        offered = [upto_requirements(self.route(gate, request, route=route))]
        program_id = Pubkey.from_string(self._channel_program or PAYMENT_CHANNELS_PROGRAM_ID)
        fee_payer_pubkey = Pubkey.from_string(fee_payer)
        receiver_authorizer_pubkey = Pubkey.from_string(receiver_authorizer)

        rpc = SolanaRpc(self._config.effective_rpc_url())
        reserved: str | None = None
        released = False

        def _release() -> None:
            if reserved is None:
                return
            with self._in_flight_lock:
                self._in_flight.discard(reserved)

        try:
            # The challenged recentSlot at verify time comes from the
            # recent-state provider when wired, else from the RPC.
            _, provided_slot = self._fetch_recent_state()
            extra: dict[str, Any] = {} if provided_slot is None else {"recent_slot": provided_slot}
            prepared = await prepare_upto_open(
                header,
                offered,
                fee_payer=fee_payer,
                receiver_authorizer=receiver_authorizer,
                rpc=rpc,
                now=int(time.time()),
                accepted_versions=self._accepted_versions,
                max_channel_lifetime_seconds=self._max_channel_lifetime_seconds,
                program_id=program_id,
                **extra,
            )
            self._reserve_channel(str(prepared.channel_id))
            reserved = str(prepared.channel_id)

            await self._ensure_payouts_ready(
                rpc, prepared.mint, prepared.token_program, prepared.distribution, fee_payer_pubkey
            )

            cosigned = await cosign_upto_open(prepared.transaction, signer)
            sent = await rpc.send_raw_transaction(cosigned)
            await rpc.await_confirmation(str(sent.value))

            channel = await self._fetch_channel(rpc, prepared.channel_id, program_id)
            self._validate_channel_state(
                channel,
                fee_payer_pubkey,
                receiver_authorizer_pubkey,
                prepared.payer,
                prepared.payee,
                prepared.mint,
                prepared.max_amount,
                int(prepared.requirements["extra"]["withdrawDelay"]),
                prepared.distribution,
            )

            verified = VerifiedUptoOpen(
                channel_id=prepared.channel_id,
                payer=prepared.payer,
                payee=prepared.payee,
                rent_payer=Pubkey.from_string(str(channel.rent_payer)),
                mint=prepared.mint,
                token_program=prepared.token_program,
                program_id=program_id,
                deposit=int(channel.deposit),
                max_amount=prepared.max_amount,
                expires_at=prepared.expires_at,
                network=prepared.requirements["network"],
                distribution=prepared.distribution,
                _release_fn=_release,
            )
            released = True
            return verified
        finally:
            if not released:
                _release()
            await rpc.aclose()

    async def settle_actual(self, verified: VerifiedUptoOpen, actual: int) -> UptoSettlementResponse:
        """Settle the metered ``actual`` (``actual ≤ max``) against a verified open.

        Honours zero: ``actual == 0`` uses the no-voucher ``settle_and_seal``
        + ``distribute`` (seal, full refund, channel closed) and returns
        ``amount="0"`` - matching the Rust spine and the spec ("settled amount
        MAY be 0"). A ``cumulative = 0`` voucher would be non-monotonic/invalid,
        hence the no-voucher path.
        """
        signer = self._signer()
        fee_payer = signer.pubkey
        message_signer: SolanaSigner = self._receiver_authorizer_signer or signer
        receiver_authorizer = message_signer.pubkey
        try:
            assert_settlement_within_ceiling(actual, verified.max_amount)

            # settle_and_seal is signed by the fee payer (the zero-share payee
            # seat); the receiver authorizer signs only the Ed25519 voucher.
            if actual == 0:
                instructions: list[Instruction] = build_settle_and_seal_instructions(
                    payee=fee_payer,
                    channel=verified.channel_id,
                    authorized_signer=receiver_authorizer,
                    signature=None,
                    cumulative=0,
                    expires_at=verified.expires_at,
                    program_id=verified.program_id,
                )
            else:
                message = voucher_message_bytes(verified.channel_id, actual, verified.expires_at)
                sig_bytes = bytes(await message_signer.sign_message(message))
                if len(sig_bytes) != 64:
                    raise InvalidProofError(
                        f"voucher signature length {len(sig_bytes)}, want 64", code="payment_invalid"
                    )
                instructions = build_settle_and_seal_instructions(
                    payee=fee_payer,
                    channel=verified.channel_id,
                    authorized_signer=receiver_authorizer,
                    signature=sig_bytes,
                    cumulative=actual,
                    expires_at=verified.expires_at,
                    program_id=verified.program_id,
                )

            # Distribute against the payee seat the channel was opened and
            # validated with in verify_open (the fee payer, zero share); the
            # settled funds flow entirely through the bound distribution split
            # (gate.pay_to, not the global recipient - a usage gate may set its
            # own pay_to, and distribute must target that ATA).
            payee = verified.payee
            treasury = treasury_owner()
            distribute = build_distribute_instruction(
                channel=verified.channel_id,
                payer=verified.payer,
                payee=payee,
                mint=verified.mint,
                recipients=verified.distribution,
                token_program=verified.token_program,
                program_id=verified.program_id,
                treasury=treasury,
                rent_payer=verified.rent_payer,
            )
            create_payee_ata = create_idempotent_associated_token_account(
                fee_payer, payee, verified.mint, verified.token_program
            )
            create_treasury_ata = create_idempotent_associated_token_account(
                fee_payer, treasury, verified.mint, verified.token_program
            )
            # Recipient accounts are never created here: the open was refused
            # unless each already existed and was usable (_ensure_payouts_ready),
            # and funding them would let an owner close and recreate the
            # account to collect the fee payer's rent on every settlement.
            instructions = [*instructions, create_payee_ata, create_treasury_ata, distribute]

            rpc = SolanaRpc(self._config.effective_rpc_url())
            try:
                blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
                wire = await build_partially_signed_v0_transaction(instructions, fee_payer, blockhash, signer)
                sent = await rpc.send_raw_transaction(wire)
                signature = str(sent.value)
                await rpc.await_confirmation(signature)
            finally:
                await rpc.aclose()

            return {
                "success": True,
                "payer": str(verified.payer),
                "transaction": signature,
                "network": verified.network,
                "amount": str(actual),
            }
        finally:
            verified.release()

    # -- internals ----------------------------------------------------------

    def _signer(self) -> TransactionSigner:
        signer = self._config.effective_x402_signer()
        if signer is None:
            raise InvalidProofError("solana_pay_kit: x402 upto requires a fee payer signer", code="payment_invalid")
        return signer

    def _reserve_channel(self, channel_id: str) -> None:
        with self._in_flight_lock:
            if channel_id in self._in_flight:
                raise InvalidProofError(
                    "channel is already being processed (concurrent request)", code="payment_invalid"
                )
            self._in_flight.add(channel_id)

    def _fetch_recent_state(self) -> tuple[str | None, int | None]:
        """Pre-fetch ``(recentBlockhash, recentSlot)`` for the challenge.

        The combined provider wins (one ``getLatestBlockhash`` call yields
        both); the blockhash-only provider is the fallback and stamps no slot.
        Provider failures are non-fatal at challenge time.
        """
        if self._recent_state_provider is not None:
            try:
                value = self._recent_state_provider()
            except Exception:  # noqa: BLE001 - provider failures are non-fatal at challenge time
                return None, None
            if value is None:
                return None, None
            blockhash, slot = value
            if not isinstance(blockhash, str) or blockhash == "":
                blockhash = None
            if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
                slot = None
            return blockhash, slot
        return self._fetch_recent_blockhash(), None

    def _fetch_recent_blockhash(self) -> str | None:
        if self._recent_blockhash_provider is None:
            return None
        try:
            value = self._recent_blockhash_provider()
        except Exception:  # noqa: BLE001 - provider failures are non-fatal at challenge time
            return None
        return value if isinstance(value, str) and value != "" else None

    def _distribution(self, requirements: UptoRequirements) -> list[Distribution]:
        # Always explicit: the payee seat is held by the facilitator (feePayer)
        # with a zero implicit remainder, so 100% of settled funds must be
        # assigned to payTo through the recipients list.
        beneficiary = Pubkey.from_string(requirements["payTo"])
        return [Distribution(recipient=beneficiary, bps=10_000)]

    async def _ensure_payouts_ready(
        self,
        rpc: SolanaRpc,
        mint: Pubkey,
        token_program: Pubkey,
        distribution: list[Distribution],
        fee_payer: Pubkey,
    ) -> None:
        """Settlement readiness (scheme_upto_svm.md Phase 3 step 8).

        Every distribution recipient's token account must already exist and
        be usable before the deposit is escrowed: settlement never creates
        it, and the program forfeits a payout to an unusable account. The
        fee payer's own account is the payee seat settlement creates itself.
        A failed read is a refusal too. Mirrors the Rust
        ``X402Upto::ensure_payouts_ready``.
        """
        for entry in distribution:
            if entry.recipient == fee_payer:
                continue
            ata, _ = find_associated_token_address(entry.recipient, mint, token_program)
            try:
                account = await rpc.get_account_info(str(ata))
            except Exception as exc:  # noqa: BLE001
                raise InvalidProofError(f"payout token account read failed: {exc}", code="payment_invalid") from exc
            problem = (
                "does not exist"
                if account is None
                else _unusable_token_account(account[1], account[0], entry.recipient, mint, token_program)
            )
            if problem is not None:
                raise InvalidProofError(
                    f"payout token account {ata} of {entry.recipient} {problem}; it must be an "
                    "initialized token account before payments settle to it",
                    code="payment_invalid",
                )

    async def _fetch_channel(self, rpc: SolanaRpc, channel_id: Pubkey, program_id: Pubkey) -> Channel:
        account = await rpc.get_account_info(str(channel_id))
        if account is None:
            raise InvalidProofError("channel account fetch failed: missing account data", code="payment_invalid")
        data, owner = account
        if owner != str(program_id):
            raise InvalidProofError(
                "channel account is not owned by the payment-channels program", code="payment_invalid"
            )
        try:
            return decode_channel_account(data)
        except ValueError as exc:
            raise InvalidProofError("invalid channel account data", code="payment_invalid") from exc

    def _validate_channel_state(
        self,
        channel: Channel,
        fee_payer: Pubkey,
        receiver_authorizer: Pubkey,
        payer: Pubkey,
        payee: Pubkey,
        mint: Pubkey,
        max_amount: int,
        withdraw_delay: int,
        distribution: list[Distribution],
    ) -> None:
        if int(channel.status) != _CHANNEL_STATUS_OPEN:
            raise InvalidProofError("channel is not open after broadcast", code="payment_invalid")
        if str(channel.mint) != str(mint):
            raise InvalidProofError(f"token mint mismatch: expected {mint}, got {channel.mint}", code="payment_invalid")
        if str(channel.payee) != str(payee):
            raise InvalidProofError(
                f"channel payee mismatch: expected the fee payer {payee}, got {channel.payee}",
                code="payment_invalid",
            )
        expected_hash = list(distribution_hash(distribution))
        if list(channel.distribution_hash) != expected_hash:
            raise InvalidProofError(
                "channel distribution does not match the expected recipient split", code="payment_invalid"
            )
        if str(channel.authorized_signer) != str(receiver_authorizer):
            raise InvalidProofError("channel authorized_signer is not the receiver authorizer", code="payment_invalid")
        if str(channel.rent_payer) != str(fee_payer):
            raise InvalidProofError("channel rent_payer is not the fee payer", code="payment_invalid")
        if int(channel.grace_period) != withdraw_delay:
            raise InvalidProofError(
                f"channel withdraw delay {channel.grace_period} does not match advertised {withdraw_delay}",
                code="payment_invalid",
            )
        if int(channel.deposit) != max_amount:
            raise InvalidProofError(
                f"on-chain deposit {channel.deposit} must equal authorized maximum {max_amount}",
                code="payment_invalid",
            )
        if str(channel.payer) != str(payer):
            raise InvalidProofError(
                f"channel payer {channel.payer} does not match payload.from {payer}", code="payment_invalid"
            )


# -- module-level helpers ---------------------------------------------------


_TOKEN_ACCOUNT_LEN = 165
_TOKEN_ACCOUNT_INITIALIZED = 1
_TOKEN_ACCOUNT_FROZEN = 2
_TOKEN_ACCOUNT_TYPE = 2
_EXTENSION_IMMUTABLE_OWNER = 7


def _unsupported_account_extension(data: bytes) -> int | None:
    """The first Token-2022 account extension other than ImmutableOwner."""
    if len(data) == _TOKEN_ACCOUNT_LEN:
        return None
    if data[_TOKEN_ACCOUNT_LEN] != _TOKEN_ACCOUNT_TYPE:
        return data[_TOKEN_ACCOUNT_LEN]
    cursor = _TOKEN_ACCOUNT_LEN + 1
    while cursor < len(data):
        if not any(data[cursor:]):
            return None
        header = data[cursor : cursor + 4]
        if len(header) < 4:
            return 0xFFFF
        extension = int.from_bytes(header[0:2], "little")
        length = int.from_bytes(header[2:4], "little")
        if extension != _EXTENSION_IMMUTABLE_OWNER:
            return extension
        cursor += 4 + length
        if cursor > len(data):
            return 0xFFFF
    return None


def _unusable_token_account(
    program: str, data: bytes, owner: Pubkey, mint: Pubkey, token_program: Pubkey
) -> str | None:
    """Why a token account cannot receive a payout, or ``None`` when it can.

    Mirrors the Rust ``unusable_settlement_account``.
    """
    if program != str(token_program):
        return "is not owned by the declared token program"
    if len(data) < _TOKEN_ACCOUNT_LEN:
        return "is not an initialized token account"
    account_mint = Pubkey.from_bytes(data[0:32])
    account_owner = Pubkey.from_bytes(data[32:64])
    state = data[108]
    if account_mint != mint:
        return f"holds mint {account_mint} rather than {mint}"
    if account_owner != owner:
        return f"is owned by {account_owner} rather than {owner}"
    if state == _TOKEN_ACCOUNT_FROZEN:
        return "is frozen"
    extension = _unsupported_account_extension(data)
    if extension is not None:
        return f"carries token account extension {extension}, which this server will not settle through"
    if state != _TOKEN_ACCOUNT_INITIALIZED:
        return f"is in account state {state}"
    return None


def _request_path(request: Any) -> str:
    path = getattr(request, "path", None)
    if isinstance(path, str):
        return path
    url = getattr(request, "url", None)
    if url is not None:
        url_path = getattr(url, "path", None)
        if isinstance(url_path, str):
            return url_path
    if isinstance(request, dict):
        candidate = cast("dict[str, object]", request).get("path")
        if isinstance(candidate, str):
            return candidate
    return "/"


def _payment_signature_header(request: Any) -> str:
    headers = getattr(request, "headers", None)
    if headers is not None:
        getter = getattr(headers, "get", None)
        if callable(getter):
            for name in ("payment-signature", "Payment-Signature", "PAYMENT-SIGNATURE", "x-payment", "X-PAYMENT"):
                value: object = getter(name)
                if value:
                    return str(value)
    if isinstance(request, dict):
        raw_headers = cast("dict[str, object]", request).get("headers")
        if isinstance(raw_headers, dict):
            for key, header_value in cast("dict[object, object]", raw_headers).items():
                if isinstance(key, str) and key.lower() in ("payment-signature", "x-payment") and header_value:
                    return str(header_value)
    return ""
