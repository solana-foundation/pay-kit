"""x402 ``upto`` (Solana) server engine - ``payment-channel`` profile.

Self-hosted usage-based authorization. Unlike ``exact`` (one inline transfer
settled before the handler runs), ``upto`` is two-phase: :meth:`X402Upto.verify_open`
broadcasts the client's channel ``open`` (the signed deposit is the ceiling) and
binds the on-chain channel state *before* the resource is served;
:meth:`X402Upto.settle_actual` signs a receiver-authorizer voucher for the metered
amount and submits ``settle_and_seal`` + ATA setup + ``distribute``,
refunding ``deposit − actual`` *after* the resource is served.

Mirrors the Rust spine (``server/upto.rs``) and the Go reference
(``go/protocols/x402/upto.go``). The on-chain machinery is reused from
:mod:`solana_pay_kit._paycore.paymentchannels`; the wire types and pure checks live in
:mod:`solana_pay_kit.protocols.x402.upto.types` / ``.verify``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from solders.hash import Hash  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.message import Message  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]
from spl.token.instructions import (  # type: ignore[import-untyped]
    create_idempotent_associated_token_account,
)

from solana_pay_kit._paycore.currency import parse_units
from solana_pay_kit._paycore.mints import resolve, token_program_for
from solana_pay_kit._paycore.paymentchannels import (
    PAYMENT_CHANNELS_PROGRAM_ID,
    Distribution,
    build_distribute_instruction,
    build_settle_and_seal_instructions,
    treasury_owner,
    voucher_message_bytes,
)
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit._paycore.transaction import is_v0_wire_bytes
from solana_pay_kit.errors import ConfigurationError, InvalidProofError
from solana_pay_kit.protocols.programs.paymentchannels.accounts.channel import Channel
from solana_pay_kit.protocols.x402.exact.verify import X402_VERSION
from solana_pay_kit.protocols.x402.upto.types import (
    DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS,
    UPTO_SCHEME,
    UptoPayload,
    UptoRequirements,
    UptoSettlementResponse,
)
from solana_pay_kit.protocols.x402.upto.verify import (
    assert_settlement_within_ceiling,
    parse_base_units,
    validate_upto_open_instruction,
    verify_upto_payload,
)

if TYPE_CHECKING:
    from solana_pay_kit.config import Config
    from solana_pay_kit.gate import Gate
    from solana_pay_kit.signer import LocalSigner

__all__ = ["X402Upto", "VerifiedUptoOpen"]

# Settlement receipt headers (mirror the exact adapter + Go x402 constants).
_RESPONSE_HEADER = "payment-response"
_SETTLEMENT_HEADER = "x-payment-settlement-signature"
_CHALLENGE_HEADER = "payment-required"

# ChannelStatus::Open discriminant (generated types.channelStatus.Open = 0).
_CHANNEL_STATUS_OPEN = 0

# Default authorization window (Go DefaultMaxTimeoutSeconds).
_DEFAULT_MAX_TIMEOUT_SECONDS = 6 * 50  # 300

# The empty-recipient distribution hash baked into the program (no splits).
_EMPTY_DISTRIBUTION_HASH = [
    223, 63, 97, 152, 4, 169, 47, 219, 64, 87, 25, 45, 196, 61, 215, 72,
    234, 119, 138, 220, 82, 188, 73, 140, 232, 5, 36, 192, 20, 184, 17, 25,
]  # fmt: skip


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
    ) -> None:
        """Build an engine bound to ``config``; raise for delegated mode.

        ``recent_state_provider`` returns ``(recentBlockhash, recentSlot)``
        from a single ``getLatestBlockhash`` call (the response context
        carries the slot); when set it wins over the blockhash-only
        ``recent_blockhash_provider``, which is kept for embedders that only
        pre-fetch the blockhash. ``recentSlot`` is server-provided in the
        challenge: the client derives the channel PDA from it and never
        fetches the slot itself.
        """
        if config.x402.is_delegated():
            raise NotImplementedError(
                "solana_pay_kit: x402 delegated mode is not yet implemented; "
                "leave X402Config.facilitator_url None for self-hosted"
            )
        self._config = config
        # The channel program defaults to the canonical deployment; the harness
        # overrides it via the PAYMENT_CHANNELS_PROGRAM_ID env (matching Go/Rust).
        self._channel_program = (
            channel_program or os.environ.get("PAYMENT_CHANNELS_PROGRAM_ID") or PAYMENT_CHANNELS_PROGRAM_ID
        )
        self._recent_blockhash_provider = recent_blockhash_provider
        self._recent_state_provider = recent_state_provider
        # Per-channel in-flight reservation (verify_open -> settle_actual), guarded
        # so it is safe even under a threaded server (Go uses a mutex here too);
        # do not rely on set() atomicity for the check-then-add.
        self._in_flight: set[str] = set()
        self._in_flight_lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    def accepts_entry(self, gate: Gate, request: Any) -> UptoRequirements:
        """Build the route-pinned ``upto`` requirement (the server's offer)."""
        fee_payer = self._signer().pubkey()
        receiver_authorizer = fee_payer
        coin = gate.amount.primary_coin()
        coin_value = coin.value if coin is not None else self._config.stablecoins[0].value
        label = self._config.network.mints_label()
        asset = resolve(coin_value, label)
        if not asset:
            raise ConfigurationError(
                "solana_pay_kit: x402 upto requires an SPL token (not native SOL); "
                f"could not resolve mint for {coin_value!r}"
            )
        token_program = token_program_for(coin_value, label)
        pay_to = gate.pay_to or self._config.effective_recipient()
        try:
            amount = parse_units(gate.total().amount_string(), 6)
        except ValueError as exc:
            raise ConfigurationError(
                f"solana_pay_kit: x402 upto price {gate.total().amount_string()!r} "
                "exceeds 6-decimal (micro-unit) precision"
            ) from exc
        requirements: UptoRequirements = {
            "scheme": UPTO_SCHEME,
            "network": self._config.network.caip2(),
            "amount": str(amount),
            "asset": asset,
            "payTo": pay_to,
            "maxTimeoutSeconds": _DEFAULT_MAX_TIMEOUT_SECONDS,
            "extra": {
                "decimals": 6,
                "tokenProgram": token_program,
                "feePayer": fee_payer,
                "receiverAuthorizer": receiver_authorizer,
                "withdrawDelay": DEFAULT_UPTO_WITHDRAW_DELAY_SECONDS,
            },
        }
        blockhash, recent_slot = self._fetch_recent_state()
        if blockhash is not None:
            requirements["extra"]["recentBlockhash"] = blockhash
        if recent_slot is not None:
            # u64-as-string, matching the session challenge convention; the
            # client accepts string or number inbound.
            requirements["extra"]["recentSlot"] = str(recent_slot)
        return requirements

    def challenge_headers(self, gate: Gate, request: Any) -> dict[str, str]:
        """Build the ``payment-required`` header (base64 JSON challenge)."""
        envelope = {
            "x402Version": X402_VERSION,
            "resource": {"type": "http", "url": _request_path(request)},
            "accepts": [self.accepts_entry(gate, request)],
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

    async def verify_open(self, gate: Gate, request: Any) -> VerifiedUptoOpen:
        """Validate the credential, broadcast + confirm the channel ``open``, and
        bind the on-chain channel state. Reserves the channel until settlement.
        """
        import time

        signer = self._signer()
        fee_payer = signer.pubkey()
        receiver_authorizer = fee_payer

        header = _payment_signature_header(request)
        if not header:
            raise InvalidProofError("solana_pay_kit: payment required", code="payment_required")
        envelope = _decode_envelope(header)
        # x402 v2 (specs/x402-specification-v2.md §5.2): the chosen
        # PaymentRequirements live in `accepted`; `scheme` and `network` are
        # required there. There is no envelope-level scheme/network.
        accepted: dict[str, Any] = envelope.get("accepted") or {}
        if accepted.get("scheme") != UPTO_SCHEME:
            raise InvalidProofError(f"invalid payload type: {accepted.get('scheme')}", code="payment_invalid")

        requirements = self.accepts_entry(gate, request)
        payload = _parse_payload(envelope.get("payload"))
        verify_upto_payload(payload, requirements, receiver_authorizer, int(time.time()))

        # Phase 3: network + role keys bound to this server's offer. Network is
        # read from `accepted` (the canonical PaymentRequirements), per spec.
        if accepted.get("network") != requirements["network"]:
            raise InvalidProofError(
                f"network mismatch: payload {accepted.get('network')!r}, expected {requirements['network']!r}",
                code="payment_invalid",
            )
        if requirements["extra"].get("feePayer") != fee_payer:
            raise InvalidProofError("extra.feePayer is not this server's key", code="payment_invalid")
        if requirements["extra"].get("receiverAuthorizer") != receiver_authorizer:
            raise InvalidProofError("extra.receiverAuthorizer is not this server's key", code="payment_invalid")

        program_id = Pubkey.from_string(self._channel_program or PAYMENT_CHANNELS_PROGRAM_ID)
        mint = Pubkey.from_string(requirements["asset"])
        fee_payer_pubkey = Pubkey.from_string(fee_payer)
        receiver_authorizer_pubkey = Pubkey.from_string(receiver_authorizer)
        payee = receiver_authorizer_pubkey
        distribution = self._distribution(requirements)
        token_program = Pubkey.from_string(requirements["extra"]["tokenProgram"])
        channel_id = Pubkey.from_string(payload["channelId"])
        payer = Pubkey.from_string(payload["from"])
        max_amount = parse_base_units(payload["maxAmount"], "maxAmount")
        expires_at = int(payload["expiresAt"])

        released = False
        self._reserve_channel(str(channel_id))

        def _release() -> None:
            with self._in_flight_lock:
                self._in_flight.discard(str(channel_id))

        rpc = SolanaRpc(self._config.effective_rpc_url())
        try:
            open_tx = payload.get("openTransaction")
            if not open_tx:
                raise InvalidProofError(
                    "payment-channel asset transfer method requires openTransaction (pull)", code="payment_invalid"
                )
            account_keys, instructions = _decode_transaction(open_tx)
            # The challenged recentSlot at verify time: the requirement is
            # recomputed with a fresh slot from the recent-state provider, so
            # the transaction's openSlot (stamped from the earlier challenge)
            # must sit at-or-before it, inside the program freshness window.
            # None (provider unwired / fetch failed) skips the window check;
            # the PDA bind below still holds and the program enforces the
            # window at broadcast.
            raw_slot = requirements["extra"].get("recentSlot")
            challenged_slot = int(raw_slot) if isinstance(raw_slot, (int, str)) and str(raw_slot).isdigit() else None
            validate_upto_open_instruction(
                account_keys,
                instructions,
                program_id=program_id,
                fee_payer=fee_payer_pubkey,
                receiver_authorizer=receiver_authorizer_pubkey,
                payer=payer,
                payee=payee,
                mint=mint,
                token_program=token_program,
                channel_id=channel_id,
                max_amount=max_amount,
                withdraw_delay=int(requirements["extra"]["withdrawDelay"]),
                payload_nonce=payload["nonce"],
                payload_open_slot=payload["openSlot"],
                recent_slot=challenged_slot,
            )
            if not account_keys or account_keys[0] != fee_payer:
                raise InvalidProofError(
                    "open transaction fee payer must be the advertised fee payer", code="payment_invalid"
                )

            cosigned = _cosign_fee_payer(open_tx, signer)
            sent = await rpc.send_raw_transaction(cosigned)
            await rpc.await_confirmation(str(sent.value))

            channel = await self._fetch_channel(rpc, channel_id, program_id)
            self._validate_channel_state(
                channel,
                fee_payer_pubkey,
                receiver_authorizer_pubkey,
                payer,
                payee,
                mint,
                max_amount,
                int(requirements["extra"]["withdrawDelay"]),
                distribution,
            )

            verified = VerifiedUptoOpen(
                channel_id=channel_id,
                payer=payer,
                payee=payee,
                rent_payer=Pubkey.from_string(str(channel.rentPayer)),
                mint=mint,
                token_program=token_program,
                program_id=program_id,
                deposit=int(channel.deposit),
                max_amount=max_amount,
                expires_at=expires_at,
                network=requirements["network"],
                distribution=distribution,
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
        fee_payer = Pubkey.from_string(signer.pubkey())
        receiver_authorizer = fee_payer
        try:
            assert_settlement_within_ceiling(actual, verified.max_amount)

            if actual == 0:
                instructions: list[Instruction] = build_settle_and_seal_instructions(
                    payee=receiver_authorizer,
                    channel=verified.channel_id,
                    authorized_signer=receiver_authorizer,
                    signature=None,
                    cumulative=0,
                    expires_at=verified.expires_at,
                    program_id=verified.program_id,
                )
            else:
                message = voucher_message_bytes(verified.channel_id, actual, verified.expires_at)
                sig_bytes = signer.sign(message)
                if len(sig_bytes) != 64:
                    raise InvalidProofError(
                        f"voucher signature length {len(sig_bytes)}, want 64", code="payment_invalid"
                    )
                instructions = build_settle_and_seal_instructions(
                    payee=receiver_authorizer,
                    channel=verified.channel_id,
                    authorized_signer=receiver_authorizer,
                    signature=sig_bytes,
                    cumulative=actual,
                    expires_at=verified.expires_at,
                    program_id=verified.program_id,
                )

            # Settle to the payee the channel was opened and validated against in
            # verify_open (gate.pay_to), not the global recipient - a usage gate
            # may set its own pay_to, and distribute must target that ATA.
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
            create_recipient_atas = [
                create_idempotent_associated_token_account(
                    fee_payer, entry.recipient, verified.mint, verified.token_program
                )
                for entry in verified.distribution
            ]
            instructions = [*instructions, create_payee_ata, create_treasury_ata, *create_recipient_atas, distribute]

            rpc = SolanaRpc(self._config.effective_rpc_url())
            try:
                blockhash = Hash.from_string((await rpc.get_latest_blockhash()).value.blockhash)
                wire = _sign_legacy_transaction(instructions, fee_payer, blockhash, signer)
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

    def _signer(self) -> LocalSigner:
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
        receiver_authorizer = Pubkey.from_string(requirements["extra"]["receiverAuthorizer"])
        beneficiary = Pubkey.from_string(requirements["payTo"])
        if beneficiary == receiver_authorizer:
            return []
        return [Distribution(recipient=beneficiary, bps=10_000)]

    async def _fetch_channel(self, rpc: SolanaRpc, channel_id: Pubkey, program_id: Pubkey) -> Any:
        account = await rpc.get_account_info(str(channel_id))
        if account is None:
            raise InvalidProofError("channel account fetch failed: missing account data", code="payment_invalid")
        data, owner = account
        if owner != str(program_id):
            raise InvalidProofError(
                "channel account is not owned by the payment-channels program", code="payment_invalid"
            )
        # The on-chain account carries a 1-byte account discriminator ahead of
        # the struct (Go's `Channel.Discriminator uint8`); the generated
        # `Channel.decode` strips that leading byte before parsing the layout.
        if len(data) < 1:
            raise InvalidProofError("channel account fetch failed: empty account data", code="payment_invalid")
        return Channel.decode(data)

    def _validate_channel_state(
        self,
        channel: Any,
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
                f"recipient mismatch: expected {payee}, got {channel.payee}", code="payment_invalid"
            )
        expected_hash = list(_distribution_hash(distribution))
        if list(channel.distributionHash) != expected_hash:
            raise InvalidProofError(
                "channel distribution does not match the expected recipient split", code="payment_invalid"
            )
        if str(channel.authorizedSigner) != str(receiver_authorizer):
            raise InvalidProofError("channel authorized_signer is not the receiver authorizer", code="payment_invalid")
        if str(channel.rentPayer) != str(fee_payer):
            raise InvalidProofError("channel rent_payer is not the fee payer", code="payment_invalid")
        if int(channel.gracePeriod) != withdraw_delay:
            raise InvalidProofError(
                f"channel withdraw delay {channel.gracePeriod} does not match advertised {withdraw_delay}",
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


def _decode_envelope(header: str) -> dict[str, Any]:
    try:
        decoded = base64.b64decode(header, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise InvalidProofError("invalid upto payment signature base64", code="payment_invalid") from exc
    try:
        envelope = json.loads(decoded)
    except Exception as exc:  # noqa: BLE001
        raise InvalidProofError("invalid upto payment signature json", code="payment_invalid") from exc
    if not isinstance(envelope, dict):
        raise InvalidProofError("invalid upto payment signature envelope", code="payment_invalid")
    return cast("dict[str, Any]", envelope)


def _parse_payload(raw: Any) -> UptoPayload:
    """Validate the inbound payload dict and narrow it to the typed shape."""
    if not isinstance(raw, dict):
        raise InvalidProofError("upto payload missing or malformed", code="payment_invalid")
    payload = cast("dict[str, Any]", raw)
    for key in ("from", "maxAmount", "channelId", "deposit", "authorizedSigner", "nonce", "openSlot"):
        if not isinstance(payload.get(key), str) or not payload[key]:
            raise InvalidProofError(f"upto payload missing {key}", code="payment_invalid")
    return cast("UptoPayload", payload)


def _distribution_hash(distribution: list[Distribution]) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(struct.pack("<I", len(distribution)))
    for entry in distribution:
        hasher.update(bytes(entry.recipient))
        hasher.update(struct.pack("<H", entry.bps))
    return hasher.digest()


def _decode_transaction(transaction_b64: str) -> tuple[list[str], list[Any]]:
    """Decode a base64 (legacy or v0) transaction into ``(account_keys, instructions)``."""
    from solders.transaction import Transaction, VersionedTransaction

    try:
        raw = base64.b64decode(transaction_b64, validate=True)
        if is_v0_wire_bytes(raw):
            message = VersionedTransaction.from_bytes(raw).message
        else:
            try:
                message = Transaction.from_bytes(raw).message
            except Exception:  # noqa: BLE001 - fall back to versioned
                message = VersionedTransaction.from_bytes(raw).message
    except InvalidProofError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise InvalidProofError(f"invalid transaction: {exc}", code="payment_invalid") from exc
    account_keys = [str(key) for key in message.account_keys]
    return account_keys, list(message.instructions)


def _cosign_fee_payer(transaction_b64: str, signer: LocalSigner) -> bytes:
    """Splice the fee-payer signature into the client-built open tx.

    The client built the open with the advertised fee payer (slot 0) and signed
    only its own (payer) slot; the server completes the fee-payer signature and
    the result is broadcastable. Mirrors the exact-scheme cosign.
    """
    from solders.message import to_bytes_versioned
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    fee_payer = Pubkey.from_string(signer.pubkey())
    if is_v0_wire_bytes(raw):
        vtx = VersionedTransaction.from_bytes(raw)
        account_keys = list(vtx.message.account_keys)
        message_bytes = bytes(to_bytes_versioned(vtx.message))
        num_required = int(vtx.message.header.num_required_signatures)
    else:
        try:
            tx = Transaction.from_bytes(raw)
            account_keys = list(tx.message.account_keys)
            message_bytes = bytes(tx.message)
            num_required = int(tx.message.header.num_required_signatures)
        except Exception:  # noqa: BLE001
            vtx = VersionedTransaction.from_bytes(raw)
            account_keys = list(vtx.message.account_keys)
            message_bytes = bytes(to_bytes_versioned(vtx.message))
            num_required = int(vtx.message.header.num_required_signatures)
    try:
        idx = account_keys.index(fee_payer)
    except ValueError as exc:
        raise InvalidProofError("fee payer pubkey not present in transaction accounts", code="payment_invalid") from exc
    if idx >= num_required:
        raise InvalidProofError("fee payer is not a required signer", code="payment_invalid")
    sig = bytes(signer.sign(message_bytes))
    serialized = bytearray(raw)
    start = 1 + idx * 64
    serialized[start : start + 64] = sig
    return bytes(serialized)


def _sign_legacy_transaction(
    instructions: list[Instruction],
    fee_payer: Pubkey,
    blockhash: Hash,
    signer: LocalSigner,
) -> bytes:
    """Build a single-signer legacy transaction, sign with the fee payer, return wire.

    The current Python config uses one signer for both advertised roles, so the
    wire is ``[1][sig64][message]``. Building the
    message + signing via the abstract signer keeps the path KMS-agnostic.
    """
    message = Message.new_with_blockhash(instructions, fee_payer, blockhash)
    message_bytes = bytes(message)
    sig = bytes(signer.sign(message_bytes))
    if len(sig) != 64:
        raise InvalidProofError(f"settlement signature length {len(sig)}, want 64", code="payment_invalid")
    return bytes([1]) + sig + message_bytes


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
