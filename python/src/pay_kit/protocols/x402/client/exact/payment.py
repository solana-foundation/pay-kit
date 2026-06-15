"""x402 ``exact`` client: challenge parsing and payment-transaction building.

Mirrors the Rust spine client
(``rust/crates/x402/src/client/exact/payment.rs``) and the Go client
(``go/protocols/x402/client/client.go``) byte-for-behavior. The Python client
operates on the :class:`~pay_kit.protocols.x402.exact.types.X402AcceptsEntry`
wire shape the pay_kit x402 server emits and the
:class:`~pay_kit.protocols.x402.exact.verify.ExactVerifier` validates: the
offer carries the resolved on-chain mint on ``asset`` and the token program /
decimals / memo on ``extra``.

The built transaction is a v0 ``VersionedTransaction`` whose fee payer is the
offer's ``extra.feePayer`` (the facilitator, which cosigns server-side) and
whose transfer authority is the client signer. Instructions are laid out
exactly as the verifier expects: ComputeBudget SetComputeUnitLimit(20000) +
SetComputeUnitPrice, then a ``transferChecked`` (SPL) or System ``transfer``
(native SOL), then a Memo carrying ``extra.memo``.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from pay_kit._paycore.mints import derive_ata, resolve_stablecoin_mint
from pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2
from pay_kit._paycore.solana import (
    MEMO_PROGRAM,
    default_token_program_for_currency,
    is_native_sol,
)
from pay_kit.protocols.x402.exact.extensions import (
    echo_extensions,
    extensions_is_empty,
    generate_payment_identifier_id,
    requires_payment_identifier,
    with_payment_identifier_id,
)
from pay_kit.protocols.x402.exact.legacy import (
    SOLANA_DEVNET_NAME,
    SOLANA_NETWORK_NAME,
    SOLANA_TESTNET_NAME,
    X402_LEGACY_PAYMENT_REQUIRED_HEADER,
    caip2_for_network,
    legacy_network_for_caip2,
)
from pay_kit.protocols.x402.exact.types import X402AcceptsEntry, X402Envelope, X402PayloadField
from pay_kit.protocols.x402.exact.verify import (
    COMPUTE_BUDGET_PROGRAM,
    EXACT_SCHEME,
    X402_VERSION,
    X402_VERSION_V1,
)

if TYPE_CHECKING:
    from pay_kit.signer import LocalSigner

__all__ = [
    "ChallengeSelection",
    "parse_x402_challenge",
    "build_payment",
    "build_payment_header",
    "build_payment_header_legacy",
]

#: ComputeBudget SetComputeUnitLimit (disc 2, u32 LE). Matches the rust spine
#: client (``rust/crates/x402/src/client/exact/payment.rs``) and the Go client;
#: the server verifier checks the instruction shape + the price cap, not this
#: value, but the SDKs emit one canonical limit.
_COMPUTE_UNIT_LIMIT = 20_000
#: ComputeBudget SetComputeUnitPrice microlamports (disc 3, u64 LE, <= MAX).
_COMPUTE_UNIT_PRICE = 1
#: Default SPL decimals when the offer omits ``extra.decimals``.
_DEFAULT_DECIMALS = 6
#: Random memo nonce length in bytes when the offer omits ``extra.memo``. The
#: x402 SVM exact contract requires a Memo of at least 16 bytes; it is
#: hex-encoded to a UTF-8 string for the Memo instruction data.
_MEMO_NONCE_BYTES = 16


def _default_memo_nonce() -> str:
    """Generate a fresh >=16-byte memo nonce, hex-encoded for UTF-8.

    Used when the offer carries no ``extra.memo``. Injectable via
    :func:`build_payment`'s ``memo_nonce`` parameter so deterministic and
    golden-vector tests can pin a fixed nonce.
    """
    return secrets.token_bytes(_MEMO_NONCE_BYTES).hex()


# x402 ``exact`` CAIP-2 networks the client knows how to pay on.
_SOLANA_CAIP2 = frozenset({SOLANA_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2})


def _caip2_for_selection(network: str | None) -> str:
    """Resolve a client network preference (slug or CAIP-2) to a CAIP-2 id.

    ``None`` defaults to mainnet, mirroring the rust
    ``ChallengeSelection`` default. ``localnet`` shares the devnet CAIP-2
    (Surfpool forks mainnet state under the devnet genesis hash).
    """
    if network is None:
        return SOLANA_MAINNET_CAIP2
    lowered = network.strip()
    if lowered in _SOLANA_CAIP2:
        return lowered
    return {
        "mainnet": SOLANA_MAINNET_CAIP2,
        "mainnet-beta": SOLANA_MAINNET_CAIP2,
        "solana": SOLANA_MAINNET_CAIP2,
        "devnet": SOLANA_DEVNET_CAIP2,
        "solana-devnet": SOLANA_DEVNET_CAIP2,
        "localnet": SOLANA_DEVNET_CAIP2,
    }.get(lowered, SOLANA_MAINNET_CAIP2)


def _mints_label_for_caip2(caip2: str) -> str:
    """Bare mints-registry label (mainnet/devnet) for a Solana CAIP-2 id."""
    return "devnet" if caip2 == SOLANA_DEVNET_CAIP2 else "mainnet"


@dataclass(frozen=True)
class ChallengeSelection:
    """Client-side preferences for picking one offer from ``accepts``.

    Mirrors the rust ``ChallengeSelection``.
    """

    #: Solana network the client wants to pay on (cluster slug or CAIP-2).
    #: ``None`` defaults to mainnet.
    network: str | None = None
    #: Priority-ordered currencies the client will pay in (symbols or mints,
    #: interchangeable). The first server offer matching the highest-priority
    #: currency wins. ``None`` falls back to cheapest amount on the preferred
    #: network.
    currencies: Sequence[str] | None = None


def parse_x402_challenge(
    headers: Mapping[str, str],
    body: str | None,
    selection: ChallengeSelection,
) -> X402AcceptsEntry | None:
    """Parse an x402 ``exact`` challenge from response headers and/or body.

    Decodes the base64 JSON ``payment-required`` header first, then falls back
    to a JSON body carrying ``{"accepts": [...]}``. Filters to
    ``protocol == "x402"`` / ``scheme == "exact"`` offers on the preferred
    network, then picks by ``selection.currencies`` preference order, else the
    cheapest ``amount``. Returns ``None`` when no supported offer matches.
    Mirrors rust ``parse_x402_challenge_with_selection``.
    """
    offer, _version = parse_x402_challenge_with_version(headers, body, selection)
    return offer


def parse_x402_challenge_with_version(
    headers: Mapping[str, str],
    body: str | None,
    selection: ChallengeSelection,
) -> tuple[X402AcceptsEntry | None, int]:
    """Like :func:`parse_x402_challenge`, but also surfaces the DECLARED wire
    version of the challenge the offer came from, so the transport can emit the
    matching producer (v1 ``X-PAYMENT`` vs v2 ``PAYMENT-SIGNATURE``). Mirrors the
    go ``ParseChallengeVersioned`` / swift ``parseX402ChallengeWithVersion``.
    Returns ``(None, X402_VERSION)`` when no supported offer matches.
    """
    header_value = _lookup_header(headers, "payment-required")
    if header_value:
        offer, version = _select_from_header(header_value, selection)
        if offer is not None:
            return offer, version

    # Legacy precedence after the canonical (v2) header: the ``X-PAYMENT-REQUIRED``
    # header carries the legacy challenge as a plain (not base64) JSON object, the
    # same shape the 402 body carries. Mirrors rust ``parse_x402_challenge_with_
    # selection`` reading ``X402_V1_PAYMENT_REQUIRED_HEADER`` before the body
    # (rust/crates/x402/src/client/exact/payment.rs:246-253).
    legacy_header = _lookup_header(headers, X402_LEGACY_PAYMENT_REQUIRED_HEADER)
    if legacy_header:
        offer, version = _select_from_body(legacy_header, selection)
        if offer is not None:
            return offer, version

    # Final fallback: the legacy 402 JSON body ``{"accepts": [...]}`` with plain
    # SVM network slugs and ``maxAmountRequired``. Mirrors rust ``parse_accepts_
    # body`` (payment.rs:255-259).
    if body is not None:
        offer, version = _select_from_body(body, selection)
        if offer is not None:
            return offer, version

    return None, X402_VERSION


def _lookup_header(headers: Mapping[str, str], name: str) -> str | None:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def _select_from_header(header_value: str, selection: ChallengeSelection) -> tuple[X402AcceptsEntry | None, int]:
    try:
        decoded = base64.b64decode(header_value, validate=True)
        envelope = json.loads(decoded)
    except Exception:  # noqa: BLE001 - any decode failure means "no challenge here"
        return None, X402_VERSION
    return _select_from_envelope(envelope, selection)


def _select_from_body(body: str, selection: ChallengeSelection) -> tuple[X402AcceptsEntry | None, int]:
    try:
        envelope = json.loads(body)
    except Exception:  # noqa: BLE001
        return None, X402_VERSION
    return _select_from_envelope(envelope, selection)


def _select_from_envelope(envelope: object, selection: ChallengeSelection) -> tuple[X402AcceptsEntry | None, int]:
    if not isinstance(envelope, dict):
        return None, X402_VERSION
    envelope_dict = cast("dict[str, object]", envelope)
    raw_version = envelope_dict.get("x402Version")
    version = raw_version if isinstance(raw_version, int) else X402_VERSION
    accepts_raw = envelope_dict.get("accepts")
    if not isinstance(accepts_raw, list):
        return None, version
    entries = cast("list[object]", accepts_raw)
    accepts = [cast("dict[str, object]", entry) for entry in entries if isinstance(entry, dict)]
    _attach_envelope_resource(envelope_dict, accepts)
    return _select_requirement(accepts, selection), version


#: Private (non-wire) key under which the envelope-level v2 ``resource`` info is
#: stashed on a parsed accept. Stripped before the offer is echoed back as the
#: ``accepted`` body so it never reaches the wire. See ``_attach_envelope_resource``.
_RESOURCE_INFO_KEY = "__pay_kit_resource_info__"


def _attach_envelope_resource(
    envelope: Mapping[str, object],
    accepts: list[dict[str, object]],
) -> None:
    """Stash the envelope-level v2 ``resource`` object on each accept.

    Mirrors rust ``PaymentRequiredEnvelope::with_resource_on_accepts``
    (types.rs:463-476): the canonical v2 challenge carries ``resource`` at the
    envelope level and the rust deserializer attaches it to every parsed
    requirement so the client can echo it at the *envelope* top level.

    The rust client echoes the offer back as ``accepted`` via
    ``PaymentRequirements::to_accepted_value`` (types.rs:235-249), which for a
    parsed offer returns the original received JSON verbatim — it never folds
    ``resource``/``description`` into the ``accepted`` body. The server's
    structural ``deepEqual`` compares that echoed ``accepted`` against its own
    freshly built requirements, which carry no top-level ``resource``; adding
    those fields to the echo breaks the match (HTTP 402 ``payment_invalid``).

    So we stash the resolved resource info under a private (non-wire) key the
    echo path strips, instead of mutating the offer's wire fields. A per-offer
    ``resource``/``description`` already present on the accept still wins.
    """
    resource_value = envelope.get("resource")
    if not isinstance(resource_value, dict):
        return
    resource = cast("dict[str, object]", resource_value)
    url = resource.get("url")
    if not isinstance(url, str) or url == "":
        return
    description = resource.get("description")
    for accept in accepts:
        info: dict[str, object] = {"url": _str_field(accept, "resource") or url}
        offer_description = _str_field(accept, "description")
        if offer_description is not None:
            info["description"] = offer_description
        elif isinstance(description, str):
            info["description"] = description
        accept.setdefault(_RESOURCE_INFO_KEY, info)


#: Plain legacy SVM network slugs accepted on the challenge-parse path
#: alongside the canonical CAIP-2 ids.
_LEGACY_NETWORK_NAMES = frozenset({SOLANA_NETWORK_NAME, SOLANA_DEVNET_NAME, SOLANA_TESTNET_NAME})


def _is_solana_exact(offer: dict[str, object]) -> bool:
    scheme = offer.get("scheme")
    protocol = offer.get("protocol")
    network = offer.get("network")
    # ``protocol`` is optional in the canonical wire (x402-express omits it);
    # accept the offer when it is absent but reject an explicit non-x402 value.
    if protocol is not None and protocol != "x402":
        return False
    if scheme != "exact" or not isinstance(network, str):
        return False
    # Canonical (v2) offers carry a CAIP-2 network; legacy offers carry a plain
    # SVM slug. Accept both so the client can pay a legacy 402 challenge.
    return network in _SOLANA_CAIP2 or network in _LEGACY_NETWORK_NAMES


def _offer_network_caip2(offer: dict[str, object]) -> str | None:
    """Normalize an offer's network (CAIP-2 or plain slug) to a CAIP-2 id."""
    network = offer.get("network")
    if not isinstance(network, str):
        return None
    if network in _SOLANA_CAIP2:
        return network
    if network in _LEGACY_NETWORK_NAMES:
        return caip2_for_network(network)
    return None


def _amount_of(offer: dict[str, object]) -> int:
    raw = offer.get("amount")
    if raw is None:
        raw = offer.get("maxAmountRequired")
    try:
        return int(cast("str | int", raw))
    except (TypeError, ValueError):
        # Treat an unparseable amount as maximally expensive so it never wins
        # the cheapest-by-amount tiebreak (mirror rust ``u64::MAX``).
        return 1 << 64


def _currency_of(offer: dict[str, object]) -> str:
    asset = offer.get("asset")
    return asset if isinstance(asset, str) else ""


def _currencies_match(offered: str, accepted: str, label: str) -> bool:
    """``accepted`` (symbol or mint) resolves to the same mint as ``offered``."""
    offered_mint = resolve_stablecoin_mint(offered, label) or offered
    accepted_mint = resolve_stablecoin_mint(accepted, label) or accepted
    return offered_mint == accepted_mint


def _select_requirement(
    accepts: list[dict[str, object]],
    selection: ChallengeSelection,
) -> X402AcceptsEntry | None:
    preferred = _caip2_for_selection(selection.network)
    label = _mints_label_for_caip2(preferred)

    solana = [offer for offer in accepts if _is_solana_exact(offer)]
    # Compare on the normalized CAIP-2 network so a legacy offer naming
    # ``solana``/``solana-devnet`` matches the preferred CAIP-2 selection.
    on_preferred = [offer for offer in solana if _offer_network_caip2(offer) == preferred]

    if selection.currencies is not None:
        for wanted in selection.currencies:
            for offer in on_preferred:
                if _currencies_match(_currency_of(offer), wanted, label):
                    return cast("X402AcceptsEntry", offer)
        # The client explicitly listed currencies; do not fall back to an
        # unlisted one (mirror rust).
        return None

    candidates = on_preferred or solana
    if not candidates:
        return None
    cheapest = min(candidates, key=_amount_of)
    return cast("X402AcceptsEntry", cheapest)


def _compute_unit_limit_ix(instruction_cls: Any, pubkey_cls: Any, units: int) -> Any:
    program = pubkey_cls.from_string(COMPUTE_BUDGET_PROGRAM)
    data = bytes([2]) + units.to_bytes(4, "little")
    return instruction_cls(program, data, [])


def _compute_unit_price_ix(instruction_cls: Any, pubkey_cls: Any, micro_lamports: int) -> Any:
    program = pubkey_cls.from_string(COMPUTE_BUDGET_PROGRAM)
    data = bytes([3]) + micro_lamports.to_bytes(8, "little")
    return instruction_cls(program, data, [])


def _extra_of(requirement: X402AcceptsEntry) -> dict[str, object]:
    extra = cast("dict[str, object]", requirement).get("extra")
    return cast("dict[str, object]", extra) if isinstance(extra, dict) else {}


def _str_field(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value != "" else None


#: Exclusive upper bound for a Solana u64 amount (lamports / token base units).
_U64_BOUND = 1 << 64


def _str_top_then_extra(
    req: Mapping[str, object],
    extra: Mapping[str, object],
    key: str,
) -> str | None:
    """Read a string field top-level first, then ``extra.*``.

    Mirrors the rust ``PaymentRequirements`` deserializer field precedence
    (``rust/crates/x402/src/protocol/schemes/exact/types.rs:344-351``) where
    canonical-wire fields (``tokenProgram``/``recentBlockhash``) are read at the
    top level before falling back to ``extra``.
    """
    return _str_field(req, key) or _str_field(extra, key)


def _bool_field(mapping: Mapping[str, object], key: str) -> bool | None:
    value = mapping.get(key)
    return value if isinstance(value, bool) else None


async def build_payment(
    signer: LocalSigner,
    rpc: Any,
    requirement: X402AcceptsEntry,
    *,
    recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    memo_nonce: Callable[[], str] | None = None,
    advertised_extensions: dict[str, Any] | None = None,
    payment_identifier_id: str | None = None,
) -> X402Envelope:
    """Build a signed x402 ``exact`` payment transaction for ``requirement``.

    Lays out the instructions the verifier expects, compiles a v0
    ``VersionedTransaction`` with the offer's ``extra.feePayer`` as fee payer
    (cosigned server-side) and the client ``signer`` as transfer authority,
    signs the client's signature slot, and returns the
    :class:`~pay_kit.protocols.x402.exact.types.X402Envelope` carrying the
    standard-base64 transaction. Mirrors rust ``build_payment`` /
    ``build_payment_header``.

    The blockhash comes from ``requirement.extra.recentBlockhash`` when present,
    else ``recent_blockhash_provider`` (injected for offline unit tests), else
    ``await rpc.get_latest_blockhash()``.

    The client ALWAYS appends exactly one Memo instruction. When the offer
    carries ``extra.memo`` that value is used; otherwise a random >=16-byte
    hex-encoded nonce guarantees uniqueness of otherwise-identical payments
    (the Memo is what lets the facilitator distinguish concurrent identical
    transfers). ``memo_nonce`` overrides the default secure RNG source so
    deterministic / golden-vector tests can pin a fixed nonce.

    ``advertised_extensions`` is the ``extensions`` object the server published
    on the inbound ``PAYMENT-REQUIRED`` challenge. The client echoes it back
    onto the outbound credential verbatim (preserving unknown extensions for
    forward-compat, x402 v2 §5.1.2) and, when the server marked
    ``payment-identifier.info.required = true``, fills ``info.id`` with
    ``payment_identifier_id`` (or a freshly generated ``pay_`` id, reused across
    retries for idempotency). When the server advertised nothing, the
    ``extensions`` key is omitted entirely (no empty ``{}``). Mirrors rust
    ``PaymentExtensions::{echoing, requires_payment_identifier,
    with_payment_identifier_id, is_empty}``.
    """
    from solders.hash import Hash
    from solders.instruction import AccountMeta, Instruction
    from solders.message import MessageV0, to_bytes_versioned
    from solders.pubkey import Pubkey
    from solders.signature import Signature
    from solders.transaction import VersionedTransaction

    req = cast("dict[str, object]", requirement)
    extra = _extra_of(requirement)

    # Field precedence mirrors the rust ``PaymentRequirements`` deserializer
    # (types.rs:334-353): top-level ``currency``/``recipient`` win over the
    # canonical-wire ``asset``/``payTo`` aliases.
    asset = _str_field(req, "currency") or _str_field(req, "asset")
    if asset is None:
        raise ValueError("pay_kit: x402 offer is missing `asset`")
    pay_to = _str_field(req, "recipient") or _str_field(req, "payTo")
    if pay_to is None:
        raise ValueError("pay_kit: x402 offer is missing `payTo`")

    amount_raw = req.get("amount")
    if amount_raw is None:
        amount_raw = req.get("maxAmountRequired")
    try:
        amount = int(cast("str | int", amount_raw))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"pay_kit: x402 offer has an invalid amount: {amount_raw!r}") from exc
    # Amount must fit an unsigned u64, matching rust ``amount.parse::<u64>()``
    # (client/exact/payment.rs:33-36). Reject out-of-range here rather than
    # deferring to a later ``int.to_bytes(8, ...)`` OverflowError.
    if amount < 0 or amount >= _U64_BOUND:
        raise ValueError(f"pay_kit: x402 offer has an invalid amount: {amount_raw!r}")

    # Fee-payer toggle + precedence (types.rs:350-353, payment.rs:43-51):
    # key comes from top-level ``feePayerKey`` first, else ``extra.feePayer``;
    # ``use_fee_payer`` is the explicit ``feePayer`` bool when present, else true
    # when a key is present. An explicit ``feePayer: false`` opts OUT even with a
    # key, in which case the client signer is the message fee payer.
    fee_payer = _str_field(req, "feePayerKey") or _str_field(extra, "feePayer")
    fee_payer_bool = _bool_field(req, "feePayer")
    use_fee_payer = (fee_payer_bool if fee_payer_bool is not None else fee_payer is not None) and (
        fee_payer is not None
    )
    fee_payer_key = Pubkey.from_string(cast("str", fee_payer)) if use_fee_payer else signer.keypair.pubkey()

    instructions: list[Any] = [
        _compute_unit_limit_ix(Instruction, Pubkey, _COMPUTE_UNIT_LIMIT),
        _compute_unit_price_ix(Instruction, Pubkey, _COMPUTE_UNIT_PRICE),
    ]

    signer_pubkey = signer.keypair.pubkey()
    recipient_key = Pubkey.from_string(pay_to)

    if is_native_sol(asset):
        from solders.system_program import TransferParams, transfer

        instructions.append(
            transfer(TransferParams(from_pubkey=signer_pubkey, to_pubkey=recipient_key, lamports=amount))
        )
    else:
        # tokenProgram: top-level first, then extra (types.rs:346-347). When the
        # offer omits it entirely, default by currency/cluster like rust
        # ``default_token_program_for_currency`` (payment.rs:445-452) instead of
        # erroring, so a canonical offer that elides tokenProgram still builds.
        token_program = _str_top_then_extra(req, extra, "tokenProgram")
        if token_program is None:
            cluster_label = _mints_label_for_caip2(_caip2_for_selection(_str_field(req, "network")))
            token_program = default_token_program_for_currency(asset, cluster_label)
        # decimals: top-level first, then extra (types.rs:344-345); default 6.
        decimals_raw = req.get("decimals")
        if not isinstance(decimals_raw, int) or isinstance(decimals_raw, bool):
            decimals_raw = extra.get("decimals")
        decimals = (
            int(decimals_raw)
            if isinstance(decimals_raw, int) and not isinstance(decimals_raw, bool)
            else _DEFAULT_DECIMALS
        )
        token_program_key = Pubkey.from_string(token_program)
        mint_key = Pubkey.from_string(asset)
        source_ata = Pubkey.from_string(derive_ata(str(signer_pubkey), asset, token_program))
        dest_ata = Pubkey.from_string(derive_ata(pay_to, asset, token_program))
        # SPL Token TransferChecked (disc 12): amount u64 LE + decimals u8.
        data = bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals & 0xFF])
        instructions.append(
            Instruction(
                token_program_key,
                data,
                [
                    AccountMeta(source_ata, False, True),
                    AccountMeta(mint_key, False, False),
                    AccountMeta(dest_ata, False, True),
                    AccountMeta(signer_pubkey, True, False),
                ],
            )
        )

    # Always append exactly one Memo. Use the offer's memo when present, else a
    # random >=16-byte hex nonce so two otherwise-identical payments produce
    # distinct transactions. The verifier requires this slot for uniqueness.
    memo = _str_field(extra, "memo")
    if memo is None:
        memo = (memo_nonce or _default_memo_nonce)()
    instructions.append(Instruction(Pubkey.from_string(MEMO_PROGRAM), memo.encode("utf-8"), []))

    # recentBlockhash: top-level first, then extra (types.rs:348-349).
    blockhash_str = _str_top_then_extra(req, extra, "recentBlockhash")
    if blockhash_str is None:
        blockhash_str = await _resolve_blockhash(rpc, recent_blockhash_provider)
    blockhash = Hash.from_string(blockhash_str)

    message = MessageV0.try_compile(fee_payer_key, instructions, [], blockhash)
    num_signers = int(message.header.num_required_signatures)
    tx = VersionedTransaction.populate(message, [Signature.default() for _ in range(num_signers)])

    sig = Signature.from_bytes(signer.sign(bytes(to_bytes_versioned(message))))
    account_keys = list(message.account_keys)
    try:
        signer_index = account_keys.index(signer_pubkey)
    except ValueError as exc:
        raise ValueError("pay_kit: signer not found in transaction accounts") from exc
    signatures = list(tx.signatures)
    signatures[signer_index] = sig
    tx = VersionedTransaction.populate(message, signatures)

    # Derive the envelope-level resource BEFORE building the echoed ``accepted``
    # body, then strip the private resource-info key so the echo carries only
    # the offer's wire fields. The rust client echoes the offer verbatim via
    # ``to_accepted_value`` and the rust server's structural compare rejects any
    # extra top-level field; mirror that exactly.
    resource_info = _resource_info_of(req)
    accepted = {key: value for key, value in req.items() if key != _RESOURCE_INFO_KEY}

    encoded = base64.b64encode(bytes(tx)).decode("ascii")
    payload: X402PayloadField = {"transaction": encoded}
    envelope: dict[str, object] = {
        "x402Version": X402_VERSION,
        "accepted": accepted,
        "payload": payload,
    }
    # Echo the offer's resource info at the envelope top level, mirroring rust
    # ``build_payment_header`` (payment.rs:131-138) which sets
    # ``resource: requirements.resource_info()``. Omit when the offer carries no
    # resource (rust ``skip_serializing_if = Option::is_none``).
    if resource_info is not None:
        envelope["resource"] = resource_info

    # Echo-and-append the v2 ``extensions`` object (x402 v2 §5.1.2). Echo the
    # server's advertised extensions verbatim (unknown keys preserved), fill the
    # required client-side payment-identifier.info.id when the server requires
    # it, and omit the key entirely when the server advertised nothing or the
    # echoed object is structurally empty. Mirrors rust ``build_payment_header``
    # (payment.rs:139-147) + ``PaymentExtensions`` helpers.
    extensions = echo_extensions(advertised_extensions)
    if requires_payment_identifier(extensions):
        payment_id = payment_identifier_id or generate_payment_identifier_id()
        extensions = with_payment_identifier_id(extensions, payment_id)
    if extensions is not None and not extensions_is_empty(extensions):
        envelope["extensions"] = extensions
    return cast("X402Envelope", envelope)


def _resource_info_of(req: Mapping[str, object]) -> dict[str, object] | None:
    """Build the canonical v2 ``resource`` object for the envelope top level.

    Mirrors rust ``PaymentRequirements::resource_info`` (types.rs:253-265):
    prefer the resource info stashed from the envelope-level v2 ``resource``
    (``_attach_envelope_resource``), then fall back to a per-offer top-level
    ``resource`` URL string with optional ``description``. Returns ``None`` when
    neither is present.
    """
    stashed = req.get(_RESOURCE_INFO_KEY)
    if isinstance(stashed, dict):
        return cast("dict[str, object]", stashed)
    url = _str_field(req, "resource")
    if url is None:
        return None
    info: dict[str, object] = {"url": url}
    description = _str_field(req, "description")
    if description is not None:
        info["description"] = description
    return info


async def _resolve_blockhash(
    rpc: Any,
    provider: Callable[[], Awaitable[str] | str] | None,
) -> str:
    if provider is not None:
        result = provider()
        if isinstance(result, str):
            return result
        return await result
    response = await rpc.get_latest_blockhash()
    value = getattr(response, "value", response)
    blockhash = getattr(value, "blockhash", value)
    return str(blockhash)


async def build_payment_header(
    signer: LocalSigner,
    rpc: Any,
    requirement: X402AcceptsEntry,
    *,
    recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    memo_nonce: Callable[[], str] | None = None,
    advertised_extensions: dict[str, Any] | None = None,
    payment_identifier_id: str | None = None,
) -> str:
    """Build the standard-base64 ``PAYMENT-SIGNATURE`` header value.

    Wraps :func:`build_payment` and base64-encodes the
    :class:`~pay_kit.protocols.x402.exact.types.X402Envelope` JSON. Mirrors rust
    ``build_payment_header``. ``advertised_extensions`` / ``payment_identifier_id``
    drive the v2 extensions echo-and-append (see :func:`build_payment`).
    """
    envelope = await build_payment(
        signer,
        rpc,
        requirement,
        recent_blockhash_provider=recent_blockhash_provider,
        memo_nonce=memo_nonce,
        advertised_extensions=advertised_extensions,
        payment_identifier_id=payment_identifier_id,
    )
    payload = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


async def build_payment_header_legacy(
    signer: LocalSigner,
    rpc: Any,
    requirement: X402AcceptsEntry,
    *,
    recent_blockhash_provider: Callable[[], Awaitable[str] | str] | None = None,
    memo_nonce: Callable[[], str] | None = None,
) -> str:
    """Build the legacy standard-base64 ``X-PAYMENT`` header value.

    The legacy wire is a SEPARATE shape from the canonical (v2) producer: the
    envelope is ``{x402Version: 1, scheme: "exact", network: <plain slug>,
    payload: {transaction}}`` with ``scheme`` and ``network`` as TOP-LEVEL
    siblings of ``payload`` and NO ``accepted`` object. The plain network slug
    (``solana`` / ``solana-devnet``) is derived from the offer's network via
    :func:`legacy_network_for_caip2`. Mirrors rust ``build_payment_header_v1``
    (rust/crates/x402/src/client/exact/payment.rs:153-170).

    The canonical (v2) producer (:func:`build_payment_header`) stays the
    default; emit this legacy shape only when the server's challenge declared
    the legacy version.
    """
    envelope = await build_payment(
        signer,
        rpc,
        requirement,
        recent_blockhash_provider=recent_blockhash_provider,
        memo_nonce=memo_nonce,
    )
    # The legacy envelope commits only to scheme + plain network, not an
    # ``accepted`` body. Reuse the signed transaction from the canonical build
    # and re-wrap it in the legacy top-level shape.
    payload_field = cast("dict[str, object]", envelope).get("payload")
    network_caip2 = _str_field(cast("dict[str, object]", requirement), "network")
    legacy_envelope: dict[str, object] = {
        "x402Version": X402_VERSION_V1,
        "scheme": EXACT_SCHEME,
        "network": legacy_network_for_caip2(network_caip2),
        "payload": payload_field,
    }
    encoded = json.dumps(legacy_envelope, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")
