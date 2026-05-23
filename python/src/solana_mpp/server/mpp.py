"""Main server-side Solana charge handler."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from solana_mpp._base64url import encode_json
from solana_mpp._errors import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    PaymentError,
    ReplayError,
)
from solana_mpp._types import PaymentChallenge, PaymentCredential, Receipt
from solana_mpp.protocol.intents import ChargeRequest, parse_units
from solana_mpp.protocol.solana import (
    MEMO_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    CredentialPayload,
    MethodDetails,
    default_rpc_url,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
    stablecoin_symbol,
)
from solana_mpp.server.network_check import check_network_blockhash
from solana_mpp.store import Store

logger = logging.getLogger(__name__)

_DEFAULT_REALM = "MPP Payment"
_SECRET_KEY_ENV_VAR = "MPP_SECRET_KEY"
_CONSUMED_PREFIX = "solana-charge:consumed:"
_SYSTEM_PROGRAM = "11111111111111111111111111111111"
_SYSTEM_TRANSFER_INSTRUCTION = 2
_TOKEN_TRANSFER_CHECKED_INSTRUCTION = 12

# Legacy Solana memo program (v1). MPP charge transactions MUST use memo v2
# (``MEMO_PROGRAM`` from :mod:`solana_mpp.protocol.solana`). v1 had a different
# instruction shape and is rejected to match the L2 lock landed on PHP fde0efb
# and mirrored in Ruby, Rust, Lua.
_MEMO_V1_PROGRAM = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"


def _build_expected_transfers(request: ChargeRequest, details: MethodDetails) -> list[tuple[str, int]]:
    total_amount = int(request.amount)
    split_total = sum(int(split.amount) for split in details.splits)
    primary_amount = total_amount - split_total
    if primary_amount <= 0:
        raise PaymentError(
            "splits consume the entire amount — primary recipient must receive a positive amount",
            code="splits-exceed-amount",
        )

    expected = [(request.recipient, primary_amount)]
    for split in details.splits:
        expected.append((split.recipient, int(split.amount)))
    return expected


def _verify_parsed_sol_transfers(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    expected = _build_expected_transfers(request, details)
    transfers = [
        instruction
        for instruction in instructions
        if instruction.get("program") == "system" and (instruction.get("parsed") or {}).get("type") == "transfer"
    ]

    for recipient, amount in expected:
        match_index = next(
            (
                index
                for index, transfer in enumerate(transfers)
                if ((transfer.get("parsed") or {}).get("info") or {}).get("destination") == recipient
                and str(((transfer.get("parsed") or {}).get("info") or {}).get("lamports")) == str(amount)
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f"no matching SOL transfer for {recipient}", code="no-transfer")
        transfers.pop(match_index)


def _verify_parsed_spl_transfers(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    expected = _build_expected_transfers(request, details)
    program_id = details.token_program or default_token_program_for_currency(request.currency, details.network)
    mint = resolve_mint(request.currency, details.network)
    transfers = [
        instruction
        for instruction in instructions
        if instruction.get("programId") == program_id
        and (instruction.get("parsed") or {}).get("type") == "transferChecked"
    ]

    for recipient, amount in expected:
        match_index = next(
            (
                index
                for index, transfer in enumerate(transfers)
                if ((transfer.get("parsed") or {}).get("info") or {}).get("mint") == mint
                and str((((transfer.get("parsed") or {}).get("info") or {}).get("tokenAmount") or {}).get("amount"))
                == str(amount)
                and _verify_ata_owner(
                    ((transfer.get("parsed") or {}).get("info") or {}).get("destination", ""),
                    recipient,
                    mint,
                    program_id,
                )
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f"no matching token transfer for {recipient}", code="no-transfer")
        transfers.pop(match_index)


def _verify_ata_owner(ata_address: str, expected_owner: str, mint: str, token_program: str) -> bool:
    """Verify that an ATA address belongs to the expected owner by deriving it."""
    try:
        from solders.pubkey import Pubkey

        owner_pk = Pubkey.from_string(expected_owner)
        mint_pk = Pubkey.from_string(mint)
        tp_pk = Pubkey.from_string(token_program)
        ata_program = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
        expected_ata, _bump = Pubkey.find_program_address(
            [bytes(owner_pk), bytes(tp_pk), bytes(mint_pk)],
            ata_program,
        )
        return str(expected_ata) == ata_address
    except Exception:
        return False


def _parsed_program_id(instruction: dict[str, Any]) -> str:
    program_id = instruction.get("programId") or instruction.get("program_id")
    if isinstance(program_id, str):
        return program_id
    if instruction.get("program") == "spl-memo":
        return MEMO_PROGRAM
    return ""


def _parsed_memo_text(instruction: dict[str, Any]) -> str | None:
    parsed = instruction.get("parsed")
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, dict):
        info = parsed.get("info")
        if isinstance(info, dict):
            memo = info.get("memo")
            if isinstance(memo, str):
                return memo
            data = info.get("data")
            if isinstance(data, str):
                return data
    return None


def _expected_memos(request: ChargeRequest, details: MethodDetails) -> list[tuple[str, str]]:
    expected: list[tuple[str, str]] = []
    if request.external_id:
        expected.append(("externalId", request.external_id))
    for split in details.splits:
        if split.memo:
            expected.append(("split", split.memo))
    return expected


def _verify_parsed_memo_instructions(
    instructions: list[dict[str, Any]],
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    matched: set[int] = set()
    for label, memo in _expected_memos(request, details):
        if len(memo.encode("utf-8")) > 566:
            raise PaymentError("memo cannot exceed 566 bytes", code="invalid-payload")

        match_index = next(
            (
                index
                for index, instruction in enumerate(instructions)
                if index not in matched
                and _parsed_program_id(instruction) == MEMO_PROGRAM
                and _parsed_memo_text(instruction) == memo
            ),
            -1,
        )
        if match_index == -1:
            raise PaymentError(f'No memo instruction found for {label} memo "{memo}"', code="invalid-payload")
        matched.add(match_index)

    for index, instruction in enumerate(instructions):
        if index not in matched and _parsed_program_id(instruction) == MEMO_PROGRAM:
            raise PaymentError("unexpected Memo Program instruction in payment transaction", code="invalid-payload")


def _rpc_value(response: Any) -> Any:
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("value", response)
    return getattr(response, "value", response)


def _json_like(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: _json_like(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_like(item) for item in value]
    if hasattr(value, "to_json"):
        return json.loads(value.to_json())
    if hasattr(value, "__dict__"):
        return {key: _json_like(val) for key, val in vars(value).items()}
    return value


def _transaction_dict(response: Any) -> dict[str, Any] | None:
    value = _rpc_value(response)
    if value is None:
        return None
    data = _json_like(value)
    if isinstance(data, dict) and "transaction" in data:
        return data
    return None


def _status_ok(response: Any) -> bool:
    value = _rpc_value(response)
    data = _json_like(value)
    if isinstance(data, list):
        return any(entry and entry.get("err") is None for entry in data)
    return data is not None


def _extract_recent_blockhash(transaction_b64: str) -> str:
    """Decode a base64 transaction and return its recent blockhash (base58).

    Tries the legacy ``Transaction`` first (the most common shape from our
    SDK clients) and falls back to ``VersionedTransaction``. Kept thin so
    the surrounding network check can be exercised by tests without a full
    verification pipeline in place.
    """
    import base64

    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    try:
        tx = Transaction.from_bytes(raw)
        return str(tx.message.recent_blockhash)
    except Exception:
        vtx = VersionedTransaction.from_bytes(raw)
        return str(vtx.message.recent_blockhash)


def _decode_legacy_payment_instructions(transaction_b64: str) -> list[dict[str, Any]]:
    """Decode local transfer and memo instructions from a legacy or v0 transaction.

    Accepts both legacy ``Transaction`` and ``VersionedTransaction``. For v0
    we only inspect the static account keys; address lookup tables are
    rejected up-front (a v0 tx with a non-empty ALT list would let an
    instruction reference accounts the verifier cannot see). Mirrors the
    Rust spine's ``verify_versioned_transaction_pre_broadcast`` policy.
    """
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    message: Any
    try:
        tx = Transaction.from_bytes(raw)
        message = tx.message
        message_instructions = list(tx.message.instructions)
    except Exception:
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:
            raise PaymentError(
                "unsupported transaction shape for pre-broadcast verification",
                code="invalid-payload-type",
            ) from exc
        # Reject v0 transactions that reference address lookup tables; the
        # pre-broadcast verifier only sees static account keys.
        lookups = getattr(vtx.message, "address_table_lookups", None)
        if lookups:
            raise PaymentError(
                "v0 transactions with address lookup tables are not supported",
                code="invalid-payload",
            ) from None
        message = vtx.message
        message_instructions = list(vtx.message.instructions)

    account_keys = [str(key) for key in message.account_keys]
    instructions: list[dict[str, Any]] = []
    for instruction in message_instructions:
        try:
            program_id = account_keys[int(instruction.program_id_index)]
        except IndexError as exc:
            raise PaymentError("transaction instruction references an unknown program", code="invalid-payload") from exc
        data = bytes(instruction.data)
        if program_id == _SYSTEM_PROGRAM:
            if len(data) < 12:
                continue
            kind = int.from_bytes(data[:4], "little")
            if kind != _SYSTEM_TRANSFER_INSTRUCTION or len(instruction.accounts) < 2:
                continue
            try:
                destination = account_keys[int(instruction.accounts[1])]
            except IndexError as exc:
                raise PaymentError(
                    "transaction transfer references an unknown account", code="invalid-payload"
                ) from exc
            lamports = int.from_bytes(data[4:12], "little")
            instructions.append(
                {
                    "program": "system",
                    "parsed": {
                        "type": "transfer",
                        "info": {
                            "destination": destination,
                            "lamports": str(lamports),
                        },
                    },
                }
            )
        elif program_id in {TOKEN_PROGRAM, TOKEN_2022_PROGRAM}:
            if len(data) < 10:
                continue
            kind = data[0]
            if kind != _TOKEN_TRANSFER_CHECKED_INSTRUCTION or len(instruction.accounts) < 3:
                continue
            try:
                mint = account_keys[int(instruction.accounts[1])]
                destination = account_keys[int(instruction.accounts[2])]
            except IndexError as exc:
                raise PaymentError(
                    "transaction token transfer references an unknown account", code="invalid-payload"
                ) from exc
            amount = int.from_bytes(data[1:9], "little")
            instructions.append(
                {
                    "programId": program_id,
                    "parsed": {
                        "type": "transferChecked",
                        "info": {
                            "destination": destination,
                            "mint": mint,
                            "tokenAmount": {"amount": str(amount)},
                        },
                    },
                }
            )
        elif program_id == MEMO_PROGRAM:
            try:
                memo = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PaymentError("memo instruction is not valid UTF-8", code="invalid-payload") from exc
            instructions.append({"programId": MEMO_PROGRAM, "parsed": memo})
        elif program_id == _MEMO_V1_PROGRAM:
            # L2 lock: MPP charge requires memo v2. Memo v1 has a different
            # instruction shape (UTF-8 directly in data with no signer check)
            # and would let a tampered transaction slip past the v2-only
            # ``_verify_parsed_memo_instructions`` matcher.
            raise PaymentError(
                "memo v1 program is not supported (use Memo v2)",
                code="invalid-payload",
            )

    return instructions


def _co_sign_with_fee_payer(transaction_b64: str, fee_payer: Any) -> str:
    """Co-sign a client transaction with the server's fee payer keypair.

    The fee payer occupies the first signer slot in Solana transactions. We
    serialize the message in the correct shape for its version (legacy uses
    ``bytes(msg)``; v0 uses ``to_bytes_versioned(msg)`` which prepends the
    ``0x80`` version tag), sign with the fee-payer private key, and splice
    the resulting signature into the signature array at the slot matching
    the fee-payer pubkey.

    Mirrors the cosign step in rust/src/server/charge.rs verify_pull.
    """
    from solders.message import to_bytes_versioned
    from solders.transaction import Transaction, VersionedTransaction

    raw = base64.b64decode(transaction_b64)
    fee_payer_pubkey = fee_payer.pubkey()

    # Try legacy transaction first (the common path); fall back to versioned.
    try:
        tx = Transaction.from_bytes(raw)
    except Exception:
        try:
            vtx = VersionedTransaction.from_bytes(raw)
        except Exception as exc:
            raise PaymentError(
                f"could not decode transaction for fee payer co-sign: {exc}",
                code="invalid-payload-type",
            ) from exc
        account_keys = list(vtx.message.account_keys)
        try:
            idx = account_keys.index(fee_payer_pubkey)
        except ValueError as exc:
            raise PaymentError(
                "fee payer pubkey not present in transaction accounts",
                code="invalid-payload",
            ) from exc
        num_required = int(vtx.message.header.num_required_signatures)
        _assert_signature_slot(idx, num_required)
        # v0 messages are signed over ``to_bytes_versioned(msg)`` which
        # prepends the 0x80 version byte.
        message_bytes = bytes(to_bytes_versioned(vtx.message))
        sig_bytes = bytes(fee_payer.sign_message(message_bytes))
        # Manual splice in the on-wire bytes preserves the rest of the
        # transaction exactly. Wire format: [num_sigs (compact-u16)] [sigs]
        # [message...]. num_sigs < 128 so it is a 1-byte prefix.
        serialized = bytearray(raw)
        sig_start = 1 + idx * 64
        serialized[sig_start : sig_start + 64] = sig_bytes
        return base64.b64encode(bytes(serialized)).decode("ascii")

    account_keys = list(tx.message.account_keys)
    try:
        idx = account_keys.index(fee_payer_pubkey)
    except ValueError as exc:
        raise PaymentError(
            "fee payer pubkey not present in transaction accounts",
            code="invalid-payload",
        ) from exc
    num_required = int(tx.message.header.num_required_signatures)
    _assert_signature_slot(idx, num_required)

    # Legacy Transaction: sign ``bytes(msg)`` directly.
    message_bytes = bytes(tx.message)
    sig_bytes = bytes(fee_payer.sign_message(message_bytes))
    serialized = bytearray(raw)
    sig_start = 1 + idx * 64
    serialized[sig_start : sig_start + 64] = sig_bytes
    return base64.b64encode(bytes(serialized)).decode("ascii")


def _assert_signature_slot(idx: int, num_required: int) -> None:
    """Validate that ``idx`` falls inside the required-signers block.

    The Solana wire format reserves one 64-byte slot per required signer at
    the head of the transaction; account keys outside the
    ``num_required_signatures`` block live in the readonly-signed or
    unsigned regions and have no signature slot. Splicing into ``1 + idx *
    64`` for an out-of-range ``idx`` overwrites message bytes and produces
    a corrupted transaction that the cluster would reject opaquely. We
    reject the credential here with a clear ``payment_invalid`` so the
    client sees a deterministic failure.
    """
    if idx < 0 or idx >= num_required:
        raise PaymentError(
            f"fee payer pubkey at account index {idx} is outside the "
            f"required-signers block (num_required_signatures={num_required}); "
            "a client must place the fee payer inside the signer header",
            code="invalid-payload",
        )


def _verify_local_transaction_intent(
    transaction_b64: str,
    request: ChargeRequest,
    details: MethodDetails,
) -> None:
    """Verify locally-decodable payment intent before broadcasting."""
    instructions = _decode_legacy_payment_instructions(transaction_b64)
    if is_native_sol(request.currency):
        _verify_parsed_sol_transfers(instructions, request, details)
    else:
        _verify_parsed_spl_transfers(instructions, request, details)
    _verify_parsed_memo_instructions(instructions, request, details)


@dataclass
class ChargeOptions:
    """Options for charge challenge generation."""

    description: str = ""
    external_id: str = ""
    expires: str = ""
    fee_payer: bool = False
    splits: list[dict] = field(default_factory=list)


@dataclass
class Config:
    """Server-side configuration."""

    recipient: str = ""
    currency: str = "USDC"
    decimals: int = 6
    network: str = "mainnet"
    rpc_url: str = ""
    secret_key: str = ""
    realm: str = ""
    html: bool = False
    fee_payer_signer: Any = None
    store: Store | None = None
    rpc: Any = None  # solana.rpc.async_api.AsyncClient


class Mpp:
    """Server-side Solana charge handler.

    Follows the same logic as the Go server.go implementation.
    """

    def __init__(self, config: Config) -> None:
        if not config.recipient or not config.recipient.strip():
            raise PaymentError("recipient is required", code="invalid-config")

        import os

        secret_key = config.secret_key or os.environ.get(_SECRET_KEY_ENV_VAR, "")
        if not secret_key:
            raise PaymentError("missing secret key", code="invalid-config")

        self._secret_key = secret_key
        self._realm = config.realm or _DEFAULT_REALM
        self._recipient = config.recipient
        self._currency = config.currency or "USDC"
        self._decimals = config.decimals or 6
        from solana_mpp.protocol.solana import _canonical_network as _canonical_net

        self._network = _canonical_net(config.network or "mainnet")
        self._rpc_url = config.rpc_url or default_rpc_url(self._network)
        self._html = config.html
        self._fee_payer_signer = config.fee_payer_signer
        if config.store is None:
            # L4 lock: a missing replay store is a server misconfiguration.
            # Silently falling back to MemoryStore() used to leave a window
            # where a credential could replay after restart. Mirrors the
            # required-explicit-store contract on Ruby and PHP after #96 / #102.
            raise PaymentError(
                "replay store is required; pass MemoryStore() or FileReplayStore(path) explicitly",
                code="invalid-config",
            )
        self._store: Store = config.store
        self._rpc = config.rpc

    @property
    def realm(self) -> str:
        return self._realm

    @property
    def rpc_url(self) -> str:
        return self._rpc_url

    @property
    def html_enabled(self) -> bool:
        return self._html

    def charge(self, amount: str) -> PaymentChallenge:
        """Create a charge challenge from a human-readable amount."""
        return self.charge_with_options(amount, ChargeOptions())

    def charge_with_options(self, amount: str, options: ChargeOptions) -> PaymentChallenge:
        """Create a charge challenge with optional fields."""
        base_units = parse_units(amount, self._decimals)

        details: dict[str, Any] = {"network": self._network}
        if not is_native_sol(self._currency):
            details["decimals"] = self._decimals
            if stablecoin_symbol(self._currency):
                details["tokenProgram"] = default_token_program_for_currency(self._currency, self._network)
        if options.fee_payer or self._fee_payer_signer is not None:
            details["feePayer"] = True
            if self._fee_payer_signer is not None:
                details["feePayerKey"] = str(self._fee_payer_signer.pubkey())
        if options.splits:
            details["splits"] = options.splits

        request_obj: dict[str, Any] = {
            "amount": base_units,
            "currency": self._currency,
            "recipient": self._recipient,
        }
        if options.description:
            request_obj["description"] = options.description
        if options.external_id:
            request_obj["externalId"] = options.external_id
        if details:
            request_obj["methodDetails"] = details

        request_b64 = encode_json(request_obj)

        from solana_mpp._expires import minutes

        default_expires = minutes(5)
        return PaymentChallenge.with_secret_key(
            secret_key=self._secret_key,
            realm=self._realm,
            method="solana",
            intent="charge",
            request=request_b64,
            expires=options.expires or default_expires,
            description=options.description,
        )

    async def verify_credential(self, credential: PaymentCredential) -> Receipt:
        """Verify either a transaction or signature credential payload.

        This is the simple API and is appropriate for servers that only gate a
        single route. Servers that gate multiple routes at different prices on
        the same secret key MUST use ``verify_credential_with_expected`` so the
        route's expected amount is compared to the credential's claimed amount;
        otherwise a credential issued for a cheaper route can be replayed at
        an expensive one.

        Even on the simple API, a Tier-2 pinned-field check enforces that the
        credential's method/intent/realm/currency/recipient match this Mpp's
        configuration, so cross-route replay across instances with different
        recipients/currencies is blocked.
        """
        request, details, payload = self._verify_challenge_and_decode(credential)
        return await self._verify_payload(credential, request, details, payload)

    async def verify_credential_with_expected(
        self,
        credential: PaymentCredential,
        expected: ChargeRequest,
    ) -> Receipt:
        """Verify a credential against the route's expected charge request.

        The amount, currency, and recipient on the credential's claimed
        challenge must match ``expected``. Settlement (transaction broadcast,
        on-chain checks) then runs against ``expected`` — not the credential's
        claims — so a credential built for a different route's request cannot
        succeed even if its other fields line up.
        """
        cred_request, _details, payload = self._verify_challenge_and_decode(credential)

        if cred_request.amount != expected.amount:
            raise PaymentError(
                f"amount mismatch: credential has {cred_request.amount} but endpoint expects {expected.amount}",
                code="amount-mismatch",
            )
        if cred_request.currency != expected.currency:
            raise PaymentError(
                f"currency mismatch: credential has {cred_request.currency} but endpoint expects {expected.currency}",
                code="currency-mismatch",
            )
        if cred_request.recipient != expected.recipient:
            raise PaymentError(
                "recipient mismatch: credential was issued for a different recipient",
                code="recipient-mismatch",
            )

        expected_details = MethodDetails()
        if expected.method_details:
            expected_details = MethodDetails.from_dict(expected.method_details)

        return await self._verify_payload(credential, expected, expected_details, payload)

    def _verify_challenge_and_decode(
        self, credential: PaymentCredential
    ) -> tuple[ChargeRequest, MethodDetails, CredentialPayload]:
        """Run Tier-1 (HMAC + expiry) and Tier-2 (pinned-field) checks.

        Returns the credential-decoded request, parsed method details, and the
        credential payload for downstream settlement.
        """
        challenge = PaymentChallenge(
            id=credential.challenge.id,
            realm=credential.challenge.realm,
            method=credential.challenge.method,
            intent=credential.challenge.intent,
            request=credential.challenge.request,
            expires=credential.challenge.expires,
            digest=credential.challenge.digest,
            opaque=credential.challenge.opaque,
        )

        if not challenge.verify(self._secret_key):
            raise ChallengeMismatchError()

        if challenge.is_expired():
            raise ChallengeExpiredError(f"challenge expired at {challenge.expires}")

        request = ChargeRequest.from_dict(challenge.decode_request())

        # Tier-2: pinned-field backstop. Even if the simple verify_credential
        # path is used, fields that are fixed at Mpp construction time must
        # match the credential.
        self._verify_pinned_fields(credential, request)

        details = MethodDetails()
        if request.method_details:
            details = MethodDetails.from_dict(request.method_details)

        payload = CredentialPayload.from_dict(credential.payload)
        return request, details, payload

    def _verify_pinned_fields(self, credential: PaymentCredential, request: ChargeRequest) -> None:
        # L6 lock: pinned-field mismatches are route mismatches, NOT HMAC
        # verification failures. A validly signed credential for a different
        # route or with a tampered echoed field reaches this path. Emitting
        # ``challenge_route_mismatch`` lets clients distinguish a bad HMAC
        # (``challenge_verification_failed``) from a signed credential
        # replayed against the wrong endpoint.
        method_name = "solana"
        if credential.challenge.method != method_name:
            raise PaymentError(
                f"credential method '{credential.challenge.method}' does not match this server "
                f"(expected '{method_name}')",
                code="method-mismatch",
            )
        # IntentName equivalent: case-insensitive "charge" comparison.
        if credential.challenge.intent.lower() != "charge":
            raise PaymentError(
                f"credential intent '{credential.challenge.intent}' is not a charge",
                code="intent-mismatch",
            )
        # The HMAC ID is computed using the server's own realm (not the echoed
        # one), so a tampered echoed realm passes HMAC unless re-signed. Pin it.
        if credential.challenge.realm != self._realm:
            raise PaymentError(
                f"credential realm '{credential.challenge.realm}' does not match this server "
                f"(expected '{self._realm}')",
                code="realm-mismatch",
            )
        if request.currency != self._currency:
            raise PaymentError(
                f"credential currency '{request.currency}' does not match this server (expected '{self._currency}')",
                code="currency-mismatch",
            )
        if request.recipient != self._recipient:
            raise PaymentError(
                "credential recipient does not match this server",
                code="recipient-mismatch",
            )

    async def _verify_payload(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        if payload.type == "transaction":
            return await self._verify_transaction(credential, request, details, payload)
        elif payload.type == "signature":
            if details.fee_payer:
                raise PaymentError(
                    'type="signature" credentials cannot be used with fee sponsorship',
                    code="invalid-payload-type",
                )
            return await self._verify_signature(credential, request, details, payload)
        else:
            raise PaymentError("missing or invalid payload type", code="invalid-payload-type")

    async def _verify_transaction(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        """Verify a pull-mode transaction credential."""
        if not payload.transaction:
            raise PaymentError("missing transaction data in credential payload", code="missing-transaction")
        if self._rpc is None:
            raise PaymentError("rpc client is required for transaction verification", code="invalid-config")
        if details.fee_payer and self._fee_payer_signer is None:
            raise PaymentError(
                "challenge advertises feePayer=true but server has no fee payer configured",
                code="invalid-config",
            )

        # Reject up-front if the client signed against the wrong network
        # (e.g. mainnet keypair pointed at a sandbox-configured server, or
        # vice versa). Cheaper and clearer than letting the broadcast fail.
        # Done here in the entry path so it runs even while the rest of the
        # pipeline below is still a stub.
        try:
            blockhash_b58 = _extract_recent_blockhash(payload.transaction)
        except Exception as exc:  # noqa: BLE001 — propagate decode failures as invalid payload
            raise PaymentError(
                f"could not decode transaction to read blockhash: {exc}",
                code="invalid-payload-type",
            ) from exc
        check_network_blockhash(self._network, blockhash_b58)
        _verify_local_transaction_intent(payload.transaction, request, details)

        # If the challenge advertises a server-side fee payer, co-sign the
        # client's transaction now (after pre-broadcast verification, before
        # broadcast). Mirrors rust/src/server/charge.rs verify_pull cosign
        # step. The fee payer signature occupies the slot for the fee-payer
        # account in the wire transaction.
        signed_b64 = payload.transaction
        if details.fee_payer:
            signed_b64 = _co_sign_with_fee_payer(payload.transaction, self._fee_payer_signer)

        # L8 lock: broadcast first, then consume_signature, then await
        # confirmation. The previous order (consume → broadcast → await,
        # with a rollback in the except block) had a fatal flaw: a
        # confirmation timeout after a successful broadcast triggered the
        # rollback path which DELETED the consume marker, so a retry of the
        # same credential could re-broadcast the same signed transaction
        # and re-issue a receipt for it. Mirrors the canonical L8 order
        # documented in lua/mpp/server/charge_handler.lua and the fix that
        # landed on Ruby + PHP + Rust in PR #96 / #102. This is the same
        # confirmation-timeout double-pay window Ludo found on the Rust
        # spine; closing it here brings Python into parity.
        from solders.signature import Signature

        raw_tx = base64.b64decode(signed_b64)
        send_resp = await self._rpc.send_raw_transaction(raw_tx)
        signature = str(_rpc_value(send_resp))

        # CONSUME the signature now that we know it has been accepted by the
        # cluster. Keying by signature (not by the credential bytes) means a
        # retry of the same credential always tries to insert the same key,
        # so the second attempt fails fast and the network is never asked
        # to settle the same transaction twice.
        consumed_key = _CONSUMED_PREFIX + signature
        inserted = await self._store.put_if_absent(consumed_key, True)
        if not inserted:
            raise ReplayError()

        # AWAIT confirmation. A timeout here MUST NOT roll back the consume:
        # the signature is on the wire and may finalize asynchronously.
        sig = Signature.from_string(signature)
        status_resp = await self._rpc.confirm_transaction(sig)
        if not _status_ok(status_resp):
            raise PaymentError("transaction not confirmed", code="transaction-not-found")

        tx_resp = await self._rpc.get_transaction(sig, encoding="jsonParsed", max_supported_transaction_version=0)
        tx = _transaction_dict(tx_resp)
        if tx is None:
            raise PaymentError("transaction not found or not yet confirmed", code="transaction-not-found")
        self._verify_confirmed_transaction(tx, request, details)
        return Receipt.success(
            method="solana",
            reference=signature,
            challenge_id=credential.challenge.id,
            external_id=request.external_id,
        )

    async def _verify_signature(
        self,
        credential: PaymentCredential,
        request: ChargeRequest,
        details: MethodDetails,
        payload: CredentialPayload,
    ) -> Receipt:
        """Verify a push-mode signature credential."""
        if not payload.signature:
            raise PaymentError("missing signature in credential payload", code="missing-signature")
        if self._rpc is None:
            raise PaymentError("rpc client is required for signature verification", code="invalid-config")

        # L8 push-mode lock: fetch the on-chain transaction and verify its
        # shape BEFORE consuming the signature. If the client lied about the
        # signature (or sent a signature that does not match the route), we
        # do not want a permanent replay-store entry for it. Only after the
        # on-chain shape is known to be correct do we mark the signature
        # consumed. Mirrors lua/mpp/server/charge_handler.lua push-mode
        # steps 2-4 and the cross-SDK lock from PR #96 / #102.
        from solders.signature import Signature

        sig = Signature.from_string(payload.signature)
        tx_resp = await self._rpc.get_transaction(sig, encoding="jsonParsed", max_supported_transaction_version=0)
        tx = _transaction_dict(tx_resp)
        if tx is None:
            raise PaymentError("transaction not found or not yet confirmed", code="transaction-not-found")
        self._verify_confirmed_transaction(tx, request, details)

        consumed_key = _CONSUMED_PREFIX + payload.signature
        inserted = await self._store.put_if_absent(consumed_key, True)
        if not inserted:
            raise ReplayError()

        return Receipt.success(
            method="solana",
            reference=payload.signature,
            challenge_id=credential.challenge.id,
            external_id=request.external_id,
        )

    def _verify_confirmed_transaction(self, tx: dict[str, Any], request: ChargeRequest, details: MethodDetails) -> None:
        meta = tx.get("meta") or {}
        if meta.get("err") is not None:
            raise PaymentError(f"transaction failed on-chain: {meta['err']}", code="transaction-failed")

        instructions = ((tx.get("transaction") or {}).get("message") or {}).get("instructions") or []
        if is_native_sol(request.currency):
            _verify_parsed_sol_transfers(instructions, request, details)
        else:
            _verify_parsed_spl_transfers(instructions, request, details)
        _verify_parsed_memo_instructions(instructions, request, details)
