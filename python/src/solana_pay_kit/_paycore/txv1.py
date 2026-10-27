"""Version-1 transaction codec (SIMD-0385) and the shared version policy.

solders 0.29 decodes legacy and version-0 wires but refuses the ``0x81``
prefix, so the kit carries its own version-1 codec. The classes here expose
the subset of the solders ``MessageV0`` / ``VersionedTransaction`` surface
the verifiers read (``header``, ``account_keys``, ``instructions``,
``recent_blockhash``, ``address_table_lookups``, ``signatures``), so one
verifier walks every version. :func:`decode_transaction` dispatches on the
first wire byte the way ``solana_transaction::VersionedTransaction`` does.

Wire layout (``solana_message::v1``)::

    0x81
    header            3 x u8   (required sigs, readonly signed, readonly unsigned)
    config mask       u32 LE   (0b11 priority fee, 0b100 compute unit limit,
                                0b1000 loaded accounts data size, 0b10000 heap)
    lifetime          32 bytes (recent blockhash)
    num_instructions  u8
    num_addresses     u8
    addresses         32 bytes each
    config values     u64 priority fee, then u32 each, in mask-bit order
    instruction heads (u8 program index, u8 num accounts, u16 LE data len) each
    instruction bodies (account indexes, data) each
    signatures        64 bytes x num_required_signatures, no length prefix

The policy helpers mirror ``rust/crates/kit/src/core/tx/{version,policy,
budget,build}.rs``.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from solders.hash import Hash
from solders.instruction import CompiledInstruction, Instruction
from solders.message import Message, MessageHeader
from solders.pubkey import Pubkey
from solders.signature import Signature

V1_PREFIX = 0x81
MESSAGE_VERSION_PREFIX = 0x80

#: Version-1 wire limits (``solana_message::v1``).
V1_MAX_TRANSACTION_SIZE = 4096
V1_MAX_ADDRESSES = 64
V1_MAX_INSTRUCTIONS = 64
V1_MAX_SIGNATURES = 12
#: Legacy / version-0 packet limit (``solana_packet::PACKET_DATA_SIZE``).
PACKET_DATA_SIZE = 1232
MAX_TX_ACCOUNT_LOCKS = 64

_MASK_PRIORITY_FEE = 0b11
_MASK_COMPUTE_UNIT_LIMIT = 0b100
_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000
_MASK_HEAP_SIZE = 0b10000
_MASK_KNOWN = _MASK_PRIORITY_FEE | _MASK_COMPUTE_UNIT_LIMIT | _MASK_LOADED_ACCOUNTS_DATA_SIZE | _MASK_HEAP_SIZE

COMPUTE_BUDGET_PROGRAM = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
SET_UNIT_LIMIT_TAG = 2
SET_UNIT_PRICE_TAG = 3
SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT_TAG = 4
MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024
#: Sponsored priority-fee ceiling in lamports (``MAX_SPONSORED_PRIORITY_FEE_LAMPORTS``).
MAX_SPONSORED_PRIORITY_FEE_LAMPORTS = 2_000

#: The accepted set when nothing is advertised.
DEFAULT_ACCEPTED_VERSIONS: tuple[int, ...] = (0,)


class TransactionVersionError(ValueError):
    """A transaction or advertisement the version policy refuses."""


@dataclass(frozen=True)
class TransactionConfig:
    """The version-1 header compute budget (``v1::TransactionConfig``)."""

    priority_fee: int | None = None
    compute_unit_limit: int | None = None
    loaded_accounts_data_size_limit: int | None = None
    heap_size: int | None = None

    def mask(self) -> int:
        mask = 0
        if self.priority_fee is not None:
            mask |= _MASK_PRIORITY_FEE
        if self.compute_unit_limit is not None:
            mask |= _MASK_COMPUTE_UNIT_LIMIT
        if self.loaded_accounts_data_size_limit is not None:
            mask |= _MASK_LOADED_ACCOUNTS_DATA_SIZE
        if self.heap_size is not None:
            mask |= _MASK_HEAP_SIZE
        return mask


@dataclass
class MessageV1:
    """A version-1 message with the read surface of ``solders.message.MessageV0``."""

    header: MessageHeader
    config: TransactionConfig
    recent_blockhash: Hash
    account_keys: list[Pubkey]
    instructions: list[CompiledInstruction]
    address_table_lookups: list[Any] = field(default_factory=list)

    version = 1

    @classmethod
    def try_compile(
        cls,
        payer: Pubkey,
        instructions: Sequence[Instruction],
        blockhash: Hash,
        config: TransactionConfig,
    ) -> MessageV1:
        """Compile like ``v1::Message::try_compile_with_config``.

        Key ordering is ``CompiledKeys::compile``, which the legacy compiler
        shares, so the legacy message supplies header, keys and indexes.
        """
        legacy = Message.new_with_blockhash(list(instructions), payer, blockhash)
        return cls(
            header=legacy.header,
            config=config,
            recent_blockhash=blockhash,
            account_keys=list(legacy.account_keys),
            instructions=list(legacy.instructions),
        )

    def __bytes__(self) -> bytes:
        out = bytearray([V1_PREFIX])
        header = self.header
        out += bytes(
            [
                header.num_required_signatures,
                header.num_readonly_signed_accounts,
                header.num_readonly_unsigned_accounts,
            ]
        )
        out += struct.pack("<I", self.config.mask())
        out += bytes(self.recent_blockhash)
        out += bytes([len(self.instructions), len(self.account_keys)])
        for key in self.account_keys:
            out += bytes(key)
        if self.config.priority_fee is not None:
            out += struct.pack("<Q", self.config.priority_fee)
        if self.config.compute_unit_limit is not None:
            out += struct.pack("<I", self.config.compute_unit_limit)
        if self.config.loaded_accounts_data_size_limit is not None:
            out += struct.pack("<I", self.config.loaded_accounts_data_size_limit)
        if self.config.heap_size is not None:
            out += struct.pack("<I", self.config.heap_size)
        for ix in self.instructions:
            out += bytes([ix.program_id_index, len(bytes(ix.accounts))])
            out += struct.pack("<H", len(bytes(ix.data)))
        for ix in self.instructions:
            out += bytes(ix.accounts)
            out += bytes(ix.data)
        return bytes(out)

    @classmethod
    def from_bytes_with_len(cls, raw: bytes) -> tuple[MessageV1, int]:
        """Decode a prefixed version-1 message; return it and the bytes read."""
        reader = _Reader(raw)
        if reader.byte() != V1_PREFIX:
            raise TransactionVersionError("not a version-1 message")
        header = MessageHeader(reader.byte(), reader.byte(), reader.byte())
        mask = reader.u32()
        if mask & ~_MASK_KNOWN or (mask & _MASK_PRIORITY_FEE) not in (0, _MASK_PRIORITY_FEE):
            raise TransactionVersionError("invalid transaction config mask")
        blockhash = Hash.from_bytes(reader.take(32))
        num_instructions = reader.byte()
        num_addresses = reader.byte()
        account_keys = [Pubkey.from_bytes(reader.take(32)) for _ in range(num_addresses)]
        config = TransactionConfig(
            priority_fee=reader.u64() if mask & _MASK_PRIORITY_FEE else None,
            compute_unit_limit=reader.u32() if mask & _MASK_COMPUTE_UNIT_LIMIT else None,
            loaded_accounts_data_size_limit=reader.u32() if mask & _MASK_LOADED_ACCOUNTS_DATA_SIZE else None,
            heap_size=reader.u32() if mask & _MASK_HEAP_SIZE else None,
        )
        heads = [(reader.byte(), reader.byte(), reader.u16()) for _ in range(num_instructions)]
        instructions = []
        for program_id_index, num_accounts, data_len in heads:
            accounts = reader.take(num_accounts)
            data = reader.take(data_len)
            instructions.append(CompiledInstruction(program_id_index, data, accounts))
        message = cls(
            header=header,
            config=config,
            recent_blockhash=blockhash,
            account_keys=account_keys,
            instructions=instructions,
        )
        return message, reader.offset

    @classmethod
    def from_bytes(cls, raw: bytes) -> MessageV1:
        message, consumed = cls.from_bytes_with_len(raw)
        if consumed != len(raw):
            raise TransactionVersionError("trailing bytes after the version-1 message")
        return message


@dataclass
class TransactionV1:
    """A version-1 transaction with the read surface of ``VersionedTransaction``."""

    message: MessageV1
    signatures: list[Signature]

    version = 1

    @classmethod
    def populate(cls, message: MessageV1, signatures: Sequence[Signature]) -> TransactionV1:
        return cls(message=message, signatures=list(signatures))

    def __bytes__(self) -> bytes:
        return bytes(self.message) + b"".join(bytes(sig) for sig in self.signatures)

    @classmethod
    def from_bytes(cls, raw: bytes) -> TransactionV1:
        message, offset = MessageV1.from_bytes_with_len(raw)
        count = message.header.num_required_signatures
        if len(raw) != offset + 64 * count:
            raise TransactionVersionError("version-1 transaction signature section does not match its required signers")
        signatures = [Signature.from_bytes(raw[offset + 64 * i : offset + 64 * (i + 1)]) for i in range(count)]
        return cls(message=message, signatures=signatures)


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def take(self, n: int) -> bytes:
        end = self.offset + n
        if end > len(self.raw):
            raise TransactionVersionError("truncated version-1 message")
        chunk = self.raw[self.offset : end]
        self.offset = end
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack("<H", self.take(2))[0])

    def u32(self) -> int:
        return int(struct.unpack("<I", self.take(4))[0])

    def u64(self) -> int:
        return int(struct.unpack("<Q", self.take(8))[0])


AnyTransaction = Any  # solders VersionedTransaction | TransactionV1


def decode_transaction(raw: bytes) -> AnyTransaction:
    """Decode a legacy, version-0 or version-1 wire transaction.

    A first byte with the high bit set is a version-1 prefix (legacy and v0
    wires open with the compact-u16 signature count, always below 0x80).
    """
    if raw and raw[0] & MESSAGE_VERSION_PREFIX:
        if raw[0] != V1_PREFIX:
            raise TransactionVersionError(f"unsupported transaction version prefix {raw[0]:#x}")
        return TransactionV1.from_bytes(raw)
    from solders.transaction import VersionedTransaction

    return VersionedTransaction.from_bytes(raw)


def is_v1(tx_or_message: Any) -> bool:
    return isinstance(tx_or_message, (TransactionV1, MessageV1))


def message_version(message: Any) -> int | str:
    """``1``, ``0`` or ``"legacy"`` for a decoded message."""
    if isinstance(message, MessageV1):
        return 1
    from solders.message import MessageV0

    return 0 if isinstance(message, MessageV0) else "legacy"


def policy_version(message: Any) -> int:
    """The policy version: legacy is policed as version 0 (``TxVersion::of``)."""
    return 1 if isinstance(message, MessageV1) else 0


def signed_message_bytes(message: Any) -> bytes:
    """The exact bytes the signatures cover, for every version."""
    if isinstance(message, MessageV1):
        return bytes(message)
    from solders.message import to_bytes_versioned  # type: ignore[import-untyped]

    return bytes(to_bytes_versioned(message))


def populate(message: Any, signatures: Sequence[Signature]) -> AnyTransaction:
    if isinstance(message, MessageV1):
        return TransactionV1.populate(message, signatures)
    from solders.transaction import VersionedTransaction

    return VersionedTransaction.populate(message, list(signatures))


# --- Advertisement ---------------------------------------------------------


def parse_transaction_versions(value: Any, *, field_name: str = "transactionVersions") -> list[int] | None:
    """Strictly parse an advertised ``transactionVersions`` list.

    ``None`` (absent) stays ``None``; otherwise every entry must be the JSON
    integer 0 or 1. ``"legacy"``, strings, booleans, other numbers and a
    non-array are refused (mpp-specs-txv1 / x402 §1.5).
    """
    if value is None:
        return None
    if not isinstance(value, list):
        raise TransactionVersionError(f"{field_name} must be an array of transaction versions")
    versions: list[int] = []
    for entry in value:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise TransactionVersionError(f"{field_name} entries must be the integers 0 or 1, got {entry!r}")
        if entry not in (0, 1):
            raise TransactionVersionError(f"unsupported transaction version {entry}")
        versions.append(entry)
    return versions


def accepted_versions(advertised: Sequence[int] | None) -> tuple[int, ...]:
    """The accepted set: ``[0]`` only when absent; present and empty accepts nothing."""
    if advertised is None:
        return DEFAULT_ACCEPTED_VERSIONS
    return tuple(advertised)


def negotiate(advertised: Sequence[int] | None, max_signable: int | None = None) -> int:
    """The highest advertised version the signer can sign (``policy::negotiate``)."""
    accepted = accepted_versions(advertised)
    if not accepted:
        raise TransactionVersionError(
            "the counterparty advertises no transaction version (transactionVersions is empty)"
        )
    candidates = [v for v in accepted if max_signable is None or v <= max_signable]
    if not candidates:
        listed = ", ".join(str(v) for v in accepted)
        raise TransactionVersionError(
            f"the server accepts transaction versions [{listed}] but the signer signs up to version {max_signable}"
        )
    return max(candidates)


# --- Envelope --------------------------------------------------------------


def _accepted_text(accepted: Sequence[int]) -> str:
    return ", ".join(str(v) for v in accepted)


def check_limits(tx: AnyTransaction, version: int) -> int:
    """Per-version size, account, instruction and signature limits."""
    size = len(bytes(tx))
    message = tx.message
    max_bytes = V1_MAX_TRANSACTION_SIZE if version == 1 else PACKET_DATA_SIZE
    if size > max_bytes:
        raise TransactionVersionError(f"version {version} transaction is {size} bytes, over the {max_bytes}-byte limit")
    max_accounts = V1_MAX_ADDRESSES if version == 1 else MAX_TX_ACCOUNT_LOCKS
    accounts = len(message.account_keys)
    if accounts > max_accounts:
        raise TransactionVersionError(
            f"version {version} transaction has {accounts} accounts, over the limit of {max_accounts}"
        )
    if version == 1:
        count = len(message.instructions)
        if count > V1_MAX_INSTRUCTIONS:
            raise TransactionVersionError(
                f"version 1 transaction has {count} instructions, over the limit of {V1_MAX_INSTRUCTIONS}"
            )
        signers = message.header.num_required_signatures
        if signers > V1_MAX_SIGNATURES:
            raise TransactionVersionError(
                f"version 1 transaction requires {signers} signatures, over the limit of {V1_MAX_SIGNATURES}"
            )
    return size


def require_static_accounts(message: Any) -> None:
    if getattr(message, "address_table_lookups", None):
        raise TransactionVersionError("transactions with address lookup tables are not supported")


def check_envelope(tx: AnyTransaction, accepted: Sequence[int], *, allow_legacy: bool = True) -> int:
    """Admit a decoded transaction against the accepted set (``policy::check_envelope``).

    ``allow_legacy=False`` is ``check_envelope_without_legacy``: MPP servers
    refuse an unprefixed message; x402 sponsors police it as version 0.
    """
    if not allow_legacy and message_version(tx.message) == "legacy":
        raise TransactionVersionError(
            f"legacy transaction version is not accepted; accepted versions: {_accepted_text(accepted)}"
        )
    version = policy_version(tx.message)
    if version not in accepted:
        raise TransactionVersionError(
            f"transaction version {version} is not accepted; accepted versions: {_accepted_text(accepted)}"
        )
    require_static_accounts(tx.message)
    check_limits(tx, version)
    return version


# --- Compute budget --------------------------------------------------------


@dataclass
class DeclaredBudget:
    unit_limit: int | None = None
    unit_price_micro_lamports: int | None = None
    loaded_accounts_data_size_limit: int | None = None
    instruction_indexes: list[int] = field(default_factory=list)


def _is_compute_budget(message: Any, ix: Any) -> bool:
    keys = message.account_keys
    index = int(ix.program_id_index)
    return index < len(keys) and keys[index] == COMPUTE_BUDGET_PROGRAM


def declared_budget(message: Any) -> DeclaredBudget:
    """The budget a message declares (``DeclaredBudget::of``)."""
    if isinstance(message, MessageV1):
        if any(_is_compute_budget(message, ix) for ix in message.instructions):
            raise TransactionVersionError("version 1 transactions must not contain ComputeBudget instructions")
        limit = message.config.compute_unit_limit
        if limit is None:
            raise TransactionVersionError("version 1 transaction config must set computeUnitLimit")
        fee = message.config.priority_fee
        price = None
        if fee is not None:
            price = (1 << 64) - 1 if limit == 0 else min(-(-fee * 1_000_000 // limit), (1 << 64) - 1)
        return DeclaredBudget(
            unit_limit=limit,
            unit_price_micro_lamports=price,
            loaded_accounts_data_size_limit=message.config.loaded_accounts_data_size_limit,
        )
    budget = DeclaredBudget()
    for index, ix in enumerate(message.instructions):
        if not _is_compute_budget(message, ix):
            continue
        data = bytes(ix.data)
        tag = data[0] if data else None
        if tag == SET_UNIT_LIMIT_TAG and len(data) == 5:
            if budget.unit_limit is not None:
                raise TransactionVersionError("duplicate SetComputeUnitLimit instruction")
            budget.unit_limit = int.from_bytes(data[1:5], "little")
        elif tag == SET_UNIT_PRICE_TAG and len(data) == 9:
            if budget.unit_price_micro_lamports is not None:
                raise TransactionVersionError("duplicate SetComputeUnitPrice instruction")
            budget.unit_price_micro_lamports = int.from_bytes(data[1:9], "little")
        elif tag == SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT_TAG and len(data) == 5:
            if budget.loaded_accounts_data_size_limit is not None:
                raise TransactionVersionError("duplicate SetLoadedAccountsDataSizeLimit instruction")
            budget.loaded_accounts_data_size_limit = int.from_bytes(data[1:5], "little")
        else:
            raise TransactionVersionError("unsupported ComputeBudget instruction")
        budget.instruction_indexes.append(index)
    return budget


def runtime_default_unit_limit(num_instructions: int) -> int:
    return min(200_000 * num_instructions, 1_400_000)


def priority_fee_lamports(unit_limit: int, unit_price_micro_lamports: int) -> int:
    return min(-(-unit_limit * unit_price_micro_lamports // 1_000_000), (1 << 64) - 1)


def check_v1_budget_caps(
    message: Any,
    max_unit_limit: int,
    max_unit_price_micro_lamports: int,
    *,
    loaded_rule: str = "maximum",
) -> DeclaredBudget | None:
    """Version-1 header budget caps (``check_v1_budget_caps_with``).

    ``loaded_rule`` is ``"maximum"`` (the limit must be exactly 64 MiB) or
    ``"present"`` (nonzero and at most 64 MiB).
    """
    if not isinstance(message, MessageV1):
        return None
    declared = declared_budget(message)
    limit = declared.unit_limit
    if limit is not None:
        if limit == 0:
            raise TransactionVersionError("compute unit limit must be positive")
        if limit > max_unit_limit:
            raise TransactionVersionError(f"compute unit limit {limit} exceeds maximum {max_unit_limit}")
    price = declared.unit_price_micro_lamports
    if price is not None and price > max_unit_price_micro_lamports:
        raise TransactionVersionError(f"compute unit price {price} exceeds maximum {max_unit_price_micro_lamports}")
    loaded = declared.loaded_accounts_data_size_limit
    if loaded_rule == "maximum":
        if loaded != MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES:
            raise TransactionVersionError(
                f"version 1 loaded accounts data size limit must be {MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES}"
            )
    elif loaded is None or loaded <= 0 or loaded > MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES:
        raise TransactionVersionError(
            "version 1 loaded accounts data size limit must be present, nonzero and at most "
            f"{MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES}"
        )
    return declared


def check_v0_budget_caps(
    message: Any,
    max_unit_limit: int,
    max_unit_price_micro_lamports: int,
) -> DeclaredBudget | None:
    """Version-0 ComputeBudget caps (``policy::check_v0_budget_caps``).

    Legacy is policed as version 0. Returns ``None`` for a version-1 message.
    """
    if isinstance(message, MessageV1):
        return None
    declared = declared_budget(message)
    instructions = list(message.instructions)
    if any(len(bytes(instructions[index].accounts)) for index in declared.instruction_indexes):
        raise TransactionVersionError("ComputeBudget instructions must not have accounts")
    if declared.loaded_accounts_data_size_limit is not None:
        raise TransactionVersionError("SetLoadedAccountsDataSizeLimit is not supported")
    limit = declared.unit_limit
    if limit is not None:
        if limit == 0:
            raise TransactionVersionError("compute unit limit must be positive")
        if limit > max_unit_limit:
            raise TransactionVersionError(f"compute unit limit {limit} exceeds maximum {max_unit_limit}")
    price = declared.unit_price_micro_lamports
    if price is not None:
        if price > max_unit_price_micro_lamports:
            raise TransactionVersionError(f"compute unit price {price} exceeds maximum {max_unit_price_micro_lamports}")
        if price > 0 and limit is None:
            implicit = runtime_default_unit_limit(len(instructions) - len(declared.instruction_indexes))
            if implicit > max_unit_limit:
                raise TransactionVersionError(
                    f"implicit compute unit limit {implicit} exceeds maximum {max_unit_limit}; "
                    "declare SetComputeUnitLimit"
                )
    return declared


def require_budget_prefix(message: Any, declared: DeclaredBudget) -> None:
    """ComputeBudget instructions lead the message, the unit limit before the
    unit price (``policy::require_budget_prefix``)."""
    if any(position != index for position, index in enumerate(declared.instruction_indexes)):
        raise TransactionVersionError("ComputeBudget instructions must lead the transaction")
    if declared.unit_limit is not None and declared.unit_price_micro_lamports is not None:
        first = list(message.instructions)[0]
        data = bytes(first.data)
        if not (_is_compute_budget(message, first) and len(data) == 5 and data[0] == SET_UNIT_LIMIT_TAG):
            raise TransactionVersionError("SetComputeUnitLimit must precede SetComputeUnitPrice")


def reject_v1_heap_request(message: Any) -> None:
    if isinstance(message, MessageV1) and message.config.heap_size is not None:
        raise TransactionVersionError("version 1 transaction config must not request a heap size")


def priority_fee_of(message: Any) -> int:
    """The priority fee in lamports a message pays, for every version."""
    if isinstance(message, MessageV1):
        return message.config.priority_fee or 0
    declared = declared_budget(message)
    price = declared.unit_price_micro_lamports or 0
    limit = declared.unit_limit
    if limit is None:
        limit = runtime_default_unit_limit(len(message.instructions) - len(declared.instruction_indexes))
    return priority_fee_lamports(limit, price)


def check_priority_fee(message: Any, max_lamports: int) -> int:
    fee = priority_fee_of(message)
    if fee > max_lamports:
        raise TransactionVersionError(f"priority fee {fee} lamports exceeds the sponsored maximum {max_lamports}")
    return fee


def v1_config(unit_limit: int, unit_price_micro_lamports: int) -> TransactionConfig:
    """``ComputeBudget::v1_config``: the header budget for a v0-shaped budget."""
    return TransactionConfig(
        priority_fee=priority_fee_lamports(unit_limit, unit_price_micro_lamports),
        compute_unit_limit=unit_limit,
        loaded_accounts_data_size_limit=MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    )
