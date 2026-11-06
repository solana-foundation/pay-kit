"""Merchant-facing credit-provider policy, independent of payment protocols.

Mirrors ``rust/crates/kit/src/core/credit_provider`` (pay-kit PRs #411/#414)
and the TypeScript port in ``typescript/packages/mpp/src/shared``: a merchant
only ever selects a provider *name*. Program IDs, entrypoints, seeds and hook
accounts are pinned per deployment and are never caller-supplied. Only devnet
has a reviewed Musebook deployment; every other network is unavailable, and
every check in this module fails closed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Literal

from solders.account_meta import AccountMeta  # type: ignore[import-untyped]
from solders.instruction import Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.paymentchannels import (
    Distribution,
    distribution_hash,
    find_associated_token_address,
)
from solana_pay_kit._paycore.solana import TOKEN_PROGRAM

#: The classic SPL Token program the provider custodies under.
TOKEN_PROGRAM_ID = Pubkey.from_string(TOKEN_PROGRAM)

__all__ = [
    "CreditProvider",
    "CreditProviderError",
    "HookAccount",
    "HookDescriptor",
    "ChannelHooks",
    "CreditDeployment",
    "MUSEBOOK_ENTRYPOINT",
    "MUSEBOOK_LEDGER_SEED",
    "MUSEBOOK_CONFIG_SEED",
    "MUSEBOOK_COMPUTE_UNIT_LIMIT",
    "SPL_TOKEN_PROGRAM_ID",
    "MAX_AUTHORIZATION_SLOTS",
    "MUSEBOOK_DEVNET_PROGRAM_ID",
    "PAYMENT_CHANNELS_V2_PROGRAM_ID",
    "MUSEBOOK_DEVNET_DEPLOYMENT",
    "deployment_for_network",
    "resolve_deployment",
    "devnet_with_program",
    "validate_credit_providers",
    "validate_credit_providers_for_network",
    "ledger_address",
    "config_address",
    "hooks_for_deployment",
    "is_credit_channel",
    "encode_authorization",
    "authorization_instructions",
]

#: A recognized credit provider a merchant wants to accept alongside currency.
CreditProvider = Literal["coinflow", "musebook"]

#: Callback entrypoint discriminator checked by the provider program.
MUSEBOOK_ENTRYPOINT = b"musebook"
MUSEBOOK_LEDGER_SEED = b"musebook-credit"
MUSEBOOK_CONFIG_SEED = b"musebook-config"
#: Hooked channel instructions run the provider callback inside the channel
#: instruction, so credit opens/top-ups always request this explicit limit.
MUSEBOOK_COMPUTE_UNIT_LIMIT = 400_000
#: The provider custodies classic SPL Token mints only.
SPL_TOKEN_PROGRAM_ID = str(TOKEN_PROGRAM_ID)
#: Longest authorization window (slots past ``open_slot``) an issuer co-signs.
MAX_AUTHORIZATION_SLOTS = 9_000

#: Reviewed Musebook provider program ID on devnet (Squads 2-of-3 governed).
MUSEBOOK_DEVNET_PROGRAM_ID = "97F68uhs5fmvddJxH1LrKytbBXrhx6ZBZwuZAdUdP7QA"
#: Payment-channels program whose callbacks the provider accepts: the V2
#: hooks deployment. This is *not* the V1 program the generated Python
#: client targets (``paymentchannels.PROGRAM_ID``); credit channels live
#: on this deployment only.
PAYMENT_CHANNELS_V2_PROGRAM_ID = "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ"


class CreditProviderError(ValueError):
    """Raised when a selected credit provider cannot be used. Fail-closed."""

    def __init__(self, provider: str, message: str) -> None:
        super().__init__(message)
        self.provider = provider


def _unavailable(provider: str) -> CreditProviderError:
    return CreditProviderError(
        provider,
        f"credit provider {provider} is unavailable: no reviewed issuer integration is registered",
    )


@dataclass(frozen=True)
class HookAccount:
    """One hook account, in the exact order the provider program expects."""

    address: str
    writable: bool

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "writable": self.writable}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HookAccount:
        return cls(address=str(data["address"]), writable=bool(data["writable"]))


@dataclass(frozen=True)
class HookDescriptor:
    """One lifecycle callback descriptor.

    ``entrypoint`` and ``static_data`` are byte strings in Python; on the
    wire they serialize as JSON number arrays, exactly as the Rust
    ``HookDescriptor`` serde representation carries them.
    """

    program_id: str
    entrypoint: bytes
    accounts: list[HookAccount] = field(default_factory=list)
    static_data: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        return {
            "programId": self.program_id,
            "entrypoint": list(self.entrypoint),
            "accounts": [account.to_dict() for account in self.accounts],
            "staticData": list(self.static_data),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HookDescriptor:
        return cls(
            program_id=str(data["programId"]),
            entrypoint=bytes(int(b) for b in data.get("entrypoint", [])),
            accounts=[HookAccount.from_dict(a) for a in data.get("accounts", [])],
            static_data=bytes(int(b) for b in data.get("staticData", [])),
        )


@dataclass(frozen=True)
class ChannelHooks:
    """The four V2 lifecycle hook slots; ``None`` slots are unset."""

    pre_fund: HookDescriptor | None = None
    post_fund: HookDescriptor | None = None
    pre_distribute: HookDescriptor | None = None
    post_distribute: HookDescriptor | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.pre_fund is not None:
            data["preFund"] = self.pre_fund.to_dict()
        if self.post_fund is not None:
            data["postFund"] = self.post_fund.to_dict()
        if self.pre_distribute is not None:
            data["preDistribute"] = self.pre_distribute.to_dict()
        if self.post_distribute is not None:
            data["postDistribute"] = self.post_distribute.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChannelHooks:
        def slot(name: str) -> HookDescriptor | None:
            raw = data.get(name)
            return HookDescriptor.from_dict(raw) if raw is not None else None

        return cls(
            pre_fund=slot("preFund"),
            post_fund=slot("postFund"),
            pre_distribute=slot("preDistribute"),
            post_distribute=slot("postDistribute"),
        )


@dataclass(frozen=True)
class CreditDeployment:
    """A reviewed, pinned deployment of the provider and the channel program it trusts."""

    cluster: str
    program_id: str
    channel_program_id: str


#: Devnet: provider ``97F68uhs…`` trusting the V2-hooks channel deployment ``CHNLxBt…``.
MUSEBOOK_DEVNET_DEPLOYMENT = CreditDeployment(
    cluster="devnet",
    program_id=MUSEBOOK_DEVNET_PROGRAM_ID,
    channel_program_id=PAYMENT_CHANNELS_V2_PROGRAM_ID,
)


def _cluster_of(network: str) -> str:
    return network[len("solana:") :] if network.startswith("solana:") else network


def deployment_for_network(network: str) -> CreditDeployment | None:
    """Resolve the pinned deployment for a network name or ``solana:<cluster>``.

    Unknown or undeployed networks yield ``None``. Mirrors Rust
    ``musebook::deployment`` exactly: the ``solana:`` prefix is stripped, the
    cluster match is exact and case-sensitive.
    """
    return MUSEBOOK_DEVNET_DEPLOYMENT if _cluster_of(network) == "devnet" else None


def resolve_deployment(network: str, program: str | None = None) -> CreditDeployment | None:
    """Resolve the deployment for ``network``, optionally replaced by an
    explicit ``program`` override. The override is honored on devnet only
    (the channel program stays pinned); on any other network it makes the
    provider unavailable. Mirrors Rust ``musebook::resolve``.
    """
    if program is None:
        return deployment_for_network(network)
    if program == MUSEBOOK_DEVNET_PROGRAM_ID:
        return deployment_for_network(network)
    if _cluster_of(network) != "devnet":
        return None
    try:
        Pubkey.from_string(program)
    except (ValueError, TypeError):
        return None
    return CreditDeployment(
        cluster="devnet",
        program_id=program,
        channel_program_id=PAYMENT_CHANNELS_V2_PROGRAM_ID,
    )


def devnet_with_program(program_id: str) -> CreditDeployment | None:
    """A devnet-only deployment of the same provider code at a different
    program ID (e.g. a throwaway instance whose upgrade authority is the
    operator's own devnet key). Never available on any other cluster; the
    channel program stays pinned. Off unless a caller explicitly asks.
    """
    try:
        Pubkey.from_string(program_id)
    except (ValueError, TypeError):
        return None
    return CreditDeployment(
        cluster="devnet",
        program_id=program_id,
        channel_program_id=PAYMENT_CHANNELS_V2_PROGRAM_ID,
    )


def validate_credit_providers(providers: list[CreditProvider]) -> None:
    """Validate merchant credit-provider policy without a network context:
    every recognized provider is unavailable, because availability is a
    property of a reviewed deployment on a specific network. Mirrors Rust
    ``validate_credit_providers``.
    """
    for provider in providers:
        raise _unavailable(provider)


def validate_credit_providers_for_network(providers: list[CreditProvider], network: str) -> None:
    """Validate merchant credit-provider policy for a known network.
    Musebook is available exactly where a deployment is pinned (devnet
    today); Coinflow stays unavailable everywhere. Mirrors Rust
    ``validate_credit_providers_for_network``.
    """
    for provider in providers:
        if provider == "musebook" and deployment_for_network(network) is not None:
            continue
        raise _unavailable(provider)


def ledger_address(deployment: CreditDeployment, owner: Pubkey, mint: Pubkey) -> Pubkey:
    """The provider ledger PDA for ``owner``'s credits in ``mint``."""
    derived, _ = Pubkey.find_program_address(
        [MUSEBOOK_LEDGER_SEED, bytes(owner), bytes(mint)],
        Pubkey.from_string(deployment.program_id),
    )
    return derived


def config_address(deployment: CreditDeployment) -> Pubkey:
    """The provider config PDA (a hook-adjacent account, never a hook account)."""
    derived, _ = Pubkey.find_program_address(
        [MUSEBOOK_CONFIG_SEED],
        Pubkey.from_string(deployment.program_id),
    )
    return derived


def _ata(owner: Pubkey, mint: Pubkey) -> Pubkey:
    derived, _ = find_associated_token_address(owner, mint, TOKEN_PROGRAM_ID)
    return derived


def hooks_for_deployment(deployment: CreditDeployment, owner: Pubkey, mint: Pubkey) -> ChannelHooks:
    """The exact, immutable hook policy for ``owner``'s credits in ``mint``:
    the same descriptor in the ``pre_fund`` and ``post_distribute`` slots,
    accounts ``[ledger (w), ledger vault ATA (w), owner ATA (w), SPL Token
    (ro)]``, entrypoint ``musebook``, no static data.
    """
    ledger = ledger_address(deployment, owner, mint)
    descriptor = HookDescriptor(
        program_id=deployment.program_id,
        entrypoint=MUSEBOOK_ENTRYPOINT,
        accounts=[
            HookAccount(address=str(ledger), writable=True),
            HookAccount(address=str(_ata(ledger, mint)), writable=True),
            HookAccount(address=str(_ata(owner, mint)), writable=True),
            HookAccount(address=SPL_TOKEN_PROGRAM_ID, writable=False),
        ],
        static_data=b"",
    )
    return ChannelHooks(pre_fund=descriptor, post_distribute=descriptor)


def is_credit_channel(deployment: CreditDeployment, hooks: ChannelHooks, owner: Pubkey, mint: Pubkey) -> bool:
    """Detection: is this hook configuration exactly the Musebook
    credit-backed hooks for ``owner``/``mint`` on this deployment? Exact
    match only — a look-alike with a different program, entrypoint, slot
    set or account list is not. Mirrors Rust ``is_credit_channel``.
    """
    return hooks == hooks_for_deployment(deployment, owner, mint)


def encode_authorization(
    *,
    payee: Pubkey,
    authorized_signer: Pubkey,
    distribution_hash_bytes: bytes,
    salt: int,
    open_slot: int,
    cap: int,
    nonce: int,
    expires_at_slot: int,
) -> bytes:
    """Encode the provider ``Authorization`` body (fixed 136 bytes, tag excluded)."""
    if len(distribution_hash_bytes) != 32:
        raise ValueError("distribution_hash must be 32 bytes")
    return b"".join(
        [
            bytes(payee),
            bytes(authorized_signer),
            distribution_hash_bytes,
            struct.pack("<QQQQQ", salt, open_slot, cap, nonce, expires_at_slot),
        ]
    )


def authorization_instructions(
    deployment: CreditDeployment,
    *,
    owner: Pubkey,
    mint: Pubkey,
    issuer: Pubkey,
    payee: Pubkey,
    authorized_signer: Pubkey,
    recipients: list[Distribution],
    salt: int,
    open_slot: int,
    cap: int,
    nonce: int,
    expires_at_slot: int,
) -> list[Instruction]:
    """The two client-signed instructions that authorize a credit channel:
    SPL Token ``Approve`` of exactly ``cap`` to the provider ledger, then
    the provider ``authorize`` binding the channel's incarnation. The
    server's issuer co-signs the second instruction. Mirrors the Rust
    ``authorization_instructions`` account lists and data layouts.
    """
    ledger = ledger_address(deployment, owner, mint)
    config = config_address(deployment)
    owner_token_account = _ata(owner, mint)
    ledger_token_account = _ata(ledger, mint)
    authorization = encode_authorization(
        payee=payee,
        authorized_signer=authorized_signer,
        distribution_hash_bytes=distribution_hash(recipients),
        salt=salt,
        open_slot=open_slot,
        cap=cap,
        nonce=nonce,
        expires_at_slot=expires_at_slot,
    )
    approve = Instruction(
        TOKEN_PROGRAM_ID,
        bytes([4]) + struct.pack("<Q", cap),
        [
            AccountMeta(owner_token_account, is_signer=False, is_writable=True),
            AccountMeta(ledger, is_signer=False, is_writable=False),
            AccountMeta(owner, is_signer=True, is_writable=False),
        ],
    )
    authorize = Instruction(
        Pubkey.from_string(deployment.program_id),
        bytes([2]) + authorization,
        [
            AccountMeta(owner, is_signer=True, is_writable=False),
            AccountMeta(issuer, is_signer=True, is_writable=False),
            AccountMeta(ledger, is_signer=False, is_writable=True),
            AccountMeta(ledger_token_account, is_signer=False, is_writable=True),
            AccountMeta(owner_token_account, is_signer=False, is_writable=True),
            AccountMeta(TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
            AccountMeta(config, is_signer=False, is_writable=False),
        ],
    )
    return [approve, authorize]
