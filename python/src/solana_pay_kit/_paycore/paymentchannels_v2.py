"""V2 (hooked) payment-channel instruction transforms — a faithful port of
``rust/crates/kit/src/core/payment_channel/v2.rs`` (mirroring the TypeScript
``shared/payment-channels-v2.ts``).

Why this file exists: the Python payment-channels builders target the V1
channel program (``CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX``) and have
no hooked instruction builders, while credit channels live on the V2
deployment (``CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ``). A hooked
instruction is exactly the V1 instruction with (a) its discriminator byte
retagged, (b) for ``open``, the compact hook suffix appended to the data,
and (c) the callback accounts appended — the program signs only the
dedicated callback-authority PDAs.
"""

from __future__ import annotations

import hashlib

from solders.instruction import AccountMeta, Instruction  # type: ignore[import-untyped]
from solders.pubkey import Pubkey  # type: ignore[import-untyped]

from solana_pay_kit._paycore.credit_provider import (
    PAYMENT_CHANNELS_V2_PROGRAM_ID,
    ChannelHooks,
    HookDescriptor,
)

OPEN_WITH_HOOKS_DISCRIMINATOR = 10
TOP_UP_WITH_HOOKS_DISCRIMINATOR = 11
DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR = 12
WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR = 13

_HOOK_DESCRIPTOR_SIZE = 206
_MAX_HOOK_ACCOUNTS = 4
_MAX_STATIC_DATA = 32
_ZERO_ADDRESS = "11111111111111111111111111111111"


def _slots(hooks: ChannelHooks) -> list[HookDescriptor | None]:
    return [hooks.pre_fund, hooks.post_fund, hooks.pre_distribute, hooks.post_distribute]


def validate_hooks(hooks: ChannelHooks) -> None:
    """Mirror of Rust ``ChannelHooks::validate``."""
    for hook in _slots(hooks):
        if hook is None:
            continue
        if hook.program_id in (_ZERO_ADDRESS, PAYMENT_CHANNELS_V2_PROGRAM_ID):
            raise ValueError("payment-channel ABI: enabled hook has zero or self target program")
        if len(hook.accounts) > _MAX_HOOK_ACCOUNTS or len(hook.static_data) > _MAX_STATIC_DATA:
            raise ValueError("payment-channel ABI: hook exceeds account or static-data bounds")
        seen: set[str] = set()
        for account in hook.accounts:
            if account.address in seen or account.address == hook.program_id:
                raise ValueError("payment-channel ABI: duplicate or target-aliasing hook account")
            seen.add(account.address)


def encode_open_suffix(hooks: ChannelHooks) -> bytes:
    """Compact ``open`` suffix: per slot, an enabled byte then only used
    data/accounts."""
    validate_hooks(hooks)
    out = bytearray()
    for hook in _slots(hooks):
        out.append(1 if hook is not None else 0)
        if hook is None:
            continue
        out += bytes(Pubkey.from_string(hook.program_id))
        out += hook.entrypoint
        out.append(len(hook.accounts))
        out.append(len(hook.static_data))
        out += hook.static_data
        for account in hook.accounts:
            out += bytes(Pubkey.from_string(account.address))
            out.append(1 if account.writable else 0)
    return bytes(out)


def encode_fixed(hooks: ChannelHooks) -> bytes:
    """Canonical fixed representation (4 x 206 bytes); unused bytes are zero."""
    validate_hooks(hooks)
    out = bytearray(4 * _HOOK_DESCRIPTOR_SIZE)
    for index, hook in enumerate(_slots(hooks)):
        if hook is None:
            continue
        base = index * _HOOK_DESCRIPTOR_SIZE
        out[base : base + 32] = bytes(Pubkey.from_string(hook.program_id))
        out[base + 32 : base + 40] = hook.entrypoint
        out[base + 40] = len(hook.accounts)
        out[base + 41] = len(hook.static_data)
        out[base + 42 : base + 42 + len(hook.static_data)] = hook.static_data
        for account_index, account in enumerate(hook.accounts):
            offset = base + 74 + account_index * 33
            out[offset : offset + 32] = bytes(Pubkey.from_string(account.address))
            out[offset + 32] = 1 if account.writable else 0
    return bytes(out)


def config_hash(hooks: ChannelHooks) -> bytes:
    """``sha256(encode_fixed(hooks))`` — the hash stored in the channel account."""
    return hashlib.sha256(encode_fixed(hooks)).digest()


def find_callback_authority(
    channel: Pubkey,
    hash_bytes: bytes,
    phase: int,
    target: Pubkey,
    program_id: Pubkey | None = None,
) -> Pubkey:
    """Capability PDA: the program signs only this dedicated callback authority."""
    if phase > 3:
        raise ValueError("payment-channel ABI: invalid callback phase")
    program = program_id or Pubkey.from_string(PAYMENT_CHANNELS_V2_PROGRAM_ID)
    derived, _ = Pubkey.find_program_address(
        [b"channel_hook", bytes(channel), hash_bytes, bytes([phase]), bytes(target)],
        program,
    )
    return derived


def _appended_hook_accounts(
    channel: Pubkey,
    hooks: ChannelHooks,
    phases: list[int],
    program_id: Pubkey,
) -> list[AccountMeta]:
    """Callback accounts for ``phases``, appended in slot order: hook program
    (readonly), callback authority (readonly), then the hook's accounts.
    Additional callback accounts never acquire signer privileges."""
    digest = config_hash(hooks)
    slots = _slots(hooks)
    metas: list[AccountMeta] = []
    for phase in phases:
        hook = slots[phase]
        if hook is None:
            continue
        target = Pubkey.from_string(hook.program_id)
        authority = find_callback_authority(channel, digest, phase, target, program_id)
        metas.append(AccountMeta(target, is_signer=False, is_writable=False))
        metas.append(AccountMeta(authority, is_signer=False, is_writable=False))
        for account in hook.accounts:
            account_pubkey = Pubkey.from_string(account.address)
            if account_pubkey in (channel, authority):
                raise ValueError("payment-channel ABI: hook extra aliases channel or callback authority")
            metas.append(AccountMeta(account_pubkey, is_signer=False, is_writable=account.writable))
    return metas


def build_open_with_hooks(
    base: Instruction,
    hooks: ChannelHooks,
    channel: Pubkey,
    program_id: Pubkey | None = None,
) -> Instruction:
    """V1 open instruction -> OpenWithHooks (discriminator 10 + open suffix)."""
    program = program_id or Pubkey.from_string(PAYMENT_CHANNELS_V2_PROGRAM_ID)
    data = bytearray(bytes(base.data))
    if any(hook is not None for hook in _slots(hooks)):
        data[0] = OPEN_WITH_HOOKS_DISCRIMINATOR
    data += encode_open_suffix(hooks)
    extra = _appended_hook_accounts(channel, hooks, [0, 1], program)
    return Instruction(base.program_id, bytes(data), [*base.accounts, *extra])
