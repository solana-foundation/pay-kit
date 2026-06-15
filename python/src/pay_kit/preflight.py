"""Boot-time soundness checks for the operator wallet (caveat #3).

Two checks run at ``configure`` time, mirroring Ruby ``pay_kit/preflight.rb``
and PHP ``Preflight.php``:

1. The fee payer (``operator.signer``) holds enough SOL to settle
   (``>= MIN_FEE_PAYER_LAMPORTS``).
2. Every stablecoin in ``config.stablecoins`` has an associated token account
   owned by the operator's effective recipient.

On ``solana_localnet`` with the demo signer, missing accounts are
auto-provisioned via the Surfnet cheatcodes (``surfnet_setAccount``,
``surfnet_setTokenAccount``) so the example apps boot reachable against
``https://402.surfnet.dev:8899`` with zero manual setup. Anywhere else, a
missing account raises :class:`~pay_kit.errors.ConfigurationError` at boot so
the operator is told immediately rather than at the first 402 retry.

RPC transport failures during preflight are LOGGED, never raised: an
unreachable endpoint must not block boot (the runtime surfaces it on the first
request anyway). Opt-out: ``configure(preflight=False)`` or
``PAY_KIT_DISABLE_PREFLIGHT=1``.

NOTE: This module is EXCLUDED from the coverage gate (see the ``omit`` entry in
``pyproject.toml``) because every meaningful path wraps a live Solana RPC call
plus Surfnet cheatcodes that cannot run inside the offline unit suite. Unit
tests instead exercise the two opt-out knobs against a stubbed
``pay_kit.preflight.run`` and inject a fake RPC callable via
:func:`set_rpc_callable_for_tests`.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import httpx

from pay_kit._paycore import mints
from pay_kit.errors import ConfigurationError

if TYPE_CHECKING:
    from pay_kit.config import Config

__all__ = [
    "run",
    "is_disabled_by_env",
    "set_rpc_callable_for_tests",
    "MIN_FEE_PAYER_LAMPORTS",
    "AUTOFUND_LAMPORTS",
]

_LOG = logging.getLogger("pay_kit.preflight")

# 0.001 SOL: enough for ~200 settlement txs at 5000 lamports/tx.
MIN_FEE_PAYER_LAMPORTS = 1_000_000

# 10 SOL: a generous local sandbox budget so a developer can poke the example
# for hours without re-funding.
AUTOFUND_LAMPORTS = 10_000_000_000

SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"

# Synchronous JSON-RPC callable signature ``(method, params) -> result``.
RpcCallable = Callable[[str, list[Any]], Any]

# Injected by tests via ``set_rpc_callable_for_tests`` so the unit suite never
# touches a live endpoint.
_rpc_callable_override: RpcCallable | None = None


def is_disabled_by_env() -> bool:
    """Return True when ``PAY_KIT_DISABLE_PREFLIGHT`` is set to ``1``/``true``."""
    raw = os.environ.get("PAY_KIT_DISABLE_PREFLIGHT")
    return raw in {"1", "true"}


def set_rpc_callable_for_tests(override: RpcCallable | None) -> None:
    """Install (or clear) a synchronous RPC callable used in place of httpx.

    @internal: test hook only. Pass ``None`` to restore live behaviour.
    """
    global _rpc_callable_override
    _rpc_callable_override = override


def run(config: Config) -> None:  # pragma: no cover - live RPC + Surfnet cheatcodes
    """Run the fee-payer and recipient-ATA preflight checks for ``config``.

    Configuration problems raise :class:`ConfigurationError`; RPC transport
    failures are logged and swallowed so an unreachable endpoint never blocks
    boot.
    """
    autofix = _autofix_enabled(config)

    try:
        _check_fee_payer_sol(config, autofix)
    except ConfigurationError:
        raise
    except Exception as exc:  # noqa: BLE001 - transient RPC failure must not block boot
        _LOG.warning("[pay_kit preflight] skipped fee-payer balance check: %s", exc)

    for coin in config.stablecoins:
        try:
            _check_recipient_ata(config, str(coin), autofix)
        except ConfigurationError:
            raise
        except Exception as exc:  # noqa: BLE001 - transient RPC failure must not block boot
            _LOG.warning("[pay_kit preflight] skipped %s ATA check: %s", coin, exc)


def _autofix_enabled(config: Config) -> bool:  # pragma: no cover - exercised live only
    """Localnet + demo signer is the only combination that mutates on-chain state."""
    network = str(config.network)
    if network != "solana_localnet":
        return False
    signer = config.operator.signer
    return signer is not None and signer.is_demo()


def _check_fee_payer_sol(config: Config, autofix: bool) -> None:  # pragma: no cover - live RPC
    """Ensure the fee payer holds at least ``MIN_FEE_PAYER_LAMPORTS``."""
    if not config.operator.fee_payer:
        return
    signer = config.operator.signer
    if signer is None:
        return

    pubkey = signer.pubkey()
    result = _rpc_call(config, "getBalance", [pubkey, {"commitment": "confirmed"}])
    lamports = int(cast("dict[str, Any]", result)["value"]) if isinstance(result, dict) and "value" in result else 0
    if lamports >= MIN_FEE_PAYER_LAMPORTS:
        return

    if autofix:
        _LOG.info(
            "[pay_kit preflight] funding demo fee-payer %s with %d lamports via surfnet_setAccount",
            pubkey,
            AUTOFUND_LAMPORTS,
        )
        _rpc_call(
            config,
            "surfnet_setAccount",
            [
                pubkey,
                {
                    "lamports": AUTOFUND_LAMPORTS,
                    "data": "",
                    "executable": False,
                    "owner": SYSTEM_PROGRAM_ID,
                    "rentEpoch": 0,
                },
            ],
        )
        return

    raise ConfigurationError(
        f"pay_kit preflight: fee-payer {pubkey} has {lamports} lamports on "
        f"{config.network} (need >= {MIN_FEE_PAYER_LAMPORTS}). "
        "Fund the account before booting."
    )


def _check_recipient_ata(config: Config, coin: str, autofix: bool) -> None:  # pragma: no cover - live RPC
    """Ensure the effective recipient has an ATA for ``coin``."""
    label = config.network.mints_label()
    mint = mints.resolve(coin, label)
    if not mint:
        return  # native SOL has no ATA to check

    token_program = mints.token_program_for(coin, label)
    recipient = config.effective_recipient()
    ata = mints.derive_ata(recipient, mint, token_program)

    info = _rpc_call(
        config,
        "getAccountInfo",
        [ata, {"encoding": "base64", "commitment": "confirmed"}],
    )
    value = cast("dict[str, Any]", info)["value"] if isinstance(info, dict) and "value" in info else None
    if value is not None:
        return

    if autofix:
        _LOG.info(
            "[pay_kit preflight] provisioning %s ATA for %s (mint=%s) via surfnet_setTokenAccount",
            coin,
            recipient,
            mint,
        )
        _rpc_call(
            config,
            "surfnet_setTokenAccount",
            [recipient, mint, {"amount": 0, "state": "initialized"}, token_program],
        )
        return

    raise ConfigurationError(
        f"pay_kit preflight: recipient {recipient} has no {coin} ATA on "
        f"{config.network} (expected {ata}). Create the ATA before booting "
        f"(e.g. `spl-token create-account {mint} --owner {recipient}`)."
    )


def _rpc_call(config: Config, method: str, params: list[Any]) -> Any:  # pragma: no cover - live RPC
    """Issue a synchronous JSON-RPC call, honoring the test override.

    Mirrors the PHP transport: returns the ``result`` field, raises on
    transport/decode failure so :func:`run` can log-and-skip.
    """
    override = _rpc_callable_override
    if override is not None:
        return override(method, params)

    endpoint = config.effective_rpc_url()
    response = httpx.post(
        endpoint,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=5.0,
    )
    response.raise_for_status()
    decoded = response.json()
    if not isinstance(decoded, dict):
        raise RuntimeError(f"rpc returned non-JSON from {endpoint}")
    return cast("dict[str, Any]", decoded).get("result")
