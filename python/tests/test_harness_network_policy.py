"""Regression coverage for Python harness network parsing."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from solana_pay_kit import Network
from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_harness_module(filename: str) -> ModuleType:
    path = _REPO_ROOT / "harness" / "python-server" / filename
    spec = importlib.util.spec_from_file_location(f"test_{path.stem.replace('-', '_')}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def harness_modules() -> tuple[ModuleType, ModuleType]:
    return _load_harness_module("server.py"), _load_harness_module("mpp-adapter-boot.py")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mainnet", Network.SOLANA_MAINNET),
        ("mainnet-beta", Network.SOLANA_MAINNET),
        (SOLANA_MAINNET_CAIP2, Network.SOLANA_MAINNET),
        ("devnet", Network.SOLANA_DEVNET),
        (SOLANA_DEVNET_CAIP2, Network.SOLANA_DEVNET),
        ("localnet", Network.SOLANA_LOCALNET),
        ("solana_mainnet", Network.SOLANA_MAINNET),
        ("solana_devnet", Network.SOLANA_DEVNET),
        ("solana_localnet", Network.SOLANA_LOCALNET),
    ],
)
def test_harness_networks_normalize_to_canonical_enum(
    harness_modules: tuple[ModuleType, ModuleType], raw: str, expected: Network
) -> None:
    server, boot = harness_modules

    assert server._resolve_network(raw) is expected
    assert boot._resolve_network(raw) is expected


@pytest.mark.parametrize("raw", ["solana:unknown-network", "testnet", "solana_testnet"])
def test_harness_networks_reject_unknown_inputs_without_fallback(
    harness_modules: tuple[ModuleType, ModuleType], raw: str
) -> None:
    server, boot = harness_modules

    with pytest.raises(ValueError, match="unknown network"):
        server._resolve_network(raw)
    with pytest.raises(ValueError, match="unknown network"):
        boot._resolve_network(raw)
