"""Pure-function tests for the Surfpool-prefix-vs-non-localnet check.

The check is asymmetric: a Surfpool-prefixed blockhash is only valid on
``localnet``, but a non-prefixed blockhash is accepted on any network
(we can't tell from a non-prefixed hash which real cluster it came from).
"""

from __future__ import annotations

import pytest

from solana_pay_kit._paycore.network_check import (
    SURFPOOL_BLOCKHASH_PREFIX,
    WrongNetworkError,
    check_network_blockhash,
)

# ── happy paths ────────────────────────────────────────────────────────────


def test_localnet_with_surfpool_hash_ok() -> None:
    check_network_blockhash("localnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")


def test_localnet_with_real_hash_ok() -> None:
    # Real localnet validator (not Surfpool) — also valid.
    check_network_blockhash("localnet", "11111111111111111111111111111111")


def test_mainnet_with_real_hash_ok() -> None:
    check_network_blockhash("mainnet", "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F")


def test_devnet_with_real_hash_ok() -> None:
    check_network_blockhash("devnet", "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")


# ── the actual bug surface ─────────────────────────────────────────────────


def test_mainnet_rejects_surfpool_hash() -> None:
    with pytest.raises(WrongNetworkError) as excinfo:
        check_network_blockhash("mainnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
    err = excinfo.value
    assert err.code == "wrong-network"
    assert "Signed against localnet" in str(err)
    assert "server expects mainnet" in str(err)
    assert "re-sign" in str(err)


def test_devnet_rejects_surfpool_hash() -> None:
    with pytest.raises(WrongNetworkError) as excinfo:
        check_network_blockhash("devnet", "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
    assert "server expects devnet" in str(excinfo.value)


# ── edge cases ─────────────────────────────────────────────────────────────


def test_partial_prefix_does_not_match() -> None:
    # "SURFNETx" alone (8 chars) is NOT the full prefix.
    check_network_blockhash("mainnet", "SURFNETx9zrUHnA1nCByPksy")


def test_exact_prefix_only_is_treated_as_surfpool() -> None:
    check_network_blockhash("localnet", SURFPOOL_BLOCKHASH_PREFIX)
    with pytest.raises(WrongNetworkError):
        check_network_blockhash("mainnet", SURFPOOL_BLOCKHASH_PREFIX)


def test_non_surfpool_hash_passes_anywhere() -> None:
    # Asymmetric design: a non-prefixed blockhash is accepted on any
    # network because we can't tell which real cluster it came from.
    for network in ("mainnet", "devnet", "localnet"):
        check_network_blockhash(network, "11111111111111111111111111111111")
