"""Legacy x402 ``exact`` wire helpers: plain SVM network names + headers.

The legacy x402 wire (``X-PAYMENT`` / ``X-PAYMENT-REQUIRED`` /
``X-PAYMENT-RESPONSE``) names networks with PLAIN SVM slugs
(``solana`` / ``solana-devnet`` / ``solana-testnet``) rather than the CAIP-2
identifiers the canonical (v2) wire uses. This module mirrors the rust spine
constants and the two mappings the legacy producer/parser rely on:

* :func:`legacy_network_for_caip2` mirrors rust ``v1_network_for_requirements``
  (``rust/crates/x402/src/client/exact/payment.rs:393-404``): devnet-family ->
  ``solana-devnet``, everything else -> ``solana``.
* :func:`caip2_for_network` mirrors rust ``caip2_network_for_cluster``
  (``rust/crates/x402/src/protocol/schemes/exact/types.rs:30-39``): normalize a
  plain slug (or a CAIP-2 string) to the canonical CAIP-2 identifier the network
  gate compares against.

The legacy wire is a SEPARATE parallel shape from the canonical (v2) wire; there
is no conversion helper between the two. Each is built/parsed natively.
"""

from __future__ import annotations

from pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2

__all__ = [
    "X402_LEGACY_PAYMENT_HEADER",
    "X402_LEGACY_PAYMENT_REQUIRED_HEADER",
    "X402_LEGACY_PAYMENT_RESPONSE_HEADER",
    "SOLANA_NETWORK_NAME",
    "SOLANA_DEVNET_NAME",
    "SOLANA_TESTNET_NAME",
    "legacy_network_for_caip2",
    "caip2_for_network",
]

#: Solana testnet CAIP-2 (rust ``SOLANA_TESTNET``, types.rs:18). Not advertised
#: by the pay_kit server but accepted on the gate so a testnet legacy credential
#: normalizes correctly.
SOLANA_TESTNET_CAIP2 = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"

#: Legacy client payment header (rust ``X402_V1_PAYMENT_HEADER``, constants.rs:16).
X402_LEGACY_PAYMENT_HEADER = "X-PAYMENT"
#: Legacy payment-required header (rust ``X402_V1_PAYMENT_REQUIRED_HEADER``,
#: constants.rs:19). pay_kit follows the rust spine: a legacy challenge MAY ship
#: in this header and the client reads it before the 402 JSON body.
X402_LEGACY_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED"
#: Legacy settlement response header (rust ``X402_V1_PAYMENT_RESPONSE_HEADER``,
#: constants.rs:22).
X402_LEGACY_PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE"

#: Plain SVM network names (rust ``SOLANA_NETWORK`` + the devnet/testnet slugs).
SOLANA_NETWORK_NAME = "solana"
SOLANA_DEVNET_NAME = "solana-devnet"
SOLANA_TESTNET_NAME = "solana-testnet"

#: Devnet-family CAIP-2 ids that map to the ``solana-devnet`` legacy slug.
_DEVNET_CAIP2 = frozenset({SOLANA_DEVNET_CAIP2})


def legacy_network_for_caip2(network: str | None) -> str:
    """Map an offer's network (CAIP-2 or plain slug) to a legacy SVM slug.

    Mirrors rust ``v1_network_for_requirements`` (payment.rs:393-404): the
    devnet family (``devnet`` / ``solana-devnet`` / devnet CAIP-2) maps to
    ``solana-devnet``; everything else maps to ``solana``.
    """
    if network is None:
        return SOLANA_NETWORK_NAME
    candidate = network.strip()
    if candidate in _DEVNET_CAIP2 or candidate in {"devnet", "solana-devnet", "localnet"}:
        return SOLANA_DEVNET_NAME
    return SOLANA_NETWORK_NAME


def caip2_for_network(network: str | None) -> str:
    """Normalize a plain slug (or CAIP-2) to the canonical CAIP-2 identifier.

    Mirrors rust ``caip2_network_for_cluster`` (types.rs:30-39): testnet and
    devnet families resolve to their CAIP-2 ids; everything else (including the
    bare ``solana`` slug and ``mainnet``/``mainnet-beta``) resolves to mainnet.
    """
    if network is None:
        return SOLANA_MAINNET_CAIP2
    candidate = network.strip()
    if candidate in {SOLANA_TESTNET_CAIP2, "testnet", SOLANA_TESTNET_NAME}:
        return SOLANA_TESTNET_CAIP2
    if candidate in {SOLANA_DEVNET_CAIP2, "devnet", SOLANA_DEVNET_NAME, "localnet"}:
        return SOLANA_DEVNET_CAIP2
    return SOLANA_MAINNET_CAIP2
