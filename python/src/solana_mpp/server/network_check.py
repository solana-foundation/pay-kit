"""Network / blockhash sanity check.

The Surfpool localnet implementation embeds a recognizable prefix into
every blockhash it returns. We use this to catch the common footgun where
a client signs a transaction against a Surfpool RPC and submits it to a
server configured for a real cluster (mainnet/devnet).

The check is asymmetric:

* If the blockhash starts with the Surfpool prefix, the transaction was
  DEFINITELY signed against a Surfpool localnet. The only network slug
  for which that's valid is ``localnet`` — any other slug must reject the
  credential up-front.

* If the blockhash does NOT start with the Surfpool prefix, we can't
  tell what cluster it came from (real localnet doesn't add a prefix
  either), so we accept it.
"""

from __future__ import annotations

from solana_mpp._errors import PaymentError

#: Base58 prefix embedded in every blockhash returned by the Surfpool
#: localnet implementation.
SURFPOOL_BLOCKHASH_PREFIX = "SURFNETxSAFEHASH"

#: Network slug for Solana's local validator. The only network for which
#: a Surfpool-prefixed blockhash is valid.
LOCALNET_NETWORK = "localnet"


class WrongNetworkError(PaymentError):
    """Raised when a Surfpool-signed blockhash is submitted to a non-localnet server."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="wrong-network")


def check_network_blockhash(network: str, blockhash_b58: str) -> None:
    """Pure check: raise if a Surfpool-prefixed blockhash is submitted to
    a server configured for any network other than ``localnet``.

    Returns ``None`` in every other case — a non-prefixed blockhash is
    undetectable as wrong-cluster from the slug alone.
    """
    if not blockhash_b58.startswith(SURFPOOL_BLOCKHASH_PREFIX):
        return
    if network == LOCALNET_NETWORK:
        return
    # The blockhash detail is debug-grade, not actionable for end
    # users — keep the message terse.
    raise WrongNetworkError(
        f"Signed against localnet but the server expects {network}. Switch your client RPC to {network} and re-sign."
    )
