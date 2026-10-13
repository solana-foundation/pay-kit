"""Thin factories for solana-keychain's managed-key backends.

Install ``solana-pay-kit[aws-kms]`` or ``solana-pay-kit[gcp-kms]`` for cloud
providers. Credentials and signing are handled entirely by solana-keychain.
"""

from __future__ import annotations

from typing import Any

import httpx
from solana_keychain import TransactionSigner, VaultSigner, VaultSignerConfig

__all__ = ["aws", "gcp", "vault"]


async def gcp(*, key_name: str, pubkey: str, client: Any = None) -> TransactionSigner:
    """Construct GCP's loop-bound client on the serving event loop.

    Create and use this signer on the same loop, such as an ASGI lifespan.
    The default gRPC client cannot be shared by synchronous middleware that
    creates a new event loop for each request.
    """
    from solana_keychain.gcp_kms import GcpKmsSignerConfig, create_gcp_kms_signer

    return await create_gcp_kms_signer(GcpKmsSignerConfig(key_name=key_name, public_key=pubkey, client=client))


def aws(*, key_id: str, pubkey: str, region: str | None = None, client: Any = None) -> TransactionSigner:
    """Construct a native AWS signer using the SDK credential chain by default."""
    from solana_keychain.aws_kms import AwsKmsSigner, AwsKmsSignerConfig

    return AwsKmsSigner(AwsKmsSignerConfig(key_id=key_id, public_key=pubkey, region=region, client=client))


def vault(
    *, addr: str, path: str, pubkey: str, token: str, http_client: httpx.AsyncClient | None = None
) -> TransactionSigner:
    """Construct a native Vault signer; ``path`` is the transit key name."""
    return VaultSigner(
        VaultSignerConfig(api_base_url=addr, key_name=path, public_key=pubkey, token=token, http_client=http_client)
    )
