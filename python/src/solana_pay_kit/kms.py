"""Reserved namespace for remote enclave signers (GCP/AWS KMS, HashiCorp Vault).

The shape is locked so consumers can build against ``solana_pay_kit.kms.gcp(...)`` today
without renaming when the real implementations ship in a follow-up release. Every
factory currently raises :class:`NotImplementedError`. Loud failure is on purpose:
silent fallback to a local in-process signer would mask a production
misconfiguration (a merchant intending to sign through a managed KMS service must
not silently get a local signer instead).

When implemented, KMS signers will satisfy the same duck-type contract as
:class:`solana_pay_kit.signer.LocalSigner` (``pubkey()``, ``sign(message)``,
``is_fee_payer()``) with explicit ``pubkey=`` configuration so boot does not probe
the enclave. Mirrors Ruby ``PayKit::Kms`` and the PHP reserved ``Kms`` namespace.
"""

from __future__ import annotations

__all__ = ["aws", "gcp", "vault"]

_FOLLOW_UP = (
    "is reserved for a follow-up release; "
    "use solana_pay_kit.Signer.file or solana_pay_kit.Signer.env in the meantime"
)


def gcp(*, key_name: str, pubkey: str) -> object:
    """Reserved: a Google Cloud KMS signer. Raises until the backend ships."""
    raise NotImplementedError(f"solana_pay_kit.kms.gcp(key_name={key_name!r}, pubkey={pubkey!r}) {_FOLLOW_UP}")


def aws(*, key_id: str, region: str, pubkey: str) -> object:
    """Reserved: an AWS KMS signer. Raises until the backend ships."""
    raise NotImplementedError(
        f"solana_pay_kit.kms.aws(key_id={key_id!r}, region={region!r}, pubkey={pubkey!r}) {_FOLLOW_UP}"
    )


def vault(*, addr: str, path: str, pubkey: str) -> object:
    """Reserved: a HashiCorp Vault transit signer. Raises until the backend ships."""
    raise NotImplementedError(f"solana_pay_kit.kms.vault(addr={addr!r}, path={path!r}, pubkey={pubkey!r}) {_FOLLOW_UP}")
