"""The shared builder uses native keychain transaction signing, not key export."""

import pytest
from solana_keychain import MemorySigner, SignedTransaction, TransactionSigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.transaction import build_partially_signed_v0_transaction


class TransactionOnlySigner(TransactionSigner):
    """Model a remote backend that cannot export keys or sign arbitrary messages."""

    def __init__(self) -> None:
        self._backend = MemorySigner(Keypair())

    @property
    def pubkey(self) -> Pubkey:
        return self._backend.pubkey

    async def is_available(self) -> bool:
        return True

    async def sign_message(self, message: bytes) -> Signature:
        raise AssertionError("transaction signing must not request a message signature")

    async def sign_transaction(self, transaction: VersionedTransaction) -> SignedTransaction:
        # Return a different object to ensure callers use the authoritative result.
        clone = VersionedTransaction.from_bytes(bytes(transaction))
        return await self._backend.sign_transaction(clone)


@pytest.mark.asyncio
async def test_transaction_only_signer_preserves_sponsor_slot() -> None:
    payer = TransactionOnlySigner()
    sponsor = MemorySigner(Keypair())
    instruction = transfer(TransferParams(from_pubkey=payer.pubkey, to_pubkey=Pubkey.new_unique(), lamports=1))
    wire = await build_partially_signed_v0_transaction([instruction], sponsor.pubkey, Hash.default(), payer)
    transaction = VersionedTransaction.from_bytes(wire)
    assert transaction.signatures[0] == Signature.default()
    assert transaction.verify_with_results() == [False, True]
    payer_signature = transaction.signatures[1]

    result = await sponsor.sign_transaction(transaction)
    assert result.is_complete
    assert result.transaction.signatures[1] == payer_signature
    assert result.transaction.verify_with_results() == [True, True]


@pytest.mark.asyncio
async def test_transaction_builder_rejects_unrelated_signer() -> None:
    signer = TransactionOnlySigner()
    payer = Pubkey.new_unique()
    instruction = transfer(TransferParams(from_pubkey=payer, to_pubkey=Pubkey.new_unique(), lamports=1))
    with pytest.raises(ValueError, match="not a required signer"):
        await build_partially_signed_v0_transaction([instruction], payer, Hash.default(), signer)


@pytest.mark.asyncio
async def test_transaction_builder_signs_without_sponsor() -> None:
    signer = TransactionOnlySigner()
    instruction = transfer(TransferParams(from_pubkey=signer.pubkey, to_pubkey=Pubkey.new_unique(), lamports=1))
    wire = await build_partially_signed_v0_transaction([instruction], signer.pubkey, Hash.default(), signer)
    assert VersionedTransaction.from_bytes(wire).verify_with_results() == [True]
