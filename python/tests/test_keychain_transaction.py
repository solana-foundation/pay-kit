"""The shared builder uses native keychain transaction signing, not key export."""

import pytest
from solana_keychain import MemorySigner, SignedTransaction, TransactionSigner
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction

from solana_pay_kit._paycore.transaction import (
    SignatureCheckError,
    build_partially_signed_v0_transaction,
    verify_required_signatures,
)


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


def _two_signer() -> tuple[VersionedTransaction, Keypair, Keypair]:
    from solders.message import MessageV0

    fee_payer, payer = Keypair(), Keypair()
    instruction = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=Pubkey.new_unique(), lamports=1))
    message = MessageV0.try_compile(fee_payer.pubkey(), [instruction], [], Hash.default())
    return VersionedTransaction(message, [fee_payer, payer]), fee_payer, payer


def test_required_signatures_accepts_a_fully_signed_transaction() -> None:
    transaction, _fee_payer, _payer = _two_signer()
    verify_required_signatures(transaction)


def test_required_signatures_refuses_a_truncated_signature_list() -> None:
    transaction, _fee_payer, _payer = _two_signer()
    truncated = VersionedTransaction.populate(transaction.message, [transaction.signatures[0]])
    assert all(truncated.verify_with_results())  # a slot-by-slot check passes it
    with pytest.raises(SignatureCheckError, match="1 signatures but its message requires 2"):
        verify_required_signatures(truncated)


def test_required_signatures_refuses_an_extra_signature() -> None:
    transaction, _fee_payer, _payer = _two_signer()
    padded = VersionedTransaction.populate(transaction.message, [*transaction.signatures, Signature.default()])
    with pytest.raises(SignatureCheckError):
        verify_required_signatures(padded)


def test_required_signatures_allows_only_the_named_unsigned_slot() -> None:
    transaction, fee_payer, _payer = _two_signer()
    sponsor_unsigned = VersionedTransaction.populate(
        transaction.message, [Signature.default(), transaction.signatures[1]]
    )
    verify_required_signatures(sponsor_unsigned, unsigned=fee_payer.pubkey())
    with pytest.raises(SignatureCheckError):
        verify_required_signatures(sponsor_unsigned)
    payer_unsigned = VersionedTransaction.populate(
        transaction.message, [transaction.signatures[0], Signature.default()]
    )
    with pytest.raises(SignatureCheckError):
        verify_required_signatures(payer_unsigned, unsigned=fee_payer.pubkey())
    # The named slot may be empty, never forged.
    forged = VersionedTransaction.populate(transaction.message, [Signature(bytes([7]) * 64), transaction.signatures[1]])
    with pytest.raises(SignatureCheckError):
        verify_required_signatures(forged, unsigned=fee_payer.pubkey())
