"""Tests for server middleware (@pay decorator)."""

from __future__ import annotations

import pytest

from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.protocols.mpp.core.headers import format_authorization
from solana_pay_kit.protocols.mpp.core.types import PaymentCredential
from solana_pay_kit.protocols.mpp.server.charge import Config, Mpp
from solana_pay_kit.protocols.mpp.server.middleware import pay
from tests.test_server import (
    TEST_RECIPIENT,
    TEST_SECRET,
    USDC_DEVNET,
    FakeRPC,
    _build_spl_transfer_checked_transaction,
    _derive_ata,
)


@pytest.fixture
def mpp_handler():
    return Mpp(
        Config(
            recipient="CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            secret_key="test-secret-key-long-enough-for-hmac-sha256-operations-1234567890",
            network="localnet",
            store=MemoryStore(),
        )
    )


class TestPayDecorator:
    def test_creates_decorator(self, mpp_handler):
        @pay(mpp_handler, "0.01")
        async def handler(request, credential, receipt):
            return {"ok": True}

        assert callable(handler)

    def test_decorator_preserves_name(self, mpp_handler):
        @pay(mpp_handler, "0.01")
        async def my_handler(request, credential, receipt):
            return {"ok": True}

        assert my_handler.__name__ == "my_handler"

    @pytest.mark.asyncio
    async def test_no_auth_returns_402(self, mpp_handler):
        @pay(mpp_handler, "10000")
        async def handler(request, credential, receipt):
            return {"ok": True}

        # Simulate a request without Authorization header
        class FakeRequest:
            headers = {}
            url = "http://localhost/test"

        # The @pay decorator wraps the inner (request, credential, receipt)
        # signature so the external caller passes only the request; pyright
        # does not infer the wrapper's reduced signature, so silence the
        # missing-args report on the call site.
        result = await handler(FakeRequest())  # pyright: ignore[reportCallIssue]
        # Should return a challenge (402-like response)
        assert result is not None

    @pytest.mark.asyncio
    async def test_splits_option_is_included_in_challenge(self, mpp_handler):
        # Audit #21: split recipients are validated as real pubkeys at issuance.
        from solders.pubkey import Pubkey

        splits = [
            {
                "recipient": str(Pubkey.new_unique()),
                "amount": "1000",
                "memo": "vendor payout",
            }
        ]

        @pay(mpp_handler, "10000", splits=splits)
        async def handler(request, credential, receipt):
            return {"ok": True}

        class FakeRequest:
            headers = {}
            url = "http://localhost/test"

        result = await handler(FakeRequest())  # pyright: ignore[reportCallIssue]
        request = result["challenge"].decode_request()

        assert request["methodDetails"]["splits"] == splits

    @pytest.mark.asyncio
    async def test_with_invalid_auth_returns_402(self, mpp_handler):
        @pay(mpp_handler, "10000")
        async def handler(request, credential, receipt):
            return {"ok": True}

        class FakeRequest:
            headers = {"authorization": "Payment invalid-credential"}
            url = "http://localhost/test"

        result = await handler(FakeRequest())  # pyright: ignore[reportCallIssue]
        assert result is not None

    @pytest.mark.asyncio
    async def test_valid_auth_reaches_wrapped_handler_and_returns_receipt(self):
        """Regression: a VALID Authorization header MUST reach the wrapped
        handler with a successful receipt. A previous version of the
        middleware called ``parse_authorization`` without a module-level
        import, so the inner ``except Exception`` swallowed the NameError
        and turned every valid paid request into a 402 ``payment_invalid``.
        Existing tests only covered the no-auth / invalid-auth branches
        and missed this regression, so this test exercises the full
        happy path end-to-end."""
        rpc = FakeRPC(
            tx={
                "meta": {"err": None},
                "transaction": {
                    "message": {
                        "instructions": [
                            {
                                "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                                "parsed": {
                                    "type": "transferChecked",
                                    "info": {
                                        "destination": _derive_ata(TEST_RECIPIENT, USDC_DEVNET),
                                        "mint": USDC_DEVNET,
                                        "tokenAmount": {"amount": "1000000"},
                                    },
                                },
                            }
                        ]
                    }
                },
            },
            token_accounts={
                _derive_ata(TEST_RECIPIENT, USDC_DEVNET): {
                    "owner": TEST_RECIPIENT,
                    "mint": USDC_DEVNET,
                }
            },
        )
        handler_mpp = Mpp(
            Config(
                recipient=TEST_RECIPIENT,
                currency="USDC",
                decimals=6,
                network="devnet",
                secret_key=TEST_SECRET,
                rpc=rpc,
                store=MemoryStore(),
            )
        )

        seen: dict[str, object] = {}

        @pay(handler_mpp, "1.00")
        async def wrapped(request, credential, receipt):
            seen["credential"] = credential
            seen["receipt"] = receipt
            return {"ok": True, "data": "paid content"}

        # Build a valid credential that matches the route's expected charge
        # ("1.00" USDC, recipient = TEST_RECIPIENT, devnet).
        challenge = handler_mpp.charge("1.00")
        transaction = _build_spl_transfer_checked_transaction(TEST_RECIPIENT, USDC_DEVNET, 1_000_000)
        credential = PaymentCredential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "transaction": transaction},
        )
        auth_header = format_authorization(credential)

        class FakeRequest:
            headers = {"authorization": auth_header}
            url = "http://localhost/test"

        result = await wrapped(FakeRequest())  # pyright: ignore[reportCallIssue]

        # The wrapped handler MUST have been reached (not a 402).
        assert result == {"ok": True, "data": "paid content"}
        assert "credential" in seen
        assert "receipt" in seen
        assert seen["receipt"].is_success()  # type: ignore[attr-defined]
