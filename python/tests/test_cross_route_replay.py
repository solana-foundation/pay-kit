"""Cross-route credential replay regression tests for the Python SDK.

Mirrors the Go suite: tampered method/intent/realm/currency/recipient must be
rejected by the Tier-2 backstop in verify_credential, and amount mismatches
between credential and route must be rejected by verify_credential_with_expected.
"""

from __future__ import annotations

import pytest

from pay_kit._paycore.errors import PaymentError
from pay_kit._paycore.store import MemoryStore
from pay_kit.protocols.mpp.core.base64url import encode_json
from pay_kit.protocols.mpp.core.challenge import compute_challenge_id
from pay_kit.protocols.mpp.core.types import ChallengeEcho, PaymentCredential
from pay_kit.protocols.mpp.intents.charge import ChargeRequest
from pay_kit.protocols.mpp.server.charge import Config, Mpp

TEST_SECRET = "cross-route-replay-test-secret-key"
TEST_RECIPIENT = "11111111111111111111111111111112"


def _make_mpp() -> Mpp:
    return Mpp(
        Config(
            recipient=TEST_RECIPIENT,
            currency="USDC",
            decimals=6,
            network="devnet",
            secret_key=TEST_SECRET,
            store=MemoryStore(),
        )
    )


def _resign_echo(echo: ChallengeEcho) -> ChallengeEcho:
    """Recompute the HMAC ID after a test mutates one of the echoed fields."""
    echo.id = compute_challenge_id(
        secret_key=TEST_SECRET,
        realm=echo.realm,
        method=echo.method,
        intent=echo.intent,
        request=echo.request,
        expires=echo.expires or "",
        digest=echo.digest or "",
        opaque=echo.opaque,
    )
    return echo


def _bogus_signature_credential(echo: ChallengeEcho) -> PaymentCredential:
    """Build a credential whose payload is a bogus signature.

    All Tier-2 / binding tests below fail before settlement, so we never need a
    real RPC.
    """
    return PaymentCredential(
        challenge=echo,
        payload={"type": "signature", "signature": "5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx"},
    )


def _echo_from(challenge) -> ChallengeEcho:
    return ChallengeEcho(
        id=challenge.id,
        realm=challenge.realm,
        method=challenge.method,
        intent=challenge.intent,
        request=challenge.request,
        expires=challenge.expires,
        digest=challenge.digest,
        opaque=challenge.opaque,
    )


# ── Tier-2 pinned-field tests ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tier2_rejects_tampered_realm():
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    echo = _echo_from(challenge)
    echo.realm = "Attacker Realm"
    _resign_echo(echo)

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(
            _bogus_signature_credential(echo),
            ChargeRequest.from_dict(challenge.decode_request()),
        )
    assert "realm" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_tier2_rejects_tampered_method():
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    echo = _echo_from(challenge)
    echo.method = "stripe"
    _resign_echo(echo)

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(
            _bogus_signature_credential(echo),
            ChargeRequest.from_dict(challenge.decode_request()),
        )
    assert "method" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_tier2_rejects_non_charge_intent():
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    echo = _echo_from(challenge)
    echo.intent = "session"
    _resign_echo(echo)

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(
            _bogus_signature_credential(echo),
            ChargeRequest.from_dict(challenge.decode_request()),
        )
    assert "intent" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_tier2_rejects_tampered_currency():
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    request = ChargeRequest.from_dict(challenge.decode_request())
    request.currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    tampered_request = encode_json(request.to_dict())

    echo = _echo_from(challenge)
    echo.request = tampered_request
    _resign_echo(echo)

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(
            _bogus_signature_credential(echo),
            ChargeRequest.from_dict(challenge.decode_request()),
        )
    assert "currency" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_tier2_rejects_tampered_recipient():
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    request = ChargeRequest.from_dict(challenge.decode_request())
    request.recipient = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ"
    tampered_request = encode_json(request.to_dict())

    echo = _echo_from(challenge)
    echo.request = tampered_request
    _resign_echo(echo)

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(
            _bogus_signature_credential(echo),
            ChargeRequest.from_dict(challenge.decode_request()),
        )
    assert "recipient" in str(exc.value).lower()


# ── verify_credential_with_expected tests ────────────────────────────────────


@pytest.mark.asyncio
async def test_with_expected_rejects_amount_mismatch():
    """A credential issued for a cheap route must not satisfy an expensive one."""
    mpp = _make_mpp()
    cheap = mpp.charge("0.001")
    cred = _bogus_signature_credential(_echo_from(cheap))

    expensive = mpp.charge("1.0")
    expected = ChargeRequest.from_dict(expensive.decode_request())

    with pytest.raises(PaymentError) as exc:
        await mpp.verify_credential_with_expected(cred, expected)
    assert "amount" in str(exc.value).lower()
    assert exc.value.code == "amount-mismatch"


@pytest.mark.asyncio
async def test_with_expected_accepts_matching_route():
    """If the credential matches the route's expected request, the binding/
    Tier-2 layer must not reject — failures from this point on must come
    from settlement (which we don't reach here because the payload is bogus).
    """
    mpp = _make_mpp()
    challenge = mpp.charge("0.10")
    cred = _bogus_signature_credential(_echo_from(challenge))
    expected = ChargeRequest.from_dict(challenge.decode_request())

    try:
        await mpp.verify_credential_with_expected(cred, expected)
    except PaymentError as e:
        msg = str(e).lower()
        # None of these phrases should appear when the route matches.
        for phrase in (
            "amount mismatch",
            "currency mismatch",
            "recipient mismatch",
            "credential method",
            "credential intent",
            "credential realm",
        ):
            assert phrase not in msg, f"matching route incorrectly tripped binding: {e}"
