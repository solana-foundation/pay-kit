"""``subscription`` vectors for the Python conformance runner.

The runner hands each vector's input to the SDK unchanged (harness/AGENTS.md
"Never put logic in the testee"); this mirrors the Rust testee
``rust/crates/kit/examples/vector_runner/subscription.rs``:

- canonical bytes: the bearer-proof message
  (``SubscriptionAuthentication.message_bytes``), the period mapping, the
  delegation / authority PDAs, the subscribe / transfer_subscription data
  encoders, and the wire types re-encoded as JCS;
- build: ``build_subscription_activation_credential`` against the fixture RPC;
- verify: the route's ``SubscriptionServer`` at the pinned clock (the offline
  activation verification, or the on-chain active-subscription check), or
  ``SubscriptionAuthentication.verify``.

Reject categories: the client refusing a challenge is ``invalid-challenge``;
otherwise the SDK's message is classified with the same table as the Rust
testee.
"""

from __future__ import annotations

import asyncio
from typing import Any

from solana_keychain import MemorySigner
from solders.keypair import Keypair

from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit.protocols.mpp.client.subscription import build_subscription_activation_credential
from solana_pay_kit.protocols.mpp.core.base64url import encode as base64url_encode
from solana_pay_kit.protocols.mpp.core.base64url import encode_json
from solana_pay_kit.protocols.mpp.core.headers import parse_authorization
from solana_pay_kit.protocols.mpp.core.json import encode_canonical
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge
from solana_pay_kit.protocols.mpp.intents.subscription import (
    ActivatePayload,
    SubscriptionAccessPayload,
    SubscriptionAuthentication,
    SubscriptionRequest,
    billing_period_hours,
    parse_period_unit,
)
from solana_pay_kit.protocols.mpp.program.subscriptions import (
    SubscribeData,
    TransferData,
    find_subscription_authority_pda,
    find_subscription_pda,
    parse_pubkey,
)
from solana_pay_kit.protocols.mpp.server.subscription import (
    PreparedAccess,
    SubscriptionConfig,
    SubscriptionServer,
)


class Rejection(Exception):
    """A refusal with an optional shared reject category."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


def _str(value: dict[str, Any], key: str) -> str:
    raw = value.get(key)
    return raw if isinstance(raw, str) else ""


def _exact(fields: dict[str, Any]) -> dict[str, Any]:
    return {"outcome": "accept", "exactBytes": fields}


def _jcs(value: Any) -> dict[str, Any]:
    raw = encode_canonical(value)
    return _exact({"canonicalJson": raw.decode("utf-8"), "base64Url": base64url_encode(raw)})


def _unsupported(reason: str) -> dict[str, Any]:
    return {"outcome": "unsupported-mode", "error": f"unsupported-mode: {reason}"}


def _canonical(inp: dict[str, Any]) -> dict[str, Any]:
    if "subscriptionAuthenticationMessage" in inp:
        m = inp["subscriptionAuthenticationMessage"]
        auth = SubscriptionAuthentication(challenge_id=_str(m, "challengeId"), payer=_str(m, "payer"), signature="")
        raw = auth.message_bytes(_str(m, "subscriptionDelegation"))
        return _exact({"canonicalJson": raw.decode("utf-8"), "base64Url": base64url_encode(raw)})
    if "subscriptionPeriod" in inp:
        p = inp["subscriptionPeriod"]
        try:
            unit = parse_period_unit(p.get("periodUnit"))
        except ValueError as exc:
            raise Rejection(f"invalid periodUnit: {exc}", "invalid-challenge") from exc
        try:
            hours = billing_period_hours(unit, _str(p, "periodCount"))
        except ValueError as exc:
            raise Rejection(str(exc), "invalid-challenge") from exc
        return _jcs({"periodHours": hours})
    if "subscriptionPda" in inp:
        p = inp["subscriptionPda"]
        program = parse_pubkey(_str(p, "subscriptionProgram"), "subscriptionProgram")
        kind = _str(p, "kind")
        if kind == "delegation":
            address = find_subscription_pda(
                parse_pubkey(_str(p, "planAddress"), "planAddress"),
                parse_pubkey(_str(p, "subscriber"), "subscriber"),
                program,
            )[0]
        elif kind == "authority":
            address = find_subscription_authority_pda(
                parse_pubkey(_str(p, "subscriber"), "subscriber"), parse_pubkey(_str(p, "mint"), "mint"), program
            )[0]
        else:
            raise Rejection(f"unknown subscriptionPda kind {kind!r}")
        return _jcs({"address": str(address)})
    if "subscriptionInstruction" in inp:
        ix = inp["subscriptionInstruction"]

        def num(key: str) -> int:
            value = ix.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise Rejection(f"missing {key}")
            try:
                return int(value)
            except ValueError as exc:
                raise Rejection(f"invalid {key}") from exc

        kind = _str(ix, "kind")
        if kind == "subscribe":
            data = SubscribeData(
                plan_id=num("planId"),
                plan_bump=num("planBump"),
                expected_mint=parse_pubkey(_str(ix, "mint"), "mint"),
                expected_amount=num("amount"),
                expected_period_hours=num("periodHours"),
                expected_created_at=num("createdAt"),
                expected_subscription_authority_init_id=num("authorityInitId"),
            ).to_bytes()
        elif kind == "transfer":
            data = TransferData(
                amount=num("amount"),
                delegator=parse_pubkey(_str(ix, "delegator"), "delegator"),
                mint=parse_pubkey(_str(ix, "mint"), "mint"),
            ).to_bytes()
        else:
            raise Rejection(f"unknown subscriptionInstruction kind {kind!r}")
        return _exact({"bytes": list(data), "base64Url": base64url_encode(data)})
    if "subscriptionWire" in inp:
        w = inp["subscriptionWire"]
        value = w.get("value")
        shape = _str(w, "shape")
        try:
            if shape == "request":
                code = "invalid-challenge"
                reencoded = SubscriptionRequest.from_dict(value).to_dict()
            elif shape == "activation":
                code = "invalid-payload"
                reencoded = ActivatePayload.from_dict(value).to_dict()
            elif shape == "access":
                code = "invalid-payload"
                reencoded = SubscriptionAccessPayload.from_dict(value).to_dict()
            else:
                raise Rejection(f"unknown subscriptionWire shape {shape!r}")
        except ValueError as exc:
            raise Rejection(f"invalid subscription wire value: {exc}", code) from exc
        return _jcs(reencoded)
    return _unsupported("no subscription canonical-bytes input")


def _signer(inp: dict[str, Any], key: str) -> MemorySigner:
    secret = inp.get(key)
    if not isinstance(secret, list):
        raise Rejection(f"vector is missing input.{key}")
    return MemorySigner(Keypair.from_bytes(bytes(secret)))


def _rpc_url(inp: dict[str, Any]) -> str:
    url = inp.get("rpcUrl")
    if not isinstance(url, str):
        raise Rejection("driver did not inject input.rpcUrl")
    return url


async def _build(inp: dict[str, Any]) -> dict[str, Any]:
    signer = _signer(inp, "signerSecretKey")
    c = inp.get("subscriptionChallenge")
    if not isinstance(c, dict):
        raise Rejection("vector is missing input.subscriptionChallenge")
    challenge = PaymentChallenge(
        id=_str(c, "id"),
        realm=_str(c, "realm"),
        method=_str(c, "method"),
        intent=_str(c, "intent"),
        request=encode_json(c.get("request")),
        expires=_str(c, "expires"),
    )
    rpc = SolanaRpc(_rpc_url(inp))
    try:
        activation = await build_subscription_activation_credential(signer, rpc, challenge)
    except Exception as exc:  # noqa: BLE001 - every refusal of the builder is a refusal of the challenge
        raise Rejection(str(exc), "invalid-challenge") from exc
    finally:
        await rpc.aclose()
    transaction = activation.credential.payload.get("transaction")
    if not isinstance(transaction, str):
        raise Rejection("activation credential carries no transaction")
    return {"outcome": "accept", "transaction": transaction}


def _server(inp: dict[str, Any]) -> tuple[SubscriptionServer, SolanaRpc]:
    s = inp.get("subscriptionServer")
    if not isinstance(s, dict):
        raise Rejection("vector is missing input.subscriptionServer")
    rpc = SolanaRpc(_rpc_url(inp))
    try:
        fee_payer_signer = (
            _signer(inp, "subscriptionServerFeePayerSecretKey")
            if "subscriptionServerFeePayerSecretKey" in inp
            else None
        )
        fee_payer_key = s.get("feePayerKey")
        server = SubscriptionServer(
            SubscriptionConfig(
                plan_id=_str(s, "planAddress"),
                mint=_str(s, "mint"),
                decimals=int(s.get("decimals") or 0),
                token_program=_str(s, "tokenProgram"),
                puller=_str(s, "puller"),
                recipient=_str(s, "recipient"),
                period_unit=parse_period_unit(s.get("periodUnit")),
                period_count=int(s.get("periodCount") or 0),
                amount_base_units=_str(s, "amount"),
                network=_str(s, "network"),
                program_id=s.get("subscriptionProgram"),
                rpc=rpc,
                challenge_binding_secret=_str(s, "secretKey"),
                realm=_str(s, "realm"),
                fee_payer=fee_payer_key is not None,
                fee_payer_signer=fee_payer_signer,
                fee_payer_pubkey=fee_payer_key,
            )
        )
    except ValueError as exc:
        raise Rejection(f"server config: {exc}") from exc
    return server, rpc


def _now(inp: dict[str, Any]) -> int:
    now = inp.get("nowSeconds")
    if isinstance(now, bool) or not isinstance(now, int):
        raise Rejection("vector is missing input.nowSeconds")
    return now


async def _verify_activation(inp: dict[str, Any]) -> dict[str, Any]:
    server, rpc = _server(inp)
    try:
        try:
            credential = parse_authorization(_str(inp, "subscriptionAuthorization"))
        except Exception as exc:  # noqa: BLE001 - a malformed header is a malformed payload
            raise Rejection(str(exc), "invalid-payload") from exc
        try:
            prepared = await server.verify_activation(credential, now=_now(inp))
        except Rejection:
            raise
        except Exception as exc:  # noqa: BLE001 - classified by message
            raise Rejection(str(exc), classify(str(exc))) from exc
    finally:
        await rpc.aclose()
    if isinstance(prepared, PreparedAccess):
        return _unsupported('a type="proof" credential needs the binding a confirmed activation writes')
    return {"outcome": "accept"}


async def _verify_active(inp: dict[str, Any]) -> dict[str, Any]:
    server, rpc = _server(inp)
    active = inp["subscriptionActive"]
    try:
        subscriber = parse_pubkey(_str(active, "subscriber"), "subscriber")
        await server.verify_active_subscription(subscriber, _str(active, "amount"), now=_now(inp))
    except Rejection:
        raise
    except Exception as exc:  # noqa: BLE001 - classified by message
        raise Rejection(str(exc), classify(str(exc)) or "subscription-inactive") from exc
    finally:
        await rpc.aclose()
    return {"outcome": "accept"}


def _verify_proof(inp: dict[str, Any]) -> dict[str, Any]:
    p = inp["subscriptionProof"]
    try:
        authentication = SubscriptionAuthentication.from_dict(p.get("authentication"))
    except ValueError as exc:
        raise Rejection(f"invalid authentication: {exc}", "authentication-invalid") from exc
    try:
        valid = authentication.verify(_str(p, "subscriptionDelegation"))
    except ValueError as exc:
        raise Rejection(str(exc), "authentication-invalid") from exc
    if not valid:
        raise Rejection(
            "the proof signature does not verify over the canonical message",
            "authentication-invalid",
        )
    return {"outcome": "accept"}


def _dispatch(mode: str, inp: dict[str, Any]) -> dict[str, Any]:
    if mode == "canonical-bytes":
        return _canonical(inp)
    if mode == "build-transaction":
        return asyncio.run(_build(inp))
    if mode == "verify-transaction":
        if "subscriptionAuthorization" in inp:
            return asyncio.run(_verify_activation(inp))
        if "subscriptionActive" in inp:
            return asyncio.run(_verify_active(inp))
        if "subscriptionProof" in inp:
            return _verify_proof(inp)
        return _unsupported("subscription verify input carries no credential")
    return _unsupported(f'no Python runner path for intent "subscription" mode {mode!r}')


def run(vector: dict[str, Any]) -> dict[str, Any]:
    """One ``subscription`` vector to a RunnerResult."""
    vector_id = vector.get("id", "")
    try:
        result = _dispatch(str(vector.get("mode")), vector.get("input") or {})
    except Rejection as exc:
        result = {"outcome": "reject", "error": str(exc)}
        if exc.code is not None:
            result["rejectCode"] = exc.code
    except Exception as exc:  # noqa: BLE001 - an unclassified SDK refusal
        result = {"outcome": "reject", "error": str(exc)}
    return {"id": vector_id, **result}


def classify(message: str) -> str | None:
    """The shared reject category of an SDK subscription error message.

    The same table as the Rust testee's ``classify``.
    """
    m = message.lower()

    def has(needle: str) -> bool:
        return needle in m

    def any_of(*needles: str) -> bool:
        return any(needle in m for needle in needles)

    if has("network does not match") or has("network mismatch"):
        return "wrong-network"
    if any_of(
        "hmac mismatch",
        "did not issue",
        "was not issued by this server",
        "does not match this server",
        "is not a subscription",
        "terms do not match",
        "does not match this route",
    ):
        return "challenge-mismatch"
    if any_of("challenge has expired", "challenge expired"):
        return "challenge-expired"
    if any_of("subscription has expired", "subscription expired"):
        return "subscription-expired"
    if any_of(
        "authentication proof",
        "proof challengeid does not match",
        "proof payer does not match",
        "missing authentication",
        "authentication.type",
        "authentication is required",
    ):
        return "authentication-invalid"
    if any_of("receiver does not match", "transfer_subscription accounts do not match"):
        return "recipient-mismatch"
    if has("source") and (has("does not match") or has("did:pkh")):
        return "source-mismatch"
    if any_of("fee payer must be", "fee payer pubkey not present", "fee-payer signer does not match"):
        return "fee-payer-mismatch"
    if has("compute unit limit exceeds"):
        return "compute-limit-over-cap"
    if has("compute unit price exceeds"):
        return "compute-price-over-cap"
    if any_of(
        "unsupported program",
        "multiple subscribe",
        "multiple transfer_subscription",
        "multiple initialize_subscription_authority",
        "initialize_subscription_authority is not allowed",
        "idempotent",
        "ata creation",
        "unsupported subscriptions instruction",
        "unsupported compute-budget",
        "multiple memo",
        "multiple compute-unit",
    ):
        return "unexpected-instruction"
    if any_of(
        "missing subscribe",
        "missing transfer_subscription",
        "subscribe must precede",
        "subscribe accounts do not match",
        "transfer_subscription data does not match",
        "transfer_subscription amount does not match",
        "transfer_subscription delegator does not match",
        "transfer_subscription mint does not match",
        "memo does not match",
        "missing challenge externalid memo",
        "signers must be exactly",
    ):
        return "activation-scope"
    if any_of(
        "not paid for the current billing period",
        "cancellation has taken effect",
        "authority has been invalidated",
        "subscriptionauthority account",
        "subscriptiondelegation account",
        "does not match the bound plan and payer",
        "owner mismatch",
        "subscriptiondelegation discriminator",
        "subscriptiondelegation length",
    ):
        return "subscription-inactive"
    if any_of(
        "invalid subscription challenge",
        "requires feepayerkey",
        "feepayerkey is required",
        "untrusted subscription program",
        "currency must match",
        "must match amount",
        "must match recipient",
        "does not match the challenge",
        "plan owner does not match",
        "plan account not found",
        "invalid recentblockhash",
        "pubkey",
        "periodcount",
        "period_hours",
        "periodunit",
        "methoddetails",
        "invalid amount",
    ):
        return "invalid-challenge"
    if any_of(
        "push-mode",
        "unsupported payload type",
        "payload type",
        "missing `transaction`",
        "missing transaction",
        "failed to decode",
        "tx decode",
        "invalid transaction",
        "could not identify subscriber",
        "subscriber cannot",
        "does not verify",
        "cannot be used with fee sponsorship",
    ):
        return "invalid-payload"
    return None
