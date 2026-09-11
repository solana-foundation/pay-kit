"""Thin async Solana JSON-RPC client.

The ``solana-py`` package depends on ``solders`` for response parsing; some
``sendTransaction`` failure paths panic inside the Rust extension on
unexpected error shapes (observed against Surfpool 1.1.1: ``missing field
'data'`` panic when an InstructionError surfaces). We bypass solders here
and parse the JSON-RPC envelope directly so the Python server never crashes
the request thread on an upstream error.

This module intentionally implements only the methods the server needs:

* ``send_raw_transaction``
* ``get_signature_statuses``
* ``get_transaction``

For anything else, callers can continue to use ``solana.rpc.async_api``.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import httpx

from solana_pay_kit._paycore.errors import PaymentError


class _RpcError(PaymentError):
    """JSON-RPC level error from a Solana node."""


class MalformedAccountError(_RpcError):
    """``getAccountInfo`` answered with an account object this client cannot
    read: no non-empty ``owner`` string, or a ``data`` field of an unexpected
    shape. The account is VISIBLE, so this is an answer and not replica lag -
    callers must fail on it rather than re-read."""


class _RpcResponse:
    """Minimal value-wrapper matching the ``solana-py`` AsyncClient
    response shape that the rest of the codebase expects (``.value``
    attribute access, plus ``.context.slot`` where the RPC envelope
    carries one). Extracted to module level so the same wrapper
    is reused by ``send_raw_transaction``, ``get_transaction``, and the
    legacy ``confirm_transaction`` shim instead of being redeclared
    inside each method body.
    """

    __slots__ = ("context", "value")

    def __init__(self, value: Any, context: _RpcContext | None = None) -> None:
        self.value = value
        self.context = context


class _RpcContext:
    """``.slot`` holder matching the ``solana-py`` response ``context`` shape.

    ``get_latest_blockhash`` exposes it so challenge issuance can take the
    current slot (the channel ``recentSlot``) from the same RPC response as
    the blockhash instead of issuing a separate ``getSlot`` call."""

    __slots__ = ("slot",)

    def __init__(self, slot: int | None) -> None:
        self.slot = slot


class _BlockhashValue:
    """``.blockhash`` holder so ``get_latest_blockhash().value.blockhash``
    matches the ``solana-py`` / solders response shape the x402 client reads."""

    __slots__ = ("blockhash",)

    def __init__(self, blockhash: str) -> None:
        self.blockhash = blockhash


class SolanaRpc:
    """Minimal async JSON-RPC client for the Solana RPC API."""

    def __init__(self, endpoint: str, timeout: float = 30.0) -> None:
        self._endpoint = endpoint
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
        # ``itertools.count`` returns unique integers atomically at the C
        # level under the GIL, so concurrent ``_call`` invocations on
        # different event loops never collide on the same JSON-RPC id.
        # An ``asyncio.Lock`` would not work here because each loop holds
        # its own lock state; the GIL-backed counter is loop-agnostic.
        self._id_counter = itertools.count(1)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, params: list[Any]) -> Any:
        rpc_id = next(self._id_counter)
        body = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
        response = await self._client.post(self._endpoint, json=body)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            err = data["error"]
            raise _RpcError(str(err.get("message") or err), code="payment_invalid")
        return data.get("result")

    async def send_raw_transaction(self, raw_tx: bytes) -> Any:
        encoded = base64.b64encode(raw_tx).decode("ascii")
        signature = await self._call(
            "sendTransaction",
            [encoded, {"encoding": "base64", "skipPreflight": False, "preflightCommitment": "confirmed"}],
        )
        # A non-compliant RPC proxy may return {"result": null} or a non-string
        # body. Validate before the caller writes the signature to the durable
        # replay store; a "None"-keyed entry would persist forever as garbage.
        if not isinstance(signature, str) or not signature.strip():
            raise _RpcError(
                "sendTransaction returned empty or non-string signature",
                code="payment_invalid",
            )

        return _RpcResponse(signature)

    async def get_latest_blockhash(self, commitment: str = "confirmed") -> _RpcResponse:
        """Fetch the latest blockhash. Used by the x402 client when an offer
        omits ``extra.recentBlockhash``. Returns ``resp.value.blockhash``, and
        exposes the envelope's current slot as ``resp.context.slot`` (``None``
        when the endpoint omits it) so challenge issuance can stamp
        ``recentSlot`` without a separate ``getSlot`` round-trip."""
        result = await self._call("getLatestBlockhash", [{"commitment": commitment}])
        blockhash = ((result or {}).get("value") or {}).get("blockhash") if isinstance(result, dict) else None
        if not isinstance(blockhash, str) or not blockhash:
            raise _RpcError("getLatestBlockhash returned no blockhash", code="payment_invalid")
        slot = ((result or {}).get("context") or {}).get("slot") if isinstance(result, dict) else None
        if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
            slot = None
        return _RpcResponse(_BlockhashValue(blockhash), context=_RpcContext(slot))

    async def get_slot(self, commitment: str = "confirmed") -> int:
        """Fetch the current slot. Used by SERVERS at challenge-issuance time:
        the program requires ``openSlot <= clock.slot`` with a 1500-slot
        freshness window, so the server stamps the challenge ``recentSlot``
        with the current slot (normally taken from the ``getLatestBlockhash``
        response context; this call is the fallback when a response lacks it).
        Clients take the channel ``openSlot`` from the challenge — they never
        fetch the slot themselves."""
        result = await self._call("getSlot", [{"commitment": commitment}])
        if not isinstance(result, int) or result < 0:
            raise _RpcError("getSlot returned a non-integer slot", code="payment_invalid")
        return result

    async def get_account_info(self, address: str, commitment: str = "confirmed") -> tuple[bytes, str] | None:
        """Fetch an account's raw data bytes and owner (base58), or ``None`` when
        the envelope carried no account object. Used to read on-chain
        payment-channel state during x402 ``upto`` verification; the generated
        ``Channel.decode`` then parses the returned bytes.

        ``None`` means one thing only: the account is not there. A genuinely
        absent account and one a lagging replica has not seen yet answer the
        same way, so ``None`` is the single read a caller may retry. A VISIBLE
        account this client cannot read raises :class:`MalformedAccountError`,
        which the caller must fail on straight away.
        """
        result = await self._call("getAccountInfo", [address, {"encoding": "base64", "commitment": commitment}])
        value = (result or {}).get("value") if isinstance(result, dict) else None
        if not isinstance(value, dict):
            return None
        owner = value.get("owner")
        if not isinstance(owner, str) or not owner:
            raise MalformedAccountError("getAccountInfo returned an account with no owner", code="payment_invalid")
        data_field = value.get("data")
        if isinstance(data_field, list) and data_field and isinstance(data_field[0], str):
            raw = base64.b64decode(data_field[0])
        elif isinstance(data_field, str):
            raw = base64.b64decode(data_field)
        else:
            raise MalformedAccountError(
                "getAccountInfo returned an account with an unreadable data field", code="payment_invalid"
            )
        return raw, owner

    async def get_signature_statuses(self, signatures: list[str]) -> list[Any]:
        result = await self._call("getSignatureStatuses", [signatures, {"searchTransactionHistory": False}])
        return (result or {}).get("value") or []

    async def confirm_transaction(self, signature: Any, *_args: Any, **_kwargs: Any) -> Any:
        """Compatibility shim matching the ``solana-py`` AsyncClient
        ``confirm_transaction`` shape. Not used on the production
        settlement path (the server uses ``await_confirmation`` with
        discriminated error codes); kept so embedders that bind a
        legacy ``solana.rpc.async_api.AsyncClient``-compatible interface
        still get the expected response shape.
        """
        for _ in range(40):
            statuses = await self.get_signature_statuses([str(signature)])
            status = statuses[0] if statuses else None
            if isinstance(status, dict) and status.get("confirmationStatus") in {"confirmed", "finalized"}:
                return _RpcResponse([{"err": status.get("err")}])
            await asyncio.sleep(0.25)
        return _RpcResponse([{"err": "timeout"}])

    async def get_transaction(self, signature: Any, **_kwargs: Any) -> Any:
        result = await self._call(
            "getTransaction",
            [
                str(signature),
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        return _RpcResponse(result)

    async def await_confirmation(
        self,
        signature: str,
        attempts: int = 40,
        delay_seconds: float = 0.25,
    ) -> None:
        """Poll getSignatureStatuses until the signature reaches at least
        confirmed. Raises PaymentError with discriminated codes:

        - ``transaction-failed`` when the cluster reports a non-null
          ``err`` (the transaction was included in a block but reverted).
        - ``transaction-not-found`` when the status never reaches the
          confirmed/finalized threshold inside the polling window.

        Discriminating these two cases lets the caller surface accurate
        diagnostics; the canonical code mapping in ``_errors`` collapses
        both to the same client-facing 402 body, so no client behaviour
        changes.
        """
        for _ in range(attempts):
            statuses = await self.get_signature_statuses([signature])
            status = statuses[0] if statuses else None
            if isinstance(status, dict):
                err = status.get("err")
                if err is not None:
                    raise PaymentError(
                        f"transaction {signature} failed on-chain: {err}",
                        code="transaction-failed",
                    )
                if status.get("confirmationStatus") in {"confirmed", "finalized"}:
                    return
            await asyncio.sleep(delay_seconds)
        raise PaymentError(
            f"timed out awaiting confirmation for {signature}",
            code="transaction-not-found",
        )


# -- channel-read replica lag -----------------------------------------------

# An RPC provider can answer getSignatureStatuses and getAccountInfo from
# different replicas, so an account written by a just-confirmed transaction can
# still read back MISSING on the replica that serves the follow-up read.
# Re-reading absorbs that, and only that: an account that is visible but does
# not say what the caller expected is an answer, not lag.
#
# LINEAR backoff, not exponential: replica lag is a small multiple of Solana's
# ~400ms slot time, so doubling spends the budget on single waits far longer
# than the lag being absorbed. Six attempts at a 200ms step schedule
# 200/400/600/800/1000ms - 3.0s total, 1s maximum single wait.
CHANNEL_READ_ATTEMPTS = 6
CHANNEL_READ_BACKOFF_STEP_SECONDS = 0.2

_T = TypeVar("_T")


def resolve_channel_read_policy(
    max_attempts: int | None,
    backoff_step_ms: int | None,
) -> tuple[int, float]:
    """Resolve the optional channel-read knobs to ``(attempts, step_seconds)``.

    Unset or non-positive takes the default, so a caller may pass a zero value
    (an unset field in a language without optionals) without disabling the
    retry.
    """
    attempts = CHANNEL_READ_ATTEMPTS
    if not isinstance(max_attempts, bool) and isinstance(max_attempts, int) and max_attempts > 0:
        attempts = max_attempts
    step_seconds = CHANNEL_READ_BACKOFF_STEP_SECONDS
    if not isinstance(backoff_step_ms, bool) and isinstance(backoff_step_ms, int) and backoff_step_ms > 0:
        step_seconds = backoff_step_ms / 1000
    return attempts, step_seconds


async def read_with_replica_retry(
    read: Callable[[], Awaitable[_T]],
    attempts: int = CHANNEL_READ_ATTEMPTS,
    backoff_step_seconds: float = CHANNEL_READ_BACKOFF_STEP_SECONDS,
) -> _T:
    """Re-read until the read returns something (``value is not None``).

    The not-yet-visible read is the ONLY lag symptom this absorbs, and there is
    deliberately no hook to widen it. A visible-but-wrong value is an answer,
    not lag: it is returned straight away and the caller raises on that first
    observation. Re-sampling a wrong-but-visible value over the backoff window
    can only ever flip reject into accept, on state a concurrent writer may
    have moved in the meantime. Anything ``read`` raises propagates immediately
    and is never retried.

    The last read is returned as-is once ``attempts`` is exhausted, so the
    caller keeps its own error for the still-invisible case. Sleeps only
    *between* attempts: the wait before attempt N+1 is
    ``backoff_step_seconds * N``, and there is no sleep after the final
    attempt.
    """
    attempt = 1
    while True:
        value = await read()
        if attempt >= attempts or value is not None:
            return value
        await asyncio.sleep(backoff_step_seconds * attempt)
        attempt += 1
