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
from typing import Any

import httpx

from pay_kit._paycore.errors import PaymentError


class _RpcError(PaymentError):
    """JSON-RPC level error from a Solana node."""


class _RpcResponse:
    """Minimal value-wrapper matching the ``solana-py`` AsyncClient
    response shape that the rest of the codebase expects (``.value``
    attribute access). Extracted to module level so the same wrapper
    is reused by ``send_raw_transaction``, ``get_transaction``, and the
    legacy ``confirm_transaction`` shim instead of being redeclared
    inside each method body.
    """

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


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
        omits ``extra.recentBlockhash``. Returns ``resp.value.blockhash``."""
        result = await self._call("getLatestBlockhash", [{"commitment": commitment}])
        blockhash = ((result or {}).get("value") or {}).get("blockhash") if isinstance(result, dict) else None
        if not isinstance(blockhash, str) or not blockhash:
            raise _RpcError("getLatestBlockhash returned no blockhash", code="payment_invalid")
        return _RpcResponse(_BlockhashValue(blockhash))

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
