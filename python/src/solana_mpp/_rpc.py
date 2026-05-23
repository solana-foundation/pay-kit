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
from typing import Any

import httpx

from solana_mpp._errors import PaymentError


class _RpcError(PaymentError):
    """JSON-RPC level error from a Solana node."""


class SolanaRpc:
    """Minimal async JSON-RPC client for the Solana RPC API."""

    def __init__(self, endpoint: str, timeout: float = 30.0) -> None:
        self._endpoint = endpoint
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
        self._id = 0

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
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

        class _Resp:
            def __init__(self, value):
                self.value = value

        return _Resp(signature)

    async def get_signature_statuses(self, signatures: list[str]) -> list[Any]:
        result = await self._call("getSignatureStatuses", [signatures, {"searchTransactionHistory": False}])
        return (result or {}).get("value") or []

    async def confirm_transaction(self, signature: Any, *_args: Any, **_kwargs: Any) -> Any:
        """Match the solana-py AsyncClient.confirm_transaction signature shape."""

        class _Resp:
            def __init__(self, value):
                self.value = value

        for _ in range(40):
            statuses = await self.get_signature_statuses([str(signature)])
            status = statuses[0] if statuses else None
            if isinstance(status, dict) and status.get("confirmationStatus") in {"confirmed", "finalized"}:
                return _Resp([{"err": status.get("err")}])
            await asyncio.sleep(0.25)
        return _Resp([{"err": "timeout"}])

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

        class _Resp:
            def __init__(self, value):
                self.value = value

        return _Resp(result)

    async def await_confirmation(
        self,
        signature: str,
        attempts: int = 40,
        delay_seconds: float = 0.25,
    ) -> None:
        """Poll getSignatureStatuses until the signature reaches at least
        confirmed. Raises PaymentError on on-chain failure or timeout."""
        for _ in range(attempts):
            statuses = await self.get_signature_statuses([signature])
            status = statuses[0] if statuses else None
            if isinstance(status, dict):
                err = status.get("err")
                if err is not None:
                    raise PaymentError(
                        f"transaction {signature} failed: {err}",
                        code="payment_invalid",
                    )
                if status.get("confirmationStatus") in {"confirmed", "finalized"}:
                    return
            await asyncio.sleep(delay_seconds)
        raise PaymentError(
            f"timed out awaiting confirmation for {signature}",
            code="payment_invalid",
        )
