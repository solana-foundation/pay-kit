"""Cross-language harness adapter for the Python solana_pay_kit MPP ``charge`` client.

Mirrors the TypeScript spine harness client
(``harness/src/fixtures/typescript/charge-client.ts``): GET the target, parse the
``WWW-Authenticate: Payment`` challenge, build the ``Authorization`` credential
from the offer the server advertised, GET again with it, then print exactly one
result JSON line to stdout. All diagnostics go to stderr.

The adapter is deliberately generic. Splits, decimals, token program, and
whether the asset is SPL or native SOL all arrive inside the server's
``request`` payload, so one code path covers ``charge-basic``,
``charge-split-ata``, ``charge-token2022-split-ata``, ``charge-decimals-9``,
``charge-sol-native``, ``charge-symbol-usdc-localnet``, and
``charge-split-ata-idempotent``.

The flow is spelled out rather than delegated to ``PaymentTransport`` on
purpose. That transport swallows credential-build failures and returns the
original 402 (``protocols/mpp/client/transport.py``), which would let a broken
build masquerade as a legitimate challenge rejection. Here a build failure
surfaces as ``status: 0`` with an ``error`` field, so the harness sees a real
fixture failure instead of a false green.

Pull mode only. In pull mode the client signs just its own slot of a
partially-signed v0 transaction and the server broadcasts and cosigns the
fee-payer slot. Push mode has no client implementation in the Python SDK --
``build_credential_header`` always emits a ``type=transaction`` payload -- so a
push request is refused loudly rather than silently downgraded to pull.

Env contract (shared with the rust/ts/go charge clients):

* ``MPP_HARNESS_TARGET_URL``        - required, the gated resource URL.
* ``MPP_HARNESS_RPC_URL``           - required, Solana RPC. Live in practice: the
  MPP server does not stamp ``methodDetails.recentBlockhash``, so the builder
  falls back to ``getLatestBlockhash`` at ``confirmed`` commitment.
* ``MPP_HARNESS_CLIENT_SECRET_KEY`` - required, JSON int array (solders Keypair).
* ``MPP_HARNESS_PAYMENT_MODE``      - optional, ``pull`` (default) or ``push``.
* ``MPP_HARNESS_SETTLEMENT_HEADER`` - optional, receipt header name.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement"
CHARGE_INTENT = "charge"


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

import httpx  # noqa: E402
from solana.rpc.async_api import AsyncClient  # type: ignore[import-untyped]  # noqa: E402
from solders.keypair import Keypair  # type: ignore[import-untyped]  # noqa: E402

from solana_pay_kit.protocols.mpp.client.charge import (  # noqa: E402
    build_credential_header,
)
from solana_pay_kit.protocols.mpp.core.headers import (  # noqa: E402
    parse_www_authenticate_all,
)
from solana_pay_kit.protocols.mpp.core.types import PaymentChallenge  # noqa: E402


class _MintOwnerRpc:
    """Adapter-side shim exposing the account lookup the charge client calls.

    ``protocols.mpp.client.charge._fetch_mint_owner`` calls
    ``rpc_client.get_account(...)`` -- the Rust-shaped name. solana-py's
    ``AsyncClient`` has no such method; it is ``get_account_info``. Because the
    charge challenge never stamps ``methodDetails.tokenProgram``,
    ``_resolve_token_program`` consults the chain on every scenario, so passing
    a bare ``AsyncClient`` raises ``AttributeError`` before the first hop.

    Keeping the workaround here rather than in the SDK keeps this adapter PR
    scoped to the harness. Delete this class once the SDK calls
    ``get_account_info``; see the bug write-up on this PR.
    """

    def __init__(self, client: AsyncClient) -> None:
        self._client = client

    async def get_account(self, pubkey: Any) -> Any:
        return await self._client.get_account_info(pubkey)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"{name} is required", file=sys.stderr)
        sys.exit(2)
    return value


def _parse_body(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _emit(result: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()


def _emit_failure(error: str, status: int = 0, headers: dict[str, str] | None = None) -> None:
    _emit(
        {
            "type": "result",
            "implementation": "python",
            "role": "client",
            "ok": False,
            "status": status,
            "responseHeaders": headers or {},
            "responseBody": None,
            "settlement": None,
            "error": error,
        }
    )


def _select_charge_challenge(
    challenges: list[PaymentChallenge],
) -> PaymentChallenge | None:
    """Pick the ``charge`` challenge from the advertised set.

    The harness servers mount a single method, but selecting on the parsed
    ``intent`` rather than taking ``challenges[0]`` keeps this honest if a
    server ever advertises more than one.
    """
    for challenge in challenges:
        if challenge.intent == CHARGE_INTENT:
            return challenge
    return None


async def _run() -> None:
    target_url = _require_env("MPP_HARNESS_TARGET_URL")
    rpc_url = _require_env("MPP_HARNESS_RPC_URL")
    secret = _require_env("MPP_HARNESS_CLIENT_SECRET_KEY")
    settlement_header = os.environ.get("MPP_HARNESS_SETTLEMENT_HEADER") or DEFAULT_SETTLEMENT_HEADER

    if (os.environ.get("MPP_HARNESS_PAYMENT_MODE") or "pull").lower() == "push":
        _emit_failure(
            "push payment mode has no client implementation in the Python SDK "
            "(build_credential_header always emits a type=transaction payload); "
            "refusing to downgrade to pull"
        )
        return

    signer = Keypair.from_json(secret)
    rpc = AsyncClient(rpc_url)
    try:
        async with httpx.AsyncClient(timeout=60.0) as http:
            challenge_response = await http.get(target_url)
            advertised = parse_www_authenticate_all(challenge_response.headers.get_list("www-authenticate"))
            challenge = _select_charge_challenge(advertised)
            if challenge is None:
                seen = ", ".join(sorted({item.intent or "<none>" for item in advertised})) or "none"
                _emit_failure(
                    "target did not advertise a solana charge challenge "
                    f"(status={challenge_response.status_code}, intents advertised: {seen})",
                    status=challenge_response.status_code,
                    headers={k: v for k, v in challenge_response.headers.items()},
                )
                return

            authorization = await build_credential_header(
                signer=signer,
                rpc_client=_MintOwnerRpc(rpc),
                challenge=challenge,
                # Audit #26 opts the unknown-Token-2022 check out. The harness
                # deploys its own mints on a local validator, so the
                # token2022 scenario's mint is never a known stablecoin; the
                # transfer-hook risk this guard covers does not apply to it.
                allow_unknown_token_2022=True,
            )

            paid = await http.get(target_url, headers={"authorization": authorization})
    finally:
        await rpc.close()

    headers = {k: v for k, v in paid.headers.items()}
    # Echoed for parity with the x402 adapter (``Payment-Signature-sent``): when
    # a cross-language leg fails, the credential the client actually sent is the
    # fastest way to tell a client encoding bug from a server rejection.
    headers["authorization-sent"] = authorization

    _emit(
        {
            "type": "result",
            "implementation": "python",
            "role": "client",
            "ok": paid.is_success,
            "status": paid.status_code,
            "responseHeaders": headers,
            "responseBody": _parse_body(paid.text),
            "settlement": headers.get(settlement_header),
        }
    )


def main() -> None:
    try:
        asyncio.run(_run())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - emit a structured failure line
        _emit_failure(str(exc))


if __name__ == "__main__":
    main()
