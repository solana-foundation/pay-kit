"""Cross-language harness adapter for the Python PayKit umbrella surface.

One TCP server, two settle paths (x402:exact and mpp:charge), picked per
scenario by which env namespace the harness orchestrator sets (or by the
explicit ``PAY_KIT_HARNESS_PROTOCOL`` hint). Mirrors ``harness/php-server/
server.php`` and the Ruby/Lua pay-kit-server pattern.

This adapter routes every request through the unified ``pay_kit`` surface:

  * x402 exact  -> ``pay_kit.protocols.x402.X402Adapter`` (the umbrella adapter)
  * MPP charge  -> ``pay_kit.protocols.mpp.server.charge.Mpp`` (the lower-level wire)

This split mirrors the canonical PHP adapter (``harness/php-server/
server.php``): x402 routes through the umbrella adapter, while MPP charge
routes through the lower-level ``pay_kit.protocols.mpp`` handler. The umbrella's
ticker-based currency model (``Stablecoin`` enum -> ``Mints.resolve``) is the
right surface for x402, where the offer's ``asset`` is the resolved on-chain
mint; but the harness MPP charge matrix runs in *pubkey mode* (the harness
deploys the scenario mint at an arbitrary ``MPP_HARNESS_MINT`` pubkey, not the
canonical USDC mint), so the MPP challenge must advertise that literal mint as
its ``currency``. The lower-level ``pay_kit.protocols.mpp`` handler takes the raw mint
directly, exactly as the PHP ``SolanaChargeHandler`` path does.

Cross-route replay protection on the MPP path is enforced by
``Mpp.verify_credential_with_expected`` (pins amount/currency/recipient per
route); the x402 path pins via ``X402Adapter``'s offer-equality gate.

Stdout discipline: ONLY the ``ready`` JSON line is written to stdout. All
diagnostics go to stderr.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

from pay_kit import (  # noqa: E402
    Config,
    Gate,
    Network,
    Operator,
    Price,
    Protocol,
    Signer,
    Stablecoin,
)
from pay_kit._paycore.errors import PaymentError, canonical_code  # noqa: E402
from pay_kit._paycore.rpc import SolanaRpc  # noqa: E402
from pay_kit._paycore.store import MemoryStore  # noqa: E402
from pay_kit.errors import InvalidProofError  # noqa: E402
from pay_kit.protocols.mpp.core.headers import format_www_authenticate, parse_authorization, parse_receipt  # noqa: E402
from pay_kit.protocols.mpp.intents.charge import ChargeRequest  # noqa: E402
from pay_kit.protocols.mpp.server import (  # noqa: E402
    SessionChallengeOptions,
    SessionOptions,
    new_session,
    session_routes,
)
from pay_kit.protocols.mpp.server.charge import (  # noqa: E402
    ChargeOptions,
    Mpp,
)
from pay_kit.protocols.mpp.server.charge import Config as MppServerConfig  # noqa: E402
from pay_kit.protocols.x402 import X402Adapter  # noqa: E402


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def optional_env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _resolve_network(raw: str) -> Network:
    """Map the harness network string to a pay_kit Network enum.

    Charge scenarios send the short slug ``localnet``; x402 scenarios send a
    CAIP-2 string (``solana:<genesis>``). Mirrors PHP ``resolve_network``.
    """
    if raw.startswith("solana:"):
        if raw == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":
            return Network.SOLANA_MAINNET
        # Devnet genesis and any other CAIP-2 fall to devnet (the localnet
        # surfpool fixtures are funded under the devnet genesis hash).
        return Network.SOLANA_DEVNET
    return {
        "mainnet": Network.SOLANA_MAINNET,
        "devnet": Network.SOLANA_DEVNET,
    }.get(raw, Network.SOLANA_LOCALNET)


def _base_units_to_human(base_units: str, decimals: int) -> str:
    """Convert a base-units string (e.g. ``"1000"``) into a decimal string."""
    if decimals <= 0:
        return str(int(base_units))
    units = int(base_units)
    sign = "-" if units < 0 else ""
    units = abs(units)
    quotient, remainder = divmod(units, 10**decimals)
    fraction = f"{remainder:0{decimals}d}".rstrip("0")
    if not fraction:
        return f"{sign}{quotient}"
    return f"{sign}{quotient}.{fraction}"


def _coin_for_mint(mint: str) -> Stablecoin:
    """Pick the settlement Stablecoin for the scenario mint.

    The harness sends an on-chain mint pubkey (pubkey mode) or a ticker
    (symbol mode). The harness matrix's stablecoin is USDC; map any ticker we
    recognise, else default to USDC. The on-chain mint is asserted by the
    harness from the SDK's own resolver, so the ticker only selects which
    6-decimal coin the offer advertises.
    """
    try:
        return Stablecoin(mint)
    except ValueError:
        return Stablecoin.USDC


def _detect_protocol() -> str:
    """Decide which protocol this run exercises (mirror PHP detection)."""
    explicit = optional_env("PAY_KIT_HARNESS_PROTOCOL", "").lower()
    if explicit in ("x402", "mpp", "charge", "session"):
        return "mpp" if explicit == "charge" else explicit
    x402_set = bool(os.environ.get("X402_HARNESS_RPC_URL"))
    mpp_set = bool(os.environ.get("MPP_HARNESS_RPC_URL"))
    if x402_set == mpp_set:
        print(
            "set exactly one of X402_HARNESS_RPC_URL / MPP_HARNESS_RPC_URL, or set PAY_KIT_HARNESS_PROTOCOL",
            file=sys.stderr,
        )
        sys.exit(2)
    return "x402" if x402_set else "mpp"


class _Adapter:
    """Holds the built pay_kit adapter plus per-route gate amounts."""

    def __init__(self) -> None:
        self.protocol = _detect_protocol()
        self.x402 = self.protocol == "x402"
        if self.protocol == "x402":
            self._build_x402()
        elif self.protocol == "session":
            self._build_session()
        else:
            self._build_mpp()

    # -- x402 -----------------------------------------------------------------

    def _build_x402(self) -> None:
        rpc_url = require_env("X402_HARNESS_RPC_URL")
        pay_to = require_env("X402_HARNESS_PAY_TO")
        facilitator_json = require_env("X402_HARNESS_FACILITATOR_SECRET_KEY")
        amount_units = optional_env("X402_HARNESS_AMOUNT", "1000")
        mint = optional_env("X402_HARNESS_MINT", "USDC")
        network_raw = optional_env("X402_HARNESS_NETWORK", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
        self.resource_path = optional_env("X402_HARNESS_RESOURCE_PATH", "/protected")
        self.settlement_header = optional_env("X402_HARNESS_SETTLEMENT_HEADER", "x-fixture-settlement").lower()
        self.coin = _coin_for_mint(mint)

        signer = Signer.json(facilitator_json)
        config = Config(
            network=_resolve_network(network_raw),
            accept=(Protocol.X402,),
            stablecoins=(self.coin,),
            rpc_url=rpc_url,
            operator=Operator(recipient=pay_to, signer=signer, fee_payer=True),
            preflight=False,
        ).model_copy()
        self.config = config
        self.adapter = X402Adapter(config)
        self.pay_to = pay_to
        decimals = int(optional_env("X402_HARNESS_DECIMALS", "6"))
        self.routes = {self.resource_path: _base_units_to_human(amount_units, decimals)}
        self.replay_path = ""

    # -- mpp ------------------------------------------------------------------

    def _build_mpp(self) -> None:
        self.rpc_url = require_env("MPP_HARNESS_RPC_URL")
        pay_to = require_env("MPP_HARNESS_PAY_TO")
        # Pubkey mode: the literal scenario mint pubkey is the MPP currency.
        self.mint = require_env("MPP_HARNESS_MINT")
        amount_units = require_env("MPP_HARNESS_AMOUNT")
        secret = optional_env("MPP_HARNESS_SECRET_KEY", "mpp-harness-secret-key")
        network_raw = optional_env("MPP_HARNESS_NETWORK", "localnet")
        self.resource_path = optional_env("MPP_HARNESS_RESOURCE_PATH", "/paid")
        self.settlement_header = optional_env("MPP_HARNESS_SETTLEMENT_HEADER", "x-payment-settlement-signature").lower()
        realm = optional_env("MPP_HARNESS_REALM", "MPP Harness")
        self.splits = json.loads(optional_env("MPP_HARNESS_SPLITS", "[]"))
        if not isinstance(self.splits, list):
            print("MPP_HARNESS_SPLITS must decode to a JSON array", file=sys.stderr)
            sys.exit(2)

        fee_payer = None
        fee_payer_raw = os.environ.get("MPP_HARNESS_FEE_PAYER_SECRET_KEY")
        if fee_payer_raw:
            from solders.keypair import Keypair

            fee_payer = Keypair.from_bytes(bytes(json.loads(fee_payer_raw)))
        self.fee_payer = fee_payer

        # Build the lower-level pay_kit.protocols.mpp handler with the raw mint. The
        # ``Mpp`` server boots with ``rpc=None``; a request-lifetime
        # ``SolanaRpc`` is scoped via ``using_rpc`` in the request path.
        config = MppServerConfig(
            recipient=pay_to,
            currency=self.mint,
            decimals=int(optional_env("MPP_HARNESS_DECIMALS", "6")),
            network=network_raw,
            rpc_url=self.rpc_url,
            secret_key=secret,
            realm=realm,
            fee_payer_signer=fee_payer,
            store=MemoryStore(),
            rpc=None,
        )
        self.handler = Mpp(config)
        self.pay_to = pay_to

        decimals = int(optional_env("MPP_HARNESS_DECIMALS", "6"))
        self.routes = {self.resource_path: _base_units_to_human(amount_units, decimals)}
        replay_path = os.environ.get("MPP_HARNESS_REPLAY_SOURCE_PATH") or ""
        if replay_path:
            replay_amount = os.environ.get("MPP_HARNESS_REPLAY_SOURCE_AMOUNT") or amount_units
            self.routes[replay_path] = _base_units_to_human(replay_amount, decimals)
        self.replay_path = replay_path

    def _build_session(self) -> None:
        self.rpc_url = require_env("MPP_HARNESS_RPC_URL")
        pay_to = require_env("MPP_HARNESS_PAY_TO")
        amount_units = require_env("MPP_HARNESS_AMOUNT")
        secret = optional_env("MPP_HARNESS_SECRET_KEY", "mpp-harness-secret-key-with-32b-pad")
        network_raw = optional_env("MPP_HARNESS_NETWORK", "localnet")
        self.resource_path = optional_env("MPP_HARNESS_RESOURCE_PATH", "/session")
        self.settlement_header = optional_env("MPP_HARNESS_SETTLEMENT_HEADER", "x-session-settlement-signature").lower()
        fee_payer_raw = require_env("MPP_HARNESS_FEE_PAYER_SECRET_KEY")
        signer = Signer.json(fee_payer_raw)
        self.session_method = new_session(
            SessionOptions(
                operator=signer.pubkey(),
                recipient=pay_to,
                cap=int(amount_units),
                currency=optional_env("MPP_HARNESS_SESSION_CURRENCY", "USDC"),
                decimals=int(optional_env("MPP_HARNESS_DECIMALS", "6")),
                network=network_raw,
                secret_key=secret,
                realm=optional_env("MPP_HARNESS_REALM", "MPP Harness"),
                modes=["pull"],
                pull_voucher_strategy="clientVoucher",
                open_tx_submitter="client",
                signer=signer,
                rpc=None,
            )
        )
        self.session_routes = session_routes(self.session_method.core(), touch=self.session_method._touch)
        self.session_challenge = SessionChallengeOptions(cap=amount_units, description="Harness session")
        decimals = int(optional_env("MPP_HARNESS_DECIMALS", "6"))
        self.routes = {self.resource_path: _base_units_to_human(amount_units, decimals)}
        self.replay_path = ""

    def charge_options(self) -> ChargeOptions:
        options = ChargeOptions(
            description="PayKit Python harness protected content",
            splits=self.splits or [],
        )
        if self.fee_payer is not None:
            options.fee_payer = True
        return options

    # -- x402 gate ------------------------------------------------------------

    def gate_for(self, path: str) -> Gate:
        amount = self.routes[path]
        return Gate.build(
            name=path.lstrip("/") or "root",
            amount=Price.usd(amount, self.coin),
            default_pay_to=self.pay_to,
            accept=(Protocol.X402,),
            description="PayKit Python harness protected content",
        )


class HarnessHandler(BaseHTTPRequestHandler):
    server_version = "python-harness/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    @property
    def adapter(self) -> _Adapter:
        return self.server.adapter  # type: ignore[attr-defined]

    def _send_json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        headers = {"content-type": "application/json"}
        if extra_headers:
            for name, value in extra_headers.items():
                headers[name.lower()] = value
        headers["content-length"] = str(len(payload))
        headers["connection"] = "close"
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _request_bag(self) -> dict[str, Any]:
        # Build the framework-agnostic request bag both adapters accept
        # (``.headers``-style getter and ``path``). Header names are
        # lower-cased so the adapters' case-tolerant lookups hit.
        headers = {name.lower(): value for name, value in self.headers.items()}
        return {"headers": headers, "path": self.path}

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json(200, {"ok": True})
            return

        adapter = self.adapter
        if adapter.protocol == "session" and self.path == adapter.resource_path:
            self._handle_session(adapter)
            return
        if self.path not in adapter.routes:
            self._send_json(404, {"error": "not_found"})
            return

        request = self._request_bag()

        if adapter.x402:
            self._handle_x402(adapter, adapter.gate_for(self.path), request)
        else:
            self._handle_mpp(adapter, request)

    def do_POST(self) -> None:  # noqa: N802
        adapter = self.adapter
        if adapter.protocol == "session":
            if self.path == adapter.resource_path:
                self._handle_session(adapter)
                return
            raw = self.rfile.read(int(self.headers.get("content-length", "0") or "0"))
            if self.path == "/__402/session/deliveries":
                response = asyncio.run(adapter.session_routes.deliveries("POST", raw or b"{}"))
                self._send_json(response.status, response.body)
                return
            if self.path == "/__402/session/commit":
                response = asyncio.run(adapter.session_routes.commit("POST", raw or b"{}"))
                self._send_json(response.status, response.body)
                return
            if self.path == "/__402/session/close":
                self._handle_session(adapter)
                return
        self._send_json(404, {"error": "not_found"})

    def _handle_x402(self, adapter: _Adapter, gate: Gate, request: dict[str, Any]) -> None:
        if not request["headers"].get("payment-signature"):
            challenge_headers = adapter.adapter.challenge_headers(gate, request)
            accepts = adapter.adapter.accepts_entry(gate, request)
            self._send_json(
                402,
                {"error": "payment_required", "resource": self.path, "accepts": [accepts]},
                extra_headers=challenge_headers,
            )
            return
        try:
            payment = asyncio.run(adapter.adapter.verify_and_settle(gate, request))
        except InvalidProofError as err:
            self._send_json(
                402,
                {"error": err.code or "invalid_proof", "code": err.code, "message": str(err)},
                extra_headers=adapter.adapter.challenge_headers(gate, request),
            )
            return
        headers = dict(payment.settlement_headers)
        headers[adapter.settlement_header] = payment.transaction
        self._send_json(
            200,
            {"ok": True, "paid": True, "protocol": "x402", "transaction": payment.transaction},
            extra_headers=headers,
        )

    def _handle_session(self, adapter: _Adapter) -> None:
        auth = self.headers.get("authorization", "")
        result = asyncio.run(adapter.session_method.handle(auth or None, adapter.session_challenge))
        if not result.ok:
            self._send_json(result.status, result.body or {"error": "payment_required"}, extra_headers=result.headers)
            return
        receipt_header = result.headers.get("payment-receipt", "")
        reference = parse_receipt(receipt_header).reference if receipt_header else ""
        body = {"ok": True, "paid": True, "protocol": "session", "reference": reference}
        if reference:
            body["settledSignature"] = reference
        self._send_json(200, body, extra_headers={**result.headers, adapter.settlement_header: reference})

    def _handle_mpp(self, adapter: _Adapter, request: dict[str, Any]) -> None:
        amount = adapter.routes[self.path]
        options = adapter.charge_options()
        auth = request["headers"].get("authorization", "")

        if not auth:
            self._issue_mpp_challenge(adapter, amount, options, message="missing authorization")
            return

        try:
            credential = parse_authorization(auth)
        except Exception as exc:  # noqa: BLE001 - parse errors map to 402
            self._issue_mpp_challenge(
                adapter,
                amount,
                options,
                message=f"could not parse Authorization: {exc}",
                code="payment_invalid",
            )
            return

        try:
            challenge = adapter.handler.charge_with_options(amount, options)
            expected = ChargeRequest.from_dict(challenge.decode_request())

            async def _verify_with_fresh_rpc():
                fresh_rpc = SolanaRpc(adapter.rpc_url)
                try:
                    async with adapter.handler.using_rpc(fresh_rpc):
                        return await adapter.handler.verify_credential_with_expected(credential, expected)
                finally:
                    await fresh_rpc.aclose()

            receipt = asyncio.run(_verify_with_fresh_rpc())
        except PaymentError as err:
            self._issue_mpp_challenge(
                adapter, amount, options, message=str(err) or "verification failed", code=err.code
            )
            return
        except Exception as err:  # noqa: BLE001 framework guard
            print(f"harness python server error: {err}", file=sys.stderr)
            self._issue_mpp_challenge(adapter, amount, options, message=str(err))
            return

        self._send_json(
            200,
            {"ok": True, "paid": True},
            extra_headers={
                "payment-receipt": receipt.reference,
                adapter.settlement_header: receipt.reference,
            },
        )

    def _issue_mpp_challenge(
        self,
        adapter: _Adapter,
        amount: str,
        options: ChargeOptions,
        *,
        message: str = "Payment required",
        code: str = "payment_invalid",
    ) -> None:
        try:
            challenge = adapter.handler.charge_with_options(amount, options)
        except PaymentError as exc:
            # Audit #21 promoted too-many-splits to a refuse-to-issue. The
            # conformance harness expects the 402-class outcome (no challenge to
            # advertise), not a 500. Re-raise anything else.
            if "too many splits" not in str(exc):
                raise
            invalid = canonical_code("payment_invalid")
            self._send_json(
                402,
                {
                    "type": f"https://paymentauth.org/problems/{invalid}",
                    "title": "Payment Required",
                    "status": 402,
                    "code": invalid,
                    "error": invalid,
                    "message": str(exc),
                },
                extra_headers={
                    "content-type": "application/problem+json",
                    "cache-control": "no-store",
                },
            )
            return
        canonical = canonical_code(code) if code else "payment_invalid"
        body = {
            "type": f"https://paymentauth.org/problems/{canonical}",
            "title": "Payment Required",
            "status": 402,
            "code": canonical,
            "error": canonical,
            "message": message,
        }
        self._send_json(
            402,
            body,
            extra_headers={
                "content-type": "application/problem+json",
                "www-authenticate": format_www_authenticate(challenge),
                "cache-control": "no-store",
            },
        )


def main() -> None:
    adapter = _Adapter()
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), HarnessHandler)
    server.adapter = adapter  # type: ignore[attr-defined]

    ready = {
        "type": "ready",
        "implementation": "python",
        "role": "server",
        "port": port,
        "capabilities": [adapter.protocol],
    }
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
