"""HTML payment page and service worker helpers.

Uses the mppx-generated template (template.gen.html) for the payment page.
The template is generated at build time by html/build.ts and contains the
same CSS, layout, and theming as all other SDK implementations.
"""

from __future__ import annotations

import html as html_mod
import importlib.resources
import json
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import parse_qs, urlparse

from pay_kit.protocols.mpp.core.base64url import decode_json
from pay_kit.protocols.mpp.core.types import PaymentChallenge

SERVICE_WORKER_PARAM = "__mpp_worker"

# Known stablecoin symbols for amount display
_KNOWN_SYMBOLS: dict[str, str] = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC",
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": "USDC",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT",
    "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH": "USDG",
    "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7": "USDG",
    "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo": "PYUSD",
    "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM": "PYUSD",
    "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH": "CASH",
    "USDC": "USDC",
    "USDT": "USDT",
    "USDG": "USDG",
    "PYUSD": "PYUSD",
    "CASH": "CASH",
}

_TEMPLATE: str | None = None
_SERVICE_WORKER: str | None = None


def _load_resource(filename: str) -> str:
    return importlib.resources.files("pay_kit.protocols.mpp.server.html").joinpath(filename).read_text("utf-8")


def challenge_to_html(challenge: PaymentChallenge, rpc_url: str, network: str) -> str:
    """Render a payment page using the mppx-generated template.

    Replaces {{AMOUNT}}, {{DESCRIPTION}}, {{EXPIRES}}, {{DATA_JSON}}
    placeholders — same approach as the Rust and Go implementations.
    """
    global _TEMPLATE  # noqa: PLW0603
    if _TEMPLATE is None:
        try:
            _TEMPLATE = _load_resource("template.gen.html")
        except Exception:
            _TEMPLATE = ""

    # Decode request for amount display
    try:
        request_data: dict[str, Any] = decode_json(challenge.request)
    except Exception:
        request_data = {}

    currency = request_data.get("currency", "SOL")
    md = request_data.get("methodDetails", {})
    decimals = md.get("decimals", 9 if currency.lower() == "sol" else 6)
    amount_raw = request_data.get("amount", "0")
    try:
        amount_dec = Decimal(str(amount_raw)) / Decimal(10**decimals)
    except (InvalidOperation, ValueError):
        amount_dec = Decimal(0)
    display_amount = str(int(amount_dec)) if amount_dec == amount_dec.to_integral_value() else f"{amount_dec:.2f}"

    sym = _KNOWN_SYMBOLS.get(currency)
    if currency.lower() == "sol":
        amount_display = f"{display_amount} SOL"
    elif sym:
        amount_display = f"${display_amount}"
    else:
        amount_display = f"{display_amount} {currency[:6]}"

    description_html = ""
    if challenge.description:
        description_html = f'<p class="mppx-summary-description">{html_mod.escape(challenge.description)}</p>'

    expires_html = ""
    if challenge.expires:
        esc_exp = html_mod.escape(challenge.expires)
        expires_html = (
            f'<p class="mppx-summary-expires">Expires at '
            f'<time datetime="{esc_exp}" id="_exp">{esc_exp}</time></p>'
            f"<script>document.getElementById('_exp').textContent="
            f"new Date('{esc_exp}').toLocaleString()</script>"
        )

    # Build embedded data (standalone format: request stays as base64url)
    embedded_data = json.dumps(
        {"challenge": challenge.__dict__, "network": network, "rpcUrl": rpc_url},
        separators=(",", ":"),
        default=str,
    ).replace("<", "\\u003c")

    if _TEMPLATE:
        return (
            _TEMPLATE.replace("{{AMOUNT}}", html_mod.escape(amount_display))
            .replace("{{DESCRIPTION}}", description_html)
            .replace("{{EXPIRES}}", expires_html)
            .replace("{{DATA_JSON}}", embedded_data)
        )

    # Minimal fallback (should not happen if html/build.ts ran)
    return f"<html><body><pre>{html_mod.escape(embedded_data)}</pre></body></html>"


def service_worker_js() -> str:
    """Return the mppx service worker JavaScript content."""
    global _SERVICE_WORKER  # noqa: PLW0603
    if _SERVICE_WORKER is None:
        try:
            _SERVICE_WORKER = _load_resource("service_worker.gen.js")
        except Exception:
            _SERVICE_WORKER = ""
    return _SERVICE_WORKER


def accepts_html(accept: str | None) -> bool:
    """Return True if the Accept header includes text/html."""
    if accept is None:
        return False
    return "text/html" in accept


def is_service_worker_request(url: str) -> bool:
    """Return True if the URL contains the service worker query parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return SERVICE_WORKER_PARAM in params
