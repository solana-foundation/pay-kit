from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from x402.interop.exact import build_exact_payment_signature_from_rpc

STABLECOIN_MINTS = {
    "USDC": {
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        ),
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": (
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
        ),
        "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": (
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
        ),
    },
    "USDT": {
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        ),
    },
    "USDG": {
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (
            "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
        ),
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": (
            "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
        ),
        "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": (
            "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
        ),
    },
    "PYUSD": {
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (
            "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
        ),
        "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1": (
            "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
        ),
        "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z": (
            "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
        ),
    },
    "CASH": {
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": (
            "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
        ),
    },
}


def _header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _load_payment_required_header(headers: dict[str, str]) -> dict[str, Any] | None:
    encoded = _header_value(headers, "PAYMENT-REQUIRED")
    if not encoded:
        return None

    try:
        raw = base64.b64decode(encoded).decode("utf-8")
        loaded = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None

    return loaded if isinstance(loaded, dict) else None


def _load_payment_required_body(body: str) -> dict[str, Any] | None:
    if not body:
        return None

    try:
        loaded = json.loads(body)
    except json.JSONDecodeError:
        return None

    return loaded if isinstance(loaded, dict) else None


def _accepts_from_envelope(envelope: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not envelope:
        return []

    accepts = envelope.get("accepts")
    if not isinstance(accepts, list):
        return []

    return [entry for entry in accepts if isinstance(entry, dict)]


def _resource_from_envelope(envelope: dict[str, Any] | None) -> dict[str, Any] | None:
    if not envelope:
        return None
    resource = envelope.get("resource")
    return resource if isinstance(resource, dict) else None


def select_svm_challenge(
    *,
    headers: dict[str, str],
    body: str,
    network: str,
    scheme: str = "exact",
    accepted_currencies: list[str] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    envelopes = [
        _load_payment_required_header(headers),
        _load_payment_required_body(body),
    ]

    for envelope in envelopes:
        requirements = [
            requirement
            for requirement in _accepts_from_envelope(envelope)
            if requirement.get("scheme") == scheme
            and requirement.get("network") == network
            and isinstance(requirement.get("asset"), str)
            and isinstance(requirement.get("amount"), str)
        ]
        if not requirements:
            continue

        if accepted_currencies:
            for currency in accepted_currencies:
                for requirement in requirements:
                    if _matches_currency(requirement, currency, network):
                        return requirement, _resource_from_envelope(envelope)
            return None, _resource_from_envelope(envelope)

        return min(requirements, key=lambda requirement: _amount_or_max(requirement["amount"])), (
            _resource_from_envelope(envelope)
        )

    return None, None


def _amount_or_max(amount: str) -> int:
    return int(amount) if amount.isdigit() else sys.maxsize


def _matches_currency(requirement: dict[str, Any], currency: str, network: str) -> bool:
    mint = _resolve_stablecoin_mint(currency, network)
    offered = requirement.get("asset")
    offered_currency = requirement.get("currency")
    return (
        requirement.get("currency") == currency
        or requirement.get("currency") == currency.upper()
        or (
            isinstance(offered_currency, str)
            and _resolve_stablecoin_mint(offered_currency, network) == mint
        )
        or (isinstance(offered, str) and _resolve_stablecoin_mint(offered, network) == mint)
    )


def _resolve_stablecoin_mint(currency: str, network: str) -> str:
    if currency.upper() == "SOL":
        return currency
    by_network = STABLECOIN_MINTS.get(currency.upper())
    if by_network:
        return (
            by_network.get(network)
            or by_network.get("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
            or currency
        )
    return currency


def _accepted_currencies_from_env() -> list[str] | None:
    raw = os.environ.get("X402_INTEROP_PREFER_CURRENCIES")
    if not raw:
        return None
    currencies = [currency.strip() for currency in raw.split(",") if currency.strip()]
    return currencies or None


def select_svm_requirement(
    *,
    headers: dict[str, str],
    body: str,
    network: str,
    scheme: str = "exact",
    accepted_currencies: list[str] | None = None,
) -> dict[str, Any] | None:
    requirement, _resource = select_svm_challenge(
        headers=headers,
        body=body,
        network=network,
        scheme=scheme,
        accepted_currencies=accepted_currencies,
    )
    return requirement


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload), flush=True)


def main() -> int:
    target_url = os.environ.get("X402_INTEROP_TARGET_URL")
    if not target_url:
        raise RuntimeError("X402_INTEROP_TARGET_URL is required")

    status = 0
    headers: dict[str, str] = {}
    body: object = None

    try:
        with urllib.request.urlopen(target_url, timeout=10) as response:
            status = response.status
            headers = dict(response.headers.items())
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        status = error.code
        headers = dict(error.headers.items())
        body = error.read().decode("utf-8")

    selected_requirement, resource = select_svm_challenge(
        headers=headers,
        body=str(body),
        network=os.environ.get(
            "X402_INTEROP_NETWORK",
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        ),
        scheme=os.environ.get("X402_INTEROP_SCHEME", "exact"),
        accepted_currencies=_accepted_currencies_from_env(),
    )
    intent = os.environ.get("X402_INTEROP_INTENT")
    scheme = os.environ.get("X402_INTEROP_SCHEME", "exact")
    error_domain = intent or scheme

    if (
        status == 402
        and intent is None
        and scheme == "exact"
        and selected_requirement is not None
        and os.environ.get("X402_INTEROP_CLIENT_SECRET_KEY")
        and os.environ.get("X402_INTEROP_RPC_URL")
    ):
        try:
            payment_signature = build_exact_payment_signature_from_rpc(
                requirement=selected_requirement,
                client_secret_key=os.environ["X402_INTEROP_CLIENT_SECRET_KEY"],
                rpc_url=os.environ["X402_INTEROP_RPC_URL"],
                resource=resource,
            )
            request = urllib.request.Request(
                target_url,
                headers={"PAYMENT-SIGNATURE": payment_signature},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    paid_status = response.status
                    paid_headers = dict(response.headers.items())
                    paid_body = response.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                paid_status = error.code
                paid_headers = dict(error.headers.items())
                paid_body = error.read().decode("utf-8")

            try:
                parsed_body: object = json.loads(paid_body)
            except json.JSONDecodeError:
                parsed_body = paid_body

            _emit(
                {
                    "type": "result",
                    "implementation": "python",
                    "role": "client",
                    "ok": 200 <= paid_status < 300,
                    "status": paid_status,
                    "responseHeaders": paid_headers,
                    "responseBody": parsed_body,
                    "settlement": _header_value(paid_headers, "x-fixture-settlement"),
                }
            )
            return 0
        except Exception as error:
            _emit(
                {
                    "type": "result",
                    "implementation": "python",
                    "role": "client",
                    "ok": False,
                    "status": status,
                    "responseHeaders": headers,
                    "responseBody": {
                        "error": "python_exact_client_payment_failed",
                        "message": str(error),
                        "challengeStatus": status,
                        "challengeBody": body,
                        "selectedRequirement": selected_requirement,
                    },
                    "settlement": None,
                }
            )
            return 0

    _emit(
        {
            "type": "result",
            "implementation": "python",
            "role": "client",
            "ok": False,
            "status": status,
            "responseHeaders": headers,
            "responseBody": {
                "error": f"python_{error_domain}_client_not_implemented",
                "challengeStatus": status,
                "challengeBody": body,
                "selectedRequirement": selected_requirement,
            },
            "settlement": None,
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
