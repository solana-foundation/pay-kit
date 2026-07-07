# examples/playground_api/discovery.py
"""OpenAPI 3.1 discovery, aligned with the TypeScript playground.

Neither the TS nor the Python SDK ships a discovery / OpenAPI builder yet, so
this is an example-local OpenAPI 3.1 document builder (python-only), pending a
future cross-SDK helper. It mirrors the *document shape* the TS playground emits
so a discovery consumer (mppx tooling, the payment-discovery draft) sees the
same structure from either SDK:

    { info, openapi: "3.1.0", paths: { <path>: { <method>: {
        responses, "x-payment-info": { offers: [...] }, summary? } } },
      "x-service-info"? }

Each `offers[]` entry lists one way to pay (one per accepted protocol/scheme).
Discovery is advisory; the runtime 402 challenge stays authoritative.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit._paycore.solana import stablecoin_decimals
from solana_pay_kit.config import Config
from solana_pay_kit.gate import Gate
from solana_pay_kit.price import Price


def _mints_network(config: Config) -> str:
    """The bare network label consumed by the stablecoin mint registry."""
    return config.network.mints_label()


def base_units(price: Price, *, currency: str = "USDC", network: str = "mainnet") -> str:
    """The integer base-unit string for a price (e.g. ``usd("0.01")`` -> ``"10000"``)."""
    decimals = stablecoin_decimals(currency, network)
    return str(int(price.amount.scaleb(decimals).to_integral_value()))


def _effective_accept(gate: Gate, config: Config) -> tuple[Protocol, ...]:
    """The protocols a gate actually settles over, mirroring the runtime resolver.

    A fee-bearing gate built with an inherited accept carries ``accept=None`` (the
    middleware narrows it per request); reproduce that here so discovery offers
    match what the 402 challenge will advertise: inherit the config list, then
    drop x402 when fees are present (stock x402 settles to a single address).
    """
    accept = gate.accept if gate.accept is not None else config.accept
    if gate.has_fees():
        accept = tuple(p for p in accept if p is not Protocol.X402)
    return accept


def _offer(**fields: Any) -> dict[str, Any]:
    """An offer dict with ``None`` values dropped (TS omits unset optional keys)."""
    return {key: value for key, value in fields.items() if value is not None}


def charge_offers(gate: Gate, config: Config, *, currency: str = "USDC") -> list[dict[str, Any]]:
    """Discovery offers for a fixed charge gate: one per accepted protocol.

    x402 settles the `exact` scheme, MPP settles `charge`; both carry the same
    base-unit amount, recipient, network, and (for x402) the fee-paying operator.
    """
    accept = _effective_accept(gate, config)
    network_label = _mints_network(config)
    amount = base_units(gate.total(), currency=currency, network=network_label)
    # Offer-level description is a price hint (matches the TS offer shape, e.g.
    # "0.01 USDC"); the human prose stays on the route-level summary.
    price = f"{gate.total().amount_string()} {currency}"
    network = config.network.caip2()
    pay_to = gate.pay_to
    operator = config.operator.signer.pubkey()
    offers: list[dict[str, Any]] = []
    if Protocol.X402 in accept:
        offers.append(
            _offer(
                amount=amount,
                currency=currency,
                description=price,
                feePayer=operator,
                intent="charge",
                method="x402",
                network=network,
                payTo=pay_to,
                scheme="exact",
            )
        )
    if Protocol.MPP in accept:
        offers.append(
            _offer(
                amount=amount,
                currency=currency,
                description=price,
                intent="charge",
                method="mpp",
                network=network,
                payTo=pay_to,
                scheme="charge",
            )
        )
    return offers


def session_offer(
    config: Config,
    *,
    cap_base_units: str,
    unit_price_base_units: str,
    pay_to: str,
    currency: str = "USDC",
) -> dict[str, Any]:
    """The single MPP `session` discovery offer (cap + per-delivery unit price).

    Offer `description` is an "up to <cap> <currency>" price hint, mirroring the
    TS session offer shape.
    """
    decimals = stablecoin_decimals(currency, _mints_network(config))
    cap_human = format(Decimal(cap_base_units) / (Decimal(10) ** decimals), "f")
    return _offer(
        amount=cap_base_units,
        currency=currency,
        description=f"up to {cap_human} {currency}",
        intent="session",
        method="mpp",
        network=config.network.caip2(),
        payTo=pay_to,
        scheme="session",
        unitPrice=unit_price_base_units,
    )


def upto_offer(gate: Gate, config: Config, *, currency: str = "USDC") -> dict[str, Any]:
    """The single x402 `upto` discovery offer (authorize a ceiling, bill usage).

    Offer `description` is an "up to <ceiling> <currency>" price hint, mirroring
    the TS playground's usage offer shape.
    """
    network_label = _mints_network(config)
    amount = base_units(gate.total(), currency=currency, network=network_label)
    cap_human = gate.total().amount_string()
    return _offer(
        amount=amount,
        currency=currency,
        description=f"up to {cap_human} {currency}",
        feePayer=config.operator.signer.pubkey(),
        intent="usage",
        method="x402",
        network=config.network.caip2(),
        payTo=gate.pay_to,
        scheme="upto",
    )


def build_openapi_document(
    *,
    info: dict[str, str] | None = None,
    routes: list[dict[str, Any]],
    service_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the OpenAPI 3.1 doc — exact port of the TS `buildOpenApiDocument`.

    Each route is ``{method, path, offers, summary?, request_body?}``; an
    ``offers`` list (possibly empty for an unpaid route) attaches the
    ``x-payment-info`` extension and the 402 response.
    """
    paths: dict[str, dict[str, Any]] = {}
    for route in routes:
        method = str(route["method"]).lower()
        offers = route.get("offers")
        operation: dict[str, Any] = {
            "responses": {
                **({"402": {"description": "Payment Required"}} if offers else {}),
                "200": {"description": "Successful response"},
            },
        }
        if offers:
            operation["x-payment-info"] = {"offers": offers}
        if route.get("summary"):
            operation["summary"] = route["summary"]
        if route.get("request_body"):
            operation["requestBody"] = route["request_body"]
        paths.setdefault(route["path"], {})[method] = operation

    doc: dict[str, Any] = {
        "info": {
            "title": (info or {}).get("title", "API"),
            "version": (info or {}).get("version", "1.0.0"),
        },
        "openapi": "3.1.0",
        "paths": paths,
    }
    if service_info:
        doc["x-service-info"] = service_info
    return doc
