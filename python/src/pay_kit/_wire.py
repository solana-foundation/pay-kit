"""Typed wire shapes for the x402 and MPP JSON surfaces.

These ``TypedDict`` definitions describe the exact JSON dicts pay_kit builds for
challenges/offers and parses from inbound credentials. They exist purely to give
the adapters precise static types over the wire payloads; they do not change the
serialized bytes. Optional keys use ``total=False`` so a missing field is a type
error only where the field is guaranteed present.

Inbound payloads (decoded via ``json.loads``) are validated structurally at
runtime and then narrowed to these shapes with ``cast``; the cast is a static-
only assertion and never alters the value.
"""

from __future__ import annotations

from typing import TypedDict


class X402ExtraRequired(TypedDict):
    """The always-present keys of an x402 ``accepts[].extra`` block."""

    feePayer: str
    decimals: int
    tokenProgram: str
    memo: str


class X402Extra(X402ExtraRequired, total=False):
    """An x402 ``accepts[].extra`` block; ``recentBlockhash`` is optional."""

    recentBlockhash: str


class X402AcceptsEntry(TypedDict):
    """One x402 ``accepts[]`` offer entry (the server requirement)."""

    protocol: str
    scheme: str
    network: str
    asset: str
    amount: str
    maxAmountRequired: str
    payTo: str
    maxTimeoutSeconds: int
    extra: X402Extra


class X402Challenge(TypedDict):
    """The base64-encoded ``payment-required`` challenge body."""

    x402Version: int
    resource: X402Resource
    accepts: list[X402AcceptsEntry]


class X402Resource(TypedDict):
    """The ``resource`` block inside an x402 challenge."""

    type: str
    url: str


class X402PayloadField(TypedDict, total=False):
    """The ``payload`` block of an inbound X-PAYMENT envelope."""

    transaction: str
    transactionHash: str


class X402Envelope(TypedDict, total=False):
    """An inbound X-PAYMENT envelope (decoded from the proof header).

    All keys optional because the structure is attacker-controlled and validated
    field-by-field at runtime before any value is trusted.
    """

    x402Version: int
    accepted: X402AcceptsEntry
    payload: X402PayloadField


class X402ResponseEnvelope(TypedDict):
    """The base64-encoded ``payment-response`` settlement receipt."""

    success: bool
    transaction: str
    network: str
    payer: str


class MppSplit(TypedDict):
    """A single fee split on an MPP offer or charge request."""

    recipient: str
    amount: str


class MppAcceptsEntryRequired(TypedDict):
    """The always-present keys of an MPP ``accepts[]`` offer entry."""

    protocol: str
    scheme: str
    network: str
    amount: str
    currency: str
    payTo: str
    realm: str


class MppAcceptsEntry(MppAcceptsEntryRequired, total=False):
    """One MPP ``accepts[]`` offer entry; ``splits`` present only with fees."""

    splits: list[MppSplit]


class MppMethodDetails(TypedDict, total=False):
    """The MPP ``request.methodDetails`` block (network always set)."""

    network: str
    splits: list[MppSplit]
    feePayer: bool
    feePayerKey: str
    recentBlockhash: str
