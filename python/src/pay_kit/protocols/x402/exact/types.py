"""x402 ``exact`` wire shapes.

TypedDicts describing the exact JSON dicts the adapter builds for challenges/
offers and parses from inbound credentials. They give the adapter precise
static types over the wire payloads and never change the serialized bytes.
Optional keys use ``total=False``. Inbound payloads are validated field-by-
field at runtime and then narrowed to these shapes with ``cast``.
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


class X402Resource(TypedDict):
    """The ``resource`` block inside an x402 challenge."""

    type: str
    url: str


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


class X402PayloadField(TypedDict, total=False):
    """The ``payload`` block of an inbound X-PAYMENT envelope."""

    transaction: str
    transactionHash: str


class X402PaymentIdentifierInfo(TypedDict, total=False):
    """The ``payment-identifier.info`` block (camelCase wire).

    ``required`` is server-side (whether clients MUST populate ``id``); ``id`` is
    the client-side idempotency key matching ``^[A-Za-z0-9_-]{16,128}$``. Mirrors
    rust ``PaymentIdentifierInfo``.
    """

    required: bool
    id: str


class X402PaymentIdentifierExtension(TypedDict, total=False):
    """The ``payment-identifier`` extension. Mirrors rust ``PaymentIdentifierExtension``.

    ``info`` carries the required/id pair; the server-published ``schema`` is
    echoed verbatim per x402 v2 §5.1.2 and typed loosely as it is opaque to the
    client.
    """

    info: X402PaymentIdentifierInfo
    schema: object


class X402Envelope(TypedDict, total=False):
    """An x402 X-PAYMENT envelope (decoded from / built for the proof header).

    All keys optional because the inbound structure is attacker-controlled and
    validated field-by-field at runtime before any value is trusted; the client
    builder populates ``x402Version``, ``accepted`` and ``payload``. ``extensions``
    is the echoed v2 extensions object (kebab-case ``payment-identifier`` key
    plus any unknown extensions preserved verbatim); omitted when the server
    advertised none. Mirrors rust ``PaymentSignatureEnvelope.extensions``.
    """

    x402Version: int
    accepted: X402AcceptsEntry
    payload: X402PayloadField
    extensions: dict[str, object]


class X402ResponseEnvelope(TypedDict):
    """The base64-encoded ``payment-response`` settlement receipt."""

    success: bool
    transaction: str
    network: str
    payer: str
