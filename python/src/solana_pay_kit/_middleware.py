"""Framework-agnostic payment-gating core plus the request-scoped trio.

The framework shims (``solana_pay_kit.fastapi`` / ``solana_pay_kit.flask`` / ``solana_pay_kit.django``)
all delegate to :class:`PayCore`. The split keeps every protocol/scheme decision,
402-challenge assembly, and adapter dispatch in one host-neutral place; the shims
only translate ``PayCore``'s outcome into their framework's response idioms
(caveat #6).

:class:`PayCore` mirrors the PHP ``Middleware\\RequirePayment`` and the Ruby Rack
middleware:

* :meth:`PayCore.resolve_gate` coerces the assorted gate-reference shapes
  (inline :class:`~solana_pay_kit.gate.Gate`, registered name, request builder, bare
  :class:`~solana_pay_kit.price.Price`) into a concrete validated gate.
* :meth:`PayCore.detect_adapter` walks the gate's accept list in order and picks
  the scheme adapter whose proof header is present. x402 wins when both proofs
  arrive; a fee-bearing gate disables x402 entirely (stock x402 facilitators
  settle to a single address).
* :meth:`PayCore.process` runs verification and returns a settled
  :class:`~solana_pay_kit.payment.Payment`, or raises :class:`PaymentRequiredError`
  (carrying the 402 challenge headers + JSON body on the exception) /
  :class:`InvalidProofError` / :class:`ProtocolNotSupportedError`.

The request-scoped trio (:func:`require_payment`, :func:`is_paid`,
:func:`is_paid_for`, :func:`payment`) read the verified
:class:`~solana_pay_kit.payment.Payment` the shims attach to the request under the
``paykit_payment`` attribute, matching the cross-SDK ``payment`` / ``paid?`` /
``require_payment!`` shape.
"""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from solana_pay_kit._paycore.protocol import Protocol
from solana_pay_kit.errors import (
    ConfigurationError,
    InvalidProofError,
    PaymentRequiredError,
    ProtocolNotSupportedError,
)
from solana_pay_kit.gate import DynamicGate, Gate
from solana_pay_kit.payment import Payment
from solana_pay_kit.price import Price
from solana_pay_kit.pricing import Pricing, coerce
from solana_pay_kit.protocols.mpp import MppAdapter
from solana_pay_kit.protocols.x402 import X402Adapter

if TYPE_CHECKING:
    from solana_pay_kit._paycore.store import Store
    from solana_pay_kit.config import Config
    from solana_pay_kit.protocols.mpp import MppAcceptsEntry
    from solana_pay_kit.protocols.x402.exact.types import X402AcceptsEntry

__all__ = [
    "PayCore",
    "require_payment",
    "is_paid",
    "is_paid_for",
    "payment",
    "PAYMENT_ATTR",
]

#: Request attribute the framework shims write the verified payment under.
PAYMENT_ATTR = "paykit_payment"

#: Gate reference shapes accepted by the middleware.
GateRef = "Gate | DynamicGate | Price | str | Callable[[Any], Gate]"


@dataclass
class _CoreCacheEntry:
    """One identity-bound cached core and the weak Config that owns it."""

    config_ref: weakref.ReferenceType[Config]
    core: PayCore
    replay_store: Store | None


class _IdentityCoreCache:
    """Thread-safe, identity-keyed cache whose entries follow Config lifetime."""

    def __init__(self) -> None:
        self._entries: dict[int, _CoreCacheEntry] = {}
        self._lock = threading.RLock()

    def get_or_create(
        self,
        core_type: type[PayCore],
        config: Config,
        replay_store: Store | None,
    ) -> PayCore:
        """Return the one core bound to this exact Config instance.

        ``WeakKeyDictionary`` compares keys by value, which lets two distinct
        but equal Config instances share a replay store. Indexing by object id
        and confirming the live referent with ``is`` preserves per-instance
        ownership. The critical section also makes first-use construction and
        replay-store binding atomic across framework request threads.
        """
        key = id(config)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                cached_config = entry.config_ref()
                if cached_config is config:
                    if replay_store is not None and entry.replay_store is not replay_store:
                        raise ConfigurationError(
                            "a different replay_store is already bound to this Config; "
                            "reuse the original store or construct a new Config"
                        )
                    return entry.core
                if cached_config is None:
                    self._entries.pop(key, None)

            def evict(config_ref: weakref.ReferenceType[Config]) -> None:
                with self._lock:
                    current = self._entries.get(key)
                    if current is not None and current.config_ref is config_ref:
                        self._entries.pop(key, None)

            config_ref = weakref.ref(config, evict)
            # A cached core keeps adapters and their replay state alive, but
            # those adapters retain their Config. Use an equal frozen snapshot
            # so the caller's Config remains weakly owned by this cache.
            core = core_type(config.model_copy(), replay_store=replay_store, _source_config_ref=config_ref)
            self._entries[key] = _CoreCacheEntry(config_ref=config_ref, core=core, replay_store=replay_store)
            return core


#: One ``PayCore`` (and its adapters + shared replay store) per Config object.
#: Framework shims construct a gate per request, so this cache keeps replay
#: markers durable for a Config's lifetime without merging equal Config values.
_CORE_CACHE = _IdentityCoreCache()


class PayCore:
    """Host-neutral payment-gating core shared by every framework shim.

    One instance wraps a frozen :class:`~solana_pay_kit.config.Config` and
    constructs only its configured protocol adapters. Callers can inject a
    replay store for the default protocol adapters or pre-built adapters to override
    defaults, e.g. with an offline ``recent_blockhash_provider`` for tests.
    """

    def __init__(
        self,
        config: Config,
        *,
        mpp: MppAdapter | None = None,
        x402: X402Adapter | None = None,
        replay_store: Store | None = None,
        _source_config_ref: weakref.ReferenceType[Config] | None = None,
    ) -> None:
        """Bind to ``config`` and resolve (or inject) the scheme adapters."""
        self._config = config
        self._source_config_ref = _source_config_ref if _source_config_ref is not None else weakref.ref(config)
        # When both adapters receive this store, their shared network-qualified
        # settlement identity fences a co-signed Solana transaction across MPP
        # and x402 as well as across requests.
        self._replay_store = replay_store
        # MPP construction enforces durable replay state outside localnet. Do
        # not construct it for x402-only configurations, where it is unused.
        if mpp is not None:
            self._mpp: MppAdapter | None = mpp
        elif Protocol.MPP in config.accept:
            self._mpp = MppAdapter(config, replay_store=replay_store)
        else:
            self._mpp = None
        # Auto-wire the x402 adapter only when the config accept list includes
        # it; mirrors the PHP constructor. An explicit adapter always wins.
        if x402 is not None:
            self._x402: X402Adapter | None = x402
        elif Protocol.X402 in config.accept:
            self._x402 = X402Adapter(config, replay_store=replay_store)
        else:
            self._x402 = None

    @classmethod
    def for_config(cls, config: Config, *, replay_store: Store | None = None) -> PayCore:
        """Return the cached per-Config core, building (and caching) one on miss.

        The framework shims call this once per request; reusing one core per
        Config keeps the MPP/x402 adapters and their shared in-memory replay
        store alive across requests so a settled signature stays consumed and
        cannot be replayed. A fresh ``PayCore(config)`` per request (the prior
        behaviour) reset that store on every call. Pass ``replay_store`` on the
        first call to supply shared durable state for a nonlocal deployment.
        """
        return _CORE_CACHE.get_or_create(cls, config, replay_store)

    @property
    def config(self) -> Config:
        """The frozen configuration this core gates against."""
        return self._source_config_ref() or self._config

    def resolve_gate(
        self,
        gate_ref: Gate | DynamicGate | Price | str | Callable[[Any], Gate],
        pricing: Pricing | None,
        request: Any,
    ) -> Gate:
        """Coerce any gate-reference shape into a concrete validated Gate.

        A plain callable (not a :class:`DynamicGate`) is invoked with the
        request and may return a :class:`Gate` or a :class:`~solana_pay_kit.price.Price`
        (wrapped with Config defaults). A :class:`DynamicGate` is resolved with
        the Config defaults the DSL omitted. Everything else funnels through
        :func:`solana_pay_kit.pricing.coerce`.
        """
        if isinstance(gate_ref, DynamicGate):
            self._inject_dynamic_defaults(gate_ref)
            return gate_ref.resolve(request)
        if not isinstance(gate_ref, (Gate, Price, str)) and callable(gate_ref):
            return self._resolve_callable(gate_ref, request)
        return self._coerce_static(gate_ref, pricing, request)

    def detect_adapter(
        self,
        gate: Gate,
        headers: Mapping[str, str],
    ) -> X402Adapter | MppAdapter | None:
        """Pick the scheme adapter whose proof header is present, in accept order.

        x402 requires a non-empty ``Payment-Signature`` header, the gate to
        accept x402, no fees on the gate, and a wired x402 adapter. MPP requires
        an ``Authorization`` header whose scheme is ``payment`` (case-insensitive).
        When both proofs are present x402 wins, matching the PHP/Ruby reference.
        """
        accept = gate.accept if gate.accept is not None else self._config.accept
        authorization = _read_header(headers, "authorization")
        signature = _read_header(headers, "payment-signature")

        for scheme in accept:
            if scheme == Protocol.X402 and signature and self._x402 is not None and not gate.has_fees():
                return self._x402
            if (
                scheme == Protocol.MPP
                and self._mpp is not None
                and authorization
                and authorization.strip().lower().startswith("payment ")
            ):
                return self._mpp
        return None

    async def process(
        self,
        gate_ref: Gate | DynamicGate | Price | str | Callable[[Any], Gate],
        pricing: Pricing | None,
        request: Any,
    ) -> Payment:
        """Resolve, dispatch, verify, and return a settled :class:`Payment`.

        Raises :class:`~solana_pay_kit.errors.PaymentRequiredError` (with
        ``challenge_headers`` and ``body`` attributes set for the shim to render
        a 402) when no usable proof is present, and re-raises
        :class:`~solana_pay_kit.errors.InvalidProofError` /
        :class:`~solana_pay_kit.errors.ProtocolNotSupportedError` on verification or
        protocol-mismatch failures.
        """
        gate = self.resolve_gate(gate_ref, pricing, request)
        headers = _request_headers(request)
        adapter = self.detect_adapter(gate, headers)

        if adapter is None:
            raise self._payment_required(gate, request)

        try:
            return await adapter.verify_and_settle(gate, request)
        except (InvalidProofError, ProtocolNotSupportedError):
            raise
        except PaymentRequiredError as exc:
            raise self._payment_required(gate, request) from exc

    def build_402(self, gate: Gate, request: Any) -> tuple[dict[str, str], dict[str, Any]]:
        """Assemble the 402 challenge headers and JSON body for ``gate``.

        Returns ``(headers, body)`` where ``body`` is
        ``{"error", "resource", "accepts"}``. x402 is offered first when the
        gate accepts it and carries no fees; MPP is offered whenever accepted.
        """
        accept = gate.accept if gate.accept is not None else self._config.accept
        accepts: list[X402AcceptsEntry | MppAcceptsEntry] = []
        headers: dict[str, str] = {}

        if self._x402 is not None and Protocol.X402 in accept and not gate.has_fees():
            accepts.append(self._x402.accepts_entry(gate, request))
            headers.update(self._x402.challenge_headers(gate, request))
        if self._mpp is not None and Protocol.MPP in accept:
            accepts.append(self._mpp.accepts_entry(gate, request))
            headers.update(self._mpp.challenge_headers(gate, request))

        headers.setdefault("content-type", "application/json")
        body = {
            "error": "payment_required",
            "resource": _request_path(request),
            "accepts": accepts,
        }
        return headers, body

    # -- internals ----------------------------------------------------------

    def _payment_required(self, gate: Gate, request: Any) -> PaymentRequiredError:
        """Build a PaymentRequiredError carrying the 402 challenge for the shim."""
        headers, body = self.build_402(gate, request)
        error = PaymentRequiredError("solana_pay_kit: payment required")
        # Stash the rendered challenge on the exception so framework shims can
        # emit a 402 without re-deriving it; mirrors PHP's build402 short-circuit.
        error.challenge_headers = headers  # type: ignore[attr-defined]
        error.body = body  # type: ignore[attr-defined]
        return error

    def _resolve_callable(self, builder: Callable[[Any], object], request: Any) -> Gate:
        """Invoke a bare request-builder and coerce its Gate/Price result.

        ``builder`` is typed to return ``object`` because user request-builders
        are untyped and may return a Gate, a Price, or an invalid value; the
        isinstance ladder is the load-bearing runtime guard.
        """
        result = builder(request)
        if isinstance(result, Gate):
            return result
        if isinstance(result, Price):
            return self._coerce_static(result, None, request)
        raise ProtocolNotSupportedError(
            f"solana_pay_kit: gate builder returned {type(result).__name__}, expected Gate or Price"
        )

    def _coerce_static(
        self,
        gate_ref: Gate | DynamicGate | Price | str,
        pricing: Pricing | None,
        request: Any,
    ) -> Gate:
        """Coerce a non-callable reference; resolve a DynamicGate against the request.

        A registered name may resolve (via the pricing registry) to a
        :class:`DynamicGate`. Such a gate still needs the current request to
        evaluate its builder, so inject the Config defaults and resolve it here
        rather than rejecting it; ``resolve_gate`` always has the request.
        """
        coerced = coerce(gate_ref, registry=pricing, config=self._config)
        if isinstance(coerced, DynamicGate):
            self._inject_dynamic_defaults(coerced)
            return coerced.resolve(request)
        return coerced

    def _inject_dynamic_defaults(self, gate: DynamicGate) -> None:
        """Seed a DynamicGate's lazy Config defaults (pay_to + accept list)."""
        defaults = getattr(gate, "_defaults", None)
        if isinstance(defaults, dict) and not defaults:
            defaults["pay_to"] = self._config.effective_recipient()
            defaults["accept"] = self._config.accept


# -- request-scoped trio ----------------------------------------------------


def payment(request: Any) -> Payment | None:
    """The verified payment attached to ``request``, or ``None`` if unpaid.

    Reads the ``paykit_payment`` attribute the framework shims write after a
    successful :meth:`PayCore.process`. Tolerates an attribute bag, a mapping,
    or a framework request exposing ``.state`` (FastAPI/Starlette).
    """
    value = _read_attr(request, PAYMENT_ATTR)
    return value if isinstance(value, Payment) else None


def is_paid(request: Any) -> bool:
    """Whether a verified payment is attached to ``request``."""
    return payment(request) is not None


def is_paid_for(request: Any, gate: Gate | str) -> bool:
    """Whether ``request`` carries a verified payment for ``gate``.

    A :class:`~solana_pay_kit.gate.Gate` instance trusts the middleware that wrote the
    attribute (Payment does not carry gate identity beyond its name); a string
    is matched against the payment's ``gate_name``.
    """
    settled = payment(request)
    if settled is None:
        return False
    if isinstance(gate, Gate):
        return True
    return settled.gate_name == gate


def require_payment(request: Any) -> Payment:
    """Return the attached payment or raise :class:`PaymentRequiredError`.

    Imperative gating from inside a handler that did not run the middleware
    decorator/dependency. Mirrors the cross-SDK ``require_payment!``.
    """
    settled = payment(request)
    if settled is None:
        raise PaymentRequiredError("solana_pay_kit: payment required")
    return settled


# -- header / attribute helpers ---------------------------------------------


def _request_headers(request: Any) -> Mapping[str, str]:
    """Extract a case-tolerant header mapping from a generic request bag."""
    headers: object = getattr(request, "headers", None)
    if headers is None and isinstance(request, Mapping):
        request_map = cast("Mapping[str, object]", request)
        headers = request_map.get("headers", request_map)
    if headers is None:
        return {}
    if isinstance(headers, Mapping):
        return cast("Mapping[str, str]", headers)
    # Header objects exposing .get (e.g. Starlette Headers, WSGI EnvironHeaders).
    if callable(getattr(headers, "get", None)):
        return _HeaderProxy(headers)
    return {}


def _read_header(headers: Mapping[str, str], name: str) -> str:
    """Read a header case-insensitively from a mapping or proxy; "" if absent."""
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    value = getter(name)
    if value is None:
        value = getter(name.title())
    if value is None:
        value = getter(name.upper())
    return str(value) if value else ""


def _read_attr(request: Any, name: str) -> object:
    """Read an attribute off a request bag, mapping, or ``.state`` namespace."""
    state = getattr(request, "state", None)
    if state is not None and hasattr(state, name):
        return getattr(state, name)
    if hasattr(request, name):
        return getattr(request, name)
    if isinstance(request, Mapping):
        return cast("Mapping[str, object]", request).get(name)
    return None


def _request_path(request: Any) -> str:
    """Best-effort request path for the 402 body ``resource`` field."""
    url = getattr(request, "url", None)
    if url is not None:
        path = getattr(url, "path", None)
        if isinstance(path, str):
            return path
    path = getattr(request, "path", None)
    if isinstance(path, str):
        return path
    if isinstance(request, Mapping):
        request_map = cast("Mapping[str, object]", request)
        candidate = request_map.get("path") or request_map.get("PATH_INFO")
        if isinstance(candidate, str):
            return candidate
    return "/"


class _HeaderProxy(Mapping[str, str]):
    """Adapts a ``.get``-bearing header object to a read-only Mapping."""

    __slots__ = ("_headers",)

    def __init__(self, headers: Any) -> None:
        self._headers = headers

    def __getitem__(self, key: str) -> str:
        value = self._headers.get(key)
        if value is None:
            raise KeyError(key)
        return str(value)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        value = self._headers.get(key)
        return value if value is not None else default

    def __iter__(self) -> Any:
        return iter(getattr(self._headers, "keys", lambda: ())())

    def __len__(self) -> int:
        try:
            return len(self._headers)
        except TypeError:
            return 0
