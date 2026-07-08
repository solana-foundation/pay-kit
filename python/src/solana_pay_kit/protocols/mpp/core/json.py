"""RFC 8785 JSON Canonicalization Scheme (JCS) encoder.

The default ``json.dumps(sort_keys=True)`` is NOT RFC 8785 compliant:

* Python's ``str <`` compares by Unicode code point, not by UTF-16 code unit.
  Differs on supplementary plane characters (U+10000 and above) where the
  UTF-16 code-unit ordering uses surrogate pairs.
* Python's default ``float.__repr__`` does not match ECMA-262 7.1.12.1
  ``ToString(Number)``: e.g. ``repr(1e21)`` is ``'1e+21'`` (which happens
  to match) but values like ``0.1 + 0.2 = 0.30000000000000004`` come out
  with the Python repr's shortest form, not the ES6 algorithm.
* Python's ``json.dumps`` happily encodes lone surrogates as ``\\uD834``,
  while RFC 8785 section 3.2.2 mandates rejection.

This module ships a small JCS encoder used by the rest of the SDK to compute
HMAC inputs and to serialize the canonical ``request`` field. Mirrors the
Ruby / PHP / Lua vendored helpers that landed alongside PR #99 / #102.

References:
* RFC 8785 section 3.2.2.3 Numbers
* RFC 8785 section 3.2.3 Member Sorting (UTF-16 code units)
* ECMA-262 section 7.1.12.1 ToString Applied to the Number Type
* ECMA-262 section 24.5.2 JSON.stringify
"""

from __future__ import annotations

import math
from typing import Any


def encode_canonical(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes for ``value``."""
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        # ``bool`` is a subclass of ``int`` in Python, but the bool branch
        # above already returned, so by this point ``value`` is a plain int.
        return str(value)
    if isinstance(value, float):
        return _encode_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        return _encode_object(value)
    raise TypeError(f"value of type {type(value).__name__} is not JSON-serializable for canonical encoding")


def _encode_object(value: dict) -> str:
    # RFC 8785 section 3.2.3: keys are sorted as sequences of UTF-16 code units.
    # Python strings index by Unicode code point, so we re-encode each key to
    # UTF-16 BE bytes and sort by that byte sequence. The encoding does NOT
    # add a BOM (we picked BE explicitly).
    entries = []
    for key in value:
        if not isinstance(key, str):
            raise TypeError("JSON object keys must be strings for canonical encoding")
        entries.append((key.encode("utf-16-be"), key))
    entries.sort(key=lambda pair: pair[0])

    parts = []
    for _utf16, key in entries:
        parts.append(_encode_string(key) + ":" + _encode(value[key]))
    return "{" + ",".join(parts) + "}"


def _encode_string(value: str) -> str:
    # RFC 8785 section 3.2.2: reject lone surrogates. Python strings can hold
    # them (UTF-16 code units), so check explicitly via the strict UTF-8 round
    # trip.
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"string contains a lone surrogate: {exc}") from exc

    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x09:
            out.append("\\t")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0D:
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(value: float) -> str:
    """ES6 ``ToString(Number)`` per ECMA-262 section 7.1.12.1.

    Forbids NaN and Infinity per RFC 8785 section 3.2.2.3. Renders integer
    floats without a fractional part (``1.0`` -> ``"1"``). Negative zero is
    rendered as ``"0"`` (ES6 step 2 of ToString collapses signed zero).

    ES6 ToString uses fixed-form for numbers whose decimal exponent ``k``
    satisfies ``-6 <= k - n < n`` where ``n`` is the number of significant
    digits, and exponential form otherwise. Python's ``repr`` chooses the
    shortest round-trip representation but uses different boundaries for
    fixed vs exponential form. We compute the digits via ``repr`` then
    rewrite the form to match ES6 when the magnitudes diverge.
    """
    if math.isnan(value):
        raise ValueError("NaN is not a valid canonical JSON number")
    if math.isinf(value):
        raise ValueError("Infinity is not a valid canonical JSON number")

    # Negative zero collapses to zero per ES6 ToString step 2.
    if value == 0:
        return "0"

    # Integer-valued floats render without a fractional part.
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))

    # Get the shortest round-trip digits via repr, then normalize to ES6 form.
    rendered = repr(value).replace("E", "e")
    sign = ""
    if rendered.startswith("-"):
        sign = "-"
        rendered = rendered[1:]

    if "e" in rendered:
        mantissa, _, exp_str = rendered.partition("e")
        exp = int(exp_str)
    else:
        mantissa = rendered
        exp = 0

    # Split mantissa into digits + the position of the decimal point.
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
        digits = int_part + frac_part
        # Decimal position relative to the start of ``digits``: number of
        # digits before the decimal point at the original mantissa.
        decimal_pos = len(int_part)
    else:
        digits = mantissa
        decimal_pos = len(mantissa)
    # Strip leading zeros from digits, adjusting decimal_pos.
    stripped = digits.lstrip("0")
    leading_zeros = len(digits) - len(stripped)
    if not stripped:
        return "0"
    digits = stripped
    decimal_pos -= leading_zeros
    # Strip trailing zeros from digits (they do not affect the value).
    digits = digits.rstrip("0") or "0"
    # ``k`` is the decimal exponent of the most significant digit.
    n = len(digits)
    k = decimal_pos + exp  # number of digits to the left of decimal point

    # ES6 ToString: use fixed form when the result has between 1 and 21
    # significant digits AND the decimal-exponent range is in [-6, 21).
    # Specifically:
    #   if 0 < k <= 21 and k >= n: rendered as digits + "0" * (k - n)
    #   if 0 < k <= 21 and k < n:  digits[:k] + "." + digits[k:]
    #   if -6 < k <= 0:            "0." + "0" * -k + digits
    #   else:                      d "." d... "e+/- (k-1)"
    if 0 < k <= 21 and k >= n:
        body = digits + "0" * (k - n)
    elif 0 < k <= 21 and k < n:
        body = digits[:k] + "." + digits[k:]
    elif -6 < k <= 0:
        body = "0." + "0" * (-k) + digits
    else:
        if n == 1:
            body = digits + f"e{k - 1:+d}".replace("+0", "+").replace("-0", "-")
        else:
            body = digits[0] + "." + digits[1:] + f"e{k - 1:+d}".replace("+0", "+").replace("-0", "-")
        # Normalize exponent: ES6 has no leading zeros in the exponent and
        # always uses an explicit sign.
        mantissa_part, _, exp_part = body.partition("e")
        exp_sign = exp_part[0] if exp_part[0] in {"+", "-"} else "+"
        exp_digits = exp_part.lstrip("+-").lstrip("0") or "0"
        body = f"{mantissa_part}e{exp_sign}{exp_digits}"

    return sign + body
