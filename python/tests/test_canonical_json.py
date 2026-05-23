"""Tests for the RFC 8785 canonical JSON encoder.

Pinned to the cross-SDK F2 + F3 + F4 lock from PR #99 / #102 (Ruby, PHP,
Lua). Every vector below MUST produce byte-identical output across every
mpp-sdk language; divergence here breaks HMAC challenge id verification.
"""

from __future__ import annotations

import pytest

from solana_mpp._canonical_json import encode_canonical


class TestKeySort:
    """F2 lock: keys MUST sort by UTF-16 code unit, not by Unicode code point.

    The two orderings differ on supplementary-plane characters (U+10000 and
    above). UTF-16 splits those into surrogate pairs starting at U+D800,
    while Python's str < uses the raw code point. RFC 8785 section 3.2.3.
    """

    def test_ascii_keys_sorted(self):
        assert encode_canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_supplementary_plane_sorted_by_utf16(self):
        # U+1F600 (GRINNING FACE) encodes as UTF-16 surrogate pair
        # (0xD83D, 0xDE00); the first code unit 0xD83D sorts AFTER any
        # Basic Multilingual Plane key like 0xFB00. So {"ﬀ", "\U0001F600"}
        # under UTF-16 ordering puts ﬀ first, even though the raw code
        # point of \U0001F600 (= 128512) is greater than ﬀ (= 64256)
        # and a code-point sort would put them in the same order — but
        # Python's str compare is by code point, which happens to agree
        # here. The real divergence is at  (Private Use) vs \U0001D11E
        # (G CLEF): code-point sort puts  first; UTF-16 sort puts
        # the supplementary one first because its first surrogate 0xD834
        # is BELOW 0xE000.
        result = encode_canonical({"": 1, "\U0001d11e": 2})
        # Surrogate-first ordering: \U0001D11E comes before .
        assert result == b'{"\xf0\x9d\x84\x9e":2,"\xee\x80\x80":1}'

    def test_nested_object_keys_also_sorted(self):
        assert encode_canonical({"outer": {"b": 1, "a": 2}}) == b'{"outer":{"a":2,"b":1}}'


class TestNumberSerialization:
    """F3 lock: numbers MUST render per ECMA-262 7.1.12.1 ToString."""

    def test_integer(self):
        assert encode_canonical(42) == b"42"

    def test_negative_integer(self):
        assert encode_canonical(-1) == b"-1"

    def test_zero(self):
        assert encode_canonical(0) == b"0"

    def test_negative_zero_collapses(self):
        assert encode_canonical(-0.0) == b"0"

    def test_one_e_twenty_one(self):
        # 1e21 must render with the exponential form, not 21 zeros.
        assert encode_canonical(1e21) == b"1e+21"

    def test_one_e_minus_seven(self):
        assert encode_canonical(1e-7) == b"1e-7"

    def test_one_e_minus_six_uses_fixed_form(self):
        # ES6 ToString uses fixed-form notation for ``k > -6``. 0.000001
        # (1e-6) renders as ``"0.000001"`` not ``"1e-6"``. Codex P2 fix.
        assert encode_canonical(1e-6) == b"0.000001"
        assert encode_canonical(0.000001) == b"0.000001"

    def test_decimal_below_one(self):
        # 0.5 must render in fixed form, not exponential.
        assert encode_canonical(0.5) == b"0.5"

    def test_negative_decimal(self):
        assert encode_canonical(-0.5) == b"-0.5"

    def test_large_integer_float(self):
        assert encode_canonical(100.0) == b"100"

    def test_integer_valued_float(self):
        # ES6 ToString drops the fractional part for integer-valued numbers.
        assert encode_canonical(1.0) == b"1"

    def test_rejects_nan(self):
        with pytest.raises(ValueError, match="NaN"):
            encode_canonical(float("nan"))

    def test_rejects_infinity(self):
        with pytest.raises(ValueError, match="Infinity"):
            encode_canonical(float("inf"))


class TestStringEncoding:
    """F4 lock: lone surrogates MUST be rejected per RFC 8785 section 3.2.2."""

    def test_basic_ascii(self):
        assert encode_canonical("hello") == b'"hello"'

    def test_escapes_quotes_and_backslash(self):
        assert encode_canonical('a"b\\c') == b'"a\\"b\\\\c"'

    def test_short_escapes(self):
        assert encode_canonical("\b\t\n\f\r") == b'"\\b\\t\\n\\f\\r"'

    def test_control_character_unicode_escape(self):
        assert encode_canonical("\x01") == b'"\\u0001"'

    def test_rejects_lone_high_surrogate(self):
        # Python string with a lone high surrogate. UTF-8 strict encode
        # raises, mirroring the RFC 8785 rejection.
        with pytest.raises(ValueError, match="lone surrogate"):
            encode_canonical("\ud834")

    def test_rejects_lone_low_surrogate(self):
        with pytest.raises(ValueError, match="lone surrogate"):
            encode_canonical("\udd1e")

    def test_valid_supplementary_plane_codepoint(self):
        # A complete surrogate pair (U+1D11E = G CLEF) is valid; it encodes
        # to a 4-byte UTF-8 sequence.
        result = encode_canonical("\U0001d11e")
        assert result == b'"\xf0\x9d\x84\x9e"'


class TestArrayAndComposite:
    def test_empty_array(self):
        assert encode_canonical([]) == b"[]"

    def test_array_of_mixed(self):
        assert encode_canonical([1, "a", True, None]) == b'[1,"a",true,null]'

    def test_empty_object(self):
        assert encode_canonical({}) == b"{}"

    def test_realistic_charge_request(self):
        # The charge ``request`` field on the wire. The byte ordering of
        # the keys here is the exact thing every SDK has to agree on for
        # the HMAC challenge id to verify across languages.
        result = encode_canonical(
            {
                "amount": "1000000",
                "currency": "USDC",
                "recipient": "11111111111111111111111111111112",
            }
        )
        assert result == (b'{"amount":"1000000","currency":"USDC","recipient":"11111111111111111111111111111112"}')
