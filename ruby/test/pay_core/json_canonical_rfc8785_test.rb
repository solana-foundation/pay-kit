# frozen_string_literal: true

# RFC 8785 (JSON Canonicalization Scheme) test cases for the Ruby SDK.
# Isolated from core_test.rb per PR #102 review (inline comment 3298060956)
# so RFC 8785 (canonical JSON) and RFC 3339 (expires parser) live in
# dedicated files. Battle-tested vector imports are tracked separately
# (see follow-up issue referenced on the same PR thread).
require_relative "../test_helper"
require "base64"

class JsonCanonicalRfc8785Test < Minitest::Test
  include RubyMppTestHelpers

  def test_canonical_json_orders_nested_keys
    value = {"b" => 2, "a" => [{"b" => true, "a" => false}]}

    assert_equal '{"a":[{"a":false,"b":true}],"b":2}', ::PayCore::Json.canonical_generate(value)
    assert_equal "eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ", ::PayCore::Base64Url.encode(::PayCore::Json.canonical_generate(value))
  end

  def test_canonical_json_es6_extra
    # ES6 ToString: 1e-6 plain notation, 1e-7 exponential.
    assert_equal "0.000001", ::PayCore::Json.canonical_generate(1e-6)
    assert_equal "1e-7", ::PayCore::Json.canonical_generate(1e-7)
    # 1e20 plain notation (still fits in plain form).
    assert_equal "100000000000000000000", ::PayCore::Json.canonical_generate(1e20)
    # 0.1 + 0.2 round-trip preserves precision.
    assert_equal "0.30000000000000004", ::PayCore::Json.canonical_generate(0.1 + 0.2)
  end

  def test_canonical_json_utf16_key_order
    # 'é' (U+00E9) > 'f' (U+0066) in UTF-16 code units, so 'f' sorts first.
    value = {"é" => 1, "f" => 2}
    assert_equal '{"f":2,"é":1}', ::PayCore::Json.canonical_generate(value)
  end

  def test_canonical_json_es6_number_serialization
    assert_equal "1e+21", ::PayCore::Json.canonical_generate(1e21)
    assert_equal "0.1", ::PayCore::Json.canonical_generate(0.1)
    assert_equal "0", ::PayCore::Json.canonical_generate(-0.0)
    assert_equal "0", ::PayCore::Json.canonical_generate(0)
  end

  def test_canonical_json_rejects_lone_surrogates
    # Build a UTF-8 byte sequence containing a lone high surrogate (U+D834) via raw bytes.
    lone = [0xED, 0xA0, 0xB4].pack("C*").force_encoding(Encoding::UTF_8)
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({"k" => lone}) }
  end

  def test_canonical_json_covers_branches
    assert_equal "true", ::PayCore::Json.canonical_generate(true)
    assert_equal "false", ::PayCore::Json.canonical_generate(false)
    assert_equal "null", ::PayCore::Json.canonical_generate(nil)
    assert_equal "[1,2,3]", ::PayCore::Json.canonical_generate([1, 2, 3])
    assert_equal '"\\u0001"', ::PayCore::Json.canonical_generate("\x01")
    assert_equal '"\\n"', ::PayCore::Json.canonical_generate("\n")
    assert_equal '{"a":1}', ::PayCore::Json.canonical_generate({a: 1})
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({1 => 2}) }
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate(Float::NAN) }
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate(Float::INFINITY) }
    assert_equal "1e-7", ::PayCore::Json.canonical_generate(1e-7)
  end

  # Cover the explicit error branches in the encoder so SimpleCov branch
  # coverage stays >= 90 cross-SDK baseline.
  def test_canonical_json_rejects_non_string_keys
    # Integer key forced via raw Hash construction.
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({1 => "v"}) }
    # Non-string non-symbol non-integer key.
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({Object.new => "v"}) }
  end

  def test_canonical_json_rejects_duplicate_keys_after_symbol_coerce
    # String "a" and symbol :a both coerce to "a"; duplicate must raise.
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({"a" => 1, :a => 2}) }
  end

  def test_canonical_json_rejects_unsupported_value_type
    # Hits the case-else branch in encode_value when the value is not
    # Hash/Array/String/Integer/Float/true/false/nil.
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate(Object.new) }
    assert_raises(ArgumentError) { ::PayCore::Json.canonical_generate({k: Object.new}) }
  end

  def test_canonical_json_zero_floats_round_trip
    # Exercises the digits='0' fallback branch in shortest_digits_and_exponent.
    assert_equal "0", ::PayCore::Json.canonical_generate(0.0)
    assert_equal "0", ::PayCore::Json.canonical_generate(-0.0)
  end

  def test_canonical_json_branches_extra
    # Symbol keys converted.
    assert_equal '{"a":1,"b":2}', ::PayCore::Json.canonical_generate({a: 1, b: 2})
    # Integer.
    assert_equal "42", ::PayCore::Json.canonical_generate(42)
    # Negative number.
    assert_equal "-3.14", ::PayCore::Json.canonical_generate(-3.14)
    # Backslash and quote escapes.
    assert_equal '"a\\\\b"', ::PayCore::Json.canonical_generate("a\\b")
    assert_equal '"a\\"b"', ::PayCore::Json.canonical_generate("a\"b")
    # Empty array, empty object.
    assert_equal "[]", ::PayCore::Json.canonical_generate([])
    assert_equal "{}", ::PayCore::Json.canonical_generate({})
    # Tab and backspace control chars.
    assert_equal '"\\t"', ::PayCore::Json.canonical_generate("\t")
    assert_equal '"\\b"', ::PayCore::Json.canonical_generate("\b")
    assert_equal '"\\f"', ::PayCore::Json.canonical_generate("\f")
    assert_equal '"\\r"', ::PayCore::Json.canonical_generate("\r")
  end
end
