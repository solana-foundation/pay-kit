# frozen_string_literal: true

require_relative "test_helper"

class CoreTest < Minitest::Test
  include RubyMppTestHelpers

  def test_canonical_json_orders_nested_keys
    value = {"b" => 2, "a" => [{"b" => true, "a" => false}]}

    assert_equal '{"a":[{"a":false,"b":true}],"b":2}', Mpp::Core::Json.canonical_generate(value)
    assert_equal "eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ", Mpp::Core::Base64Url.encode(Mpp::Core::Json.canonical_generate(value))
  end

  def test_json_and_header_error_branches
    assert_raises(ArgumentError) { Mpp::Core::Json.canonical_generate(Object.new) }
    assert_raises(ArgumentError) { Mpp::Core::Json.parse("{") }
    assert_equal "hello", Mpp::Core::Base64Url.decode(Base64.strict_encode64("hello"))
    assert_raises(ArgumentError) { Mpp::Core::Headers.parse_www_authenticate("Bearer token") }
    # Token-form values are valid per RFC 7235 sec 2.1.
    assert_equal({"id" => "abc"}, Mpp::Core::Headers.parse_auth_params("id=abc"))
    assert_raises(ArgumentError) { Mpp::Core::Headers.parse_auth_params("=value") }
    assert_raises(ArgumentError) { Mpp::Core::Headers.parse_auth_params("id=a, id=b") }
  end

  def test_parse_auth_params_token_form_values
    params = Mpp::Core::Headers.parse_auth_params("id=abc, realm=api, method=solana, intent=charge, request=e30")
    assert_equal "abc", params.fetch("id")
    assert_equal "api", params.fetch("realm")
    assert_equal "solana", params.fetch("method")
    assert_equal "e30", params.fetch("request")
  end

  def test_parse_www_authenticate_all_multi_challenge
    h = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30", Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
    results = Mpp::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "a", results[0].id
    assert_equal "b", results[1].id
  end

  def test_parse_www_authenticate_all_ignores_payment_inside_quoted_value
    h = 'Payment id="a", realm="api, Payment realm", method="solana", intent="charge", request="e30", Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
    results = Mpp::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "api, Payment realm", results[0].realm
    assert_equal "b", results[1].id
  end

  def test_parse_www_authenticate_all_partial_success
    # First challenge has an invalid method; second is valid. Should yield one challenge.
    h = 'Payment id="bad", realm="r", method="BAD", intent="charge", request="e30", ' \
        'Payment id="ok", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Core::Headers.parse_www_authenticate_all(h)
    assert_equal 1, results.length
    assert_equal "ok", results[0].id
  end

  def test_canonical_json_es6_extra
    # ES6 ToString: 1e-6 plain notation, 1e-7 exponential.
    assert_equal "0.000001", Mpp::Core::Json.canonical_generate(1e-6)
    assert_equal "1e-7", Mpp::Core::Json.canonical_generate(1e-7)
    # 1e20 plain notation (still fits in plain form).
    assert_equal "100000000000000000000", Mpp::Core::Json.canonical_generate(1e20)
    # 0.1 + 0.2 round-trip preserves precision.
    assert_equal "0.30000000000000004", Mpp::Core::Json.canonical_generate(0.1 + 0.2)
  end

  def test_canonical_json_utf16_key_order
    # 'é' (U+00E9) > 'f' (U+0066) in UTF-16 code units, so 'f' sorts first.
    value = {"é" => 1, "f" => 2}
    assert_equal '{"f":2,"é":1}', Mpp::Core::Json.canonical_generate(value)
  end

  def test_canonical_json_es6_number_serialization
    assert_equal "1e+21", Mpp::Core::Json.canonical_generate(1e21)
    assert_equal "0.1", Mpp::Core::Json.canonical_generate(0.1)
    assert_equal "0", Mpp::Core::Json.canonical_generate(-0.0)
    assert_equal "0", Mpp::Core::Json.canonical_generate(0)
  end

  def test_canonical_json_rejects_lone_surrogates
    # Build a UTF-8 byte sequence containing a lone high surrogate (U+D834) via raw bytes.
    lone = [0xED, 0xA0, 0xB4].pack("C*").force_encoding(Encoding::UTF_8)
    assert_raises(ArgumentError) { Mpp::Core::Json.canonical_generate({"k" => lone}) }
  end

  def test_canonical_json_covers_branches
    assert_equal "true", Mpp::Core::Json.canonical_generate(true)
    assert_equal "false", Mpp::Core::Json.canonical_generate(false)
    assert_equal "null", Mpp::Core::Json.canonical_generate(nil)
    assert_equal "[1,2,3]", Mpp::Core::Json.canonical_generate([1, 2, 3])
    assert_equal '"\\u0001"', Mpp::Core::Json.canonical_generate("\x01")
    assert_equal '"\\n"', Mpp::Core::Json.canonical_generate("\n")
    assert_equal '{"a":1}', Mpp::Core::Json.canonical_generate({a: 1})
    assert_raises(ArgumentError) { Mpp::Core::Json.canonical_generate({1 => 2}) }
    assert_raises(ArgumentError) { Mpp::Core::Json.canonical_generate(Float::NAN) }
    assert_raises(ArgumentError) { Mpp::Core::Json.canonical_generate(Float::INFINITY) }
    assert_equal "1e-7", Mpp::Core::Json.canonical_generate(1e-7)
  end

  def test_split_payment_challenge_values_edges
    # Header that does not contain Payment scheme yields empty.
    assert_empty Mpp::Core::Headers.parse_www_authenticate_all(["Bearer xyz"])
    # Tab after Payment.
    h = "Payment\tid=\"x\", realm=\"api\", method=\"solana\", intent=\"charge\", request=\"e30\""
    parsed = Mpp::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 1, parsed.length
  end

  def test_expires_strict_rfc3339_extra
    # Month 13 rejected.
    c = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-13-01T00:00:00Z")
    assert c.expired?
    # Minute 60 rejected.
    c2 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:60:00Z")
    assert c2.expired?
    # Day 0 rejected.
    c3 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-00T00:00:00Z")
    assert c3.expired?
  end

  def test_parse_www_authenticate_all_string_input
    # String (not array) is wrapped via Array().
    h = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30"'
    results = Mpp::Core::Headers.parse_www_authenticate_all(h)
    assert_equal 1, results.length
  end

  def test_payment_scheme_start_negatives
    # "Paymentx" without whitespace is not a scheme start; should yield empty.
    assert_empty Mpp::Core::Headers.parse_www_authenticate_all(["Paymentid=x"])
    # Payment preceded by non-comma is not a scheme start.
    assert_empty Mpp::Core::Headers.parse_www_authenticate_all(["X Payment id=x"])
  end

  def test_canonical_json_branches_extra
    # Symbol keys converted.
    assert_equal '{"a":1,"b":2}', Mpp::Core::Json.canonical_generate({a: 1, b: 2})
    # Integer.
    assert_equal "42", Mpp::Core::Json.canonical_generate(42)
    # Negative number.
    assert_equal "-3.14", Mpp::Core::Json.canonical_generate(-3.14)
    # Backslash and quote escapes.
    assert_equal '"a\\\\b"', Mpp::Core::Json.canonical_generate("a\\b")
    assert_equal '"a\\"b"', Mpp::Core::Json.canonical_generate("a\"b")
    # Empty array, empty object.
    assert_equal "[]", Mpp::Core::Json.canonical_generate([])
    assert_equal "{}", Mpp::Core::Json.canonical_generate({})
    # Tab and backspace control chars.
    assert_equal '"\\t"', Mpp::Core::Json.canonical_generate("\t")
    assert_equal '"\\b"', Mpp::Core::Json.canonical_generate("\b")
    assert_equal '"\\f"', Mpp::Core::Json.canonical_generate("\f")
    assert_equal '"\\r"', Mpp::Core::Json.canonical_generate("\r")
  end

  def test_expires_strict_rfc3339_branches
    # Lowercase t accepted.
    c1 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01t00:00:00Z")
    refute c1.expired?
    # Fractional seconds accepted.
    c2 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00.123Z")
    refute c2.expired?
    # Numeric offset accepted.
    c3 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00+00:00")
    refute c3.expired?
    # Invalid calendar date rejected (Feb 30).
    c4 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-02-30T00:00:00Z")
    assert c4.expired?
    # Hour 24 rejected.
    c5 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T24:00:00Z")
    assert c5.expired?
  end

  def test_parse_auth_params_branches
    # BWS around `=`.
    params = Mpp::Core::Headers.parse_auth_params('id ="x" , realm="api"')
    assert_equal "x", params.fetch("id")
    assert_equal "api", params.fetch("realm")
    # Multi-challenge empty header.
    assert_empty Mpp::Core::Headers.parse_www_authenticate_all([])
    # Single-value challenge through all helper.
    h = 'Payment id="x", realm="api", method="solana", intent="charge", request="e30"'
    assert_equal 1, Mpp::Core::Headers.parse_www_authenticate_all([h]).length
  end

  def test_expires_strict_rfc3339
    chal = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00Z")
    refute chal.expired?
    chal2 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "tomorrow")
    assert chal2.expired?, "non-RFC-3339 expires must fail closed"
    chal3 = Mpp::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "10000-01-01T00:00:00Z")
    assert chal3.expired?, "5-digit year must fail closed"
  end

  def test_header_parser_unescapes_quoted_values
    params = Mpp::Core::Headers.parse_auth_params('realm="api\"quoted", id="x"')

    assert_equal 'api"quoted', params.fetch("realm")
    assert_equal "x", params.fetch("id")
    assert_empty Mpp::Core::Headers.parse_auth_params(" , \t ")
  end

  def test_challenge_header_round_trip_and_hmac
    request = charge_request
    challenge = Mpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: request.to_h,
      expires: "2027-01-01T00:00:00Z"
    )

    parsed = Mpp::Core::Headers.parse_www_authenticate(Mpp::Core::Headers.format_www_authenticate(challenge))

    assert_equal challenge.id, parsed.id
    assert parsed.verify?("secret")
    refute parsed.verify?("other")
    assert_equal request.to_h, parsed.decode_request
  end

  def test_challenge_fails_closed_on_invalid_expiry
    challenge = Mpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: charge_request.to_h,
      expires: "not-time"
    )

    assert challenge.expired?
  end

  def test_challenge_expired_past_and_optional_fields
    challenge = Mpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: charge_request.to_h,
      expires: "2020-01-01T00:00:00Z",
      description: "paid route",
      digest: "sha-256=:abc:",
      opaque: "opaque"
    )

    assert challenge.expired?
    echo = challenge.to_echo
    assert_equal "sha-256=:abc:", echo.digest
    assert_equal "opaque", echo.opaque
  end

  def test_credential_authorization_round_trip
    challenge = Mpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: charge_request.to_h
    )
    credential = Mpp::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87})

    parsed = Mpp::Core::Credential.from_authorization_header(credential.to_authorization_header)

    assert_equal challenge.id, parsed.challenge.id
    assert_equal "1" * 87, parsed.payload["signature"]

    sourced = Mpp::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87}, source: "wallet")
    assert_equal "wallet", sourced.to_h.fetch("source")
  end

  def test_challenge_and_credential_validation_edges
    assert_raises(ArgumentError) { Mpp::Core::Challenge.new(id: "", realm: "api", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Core::Challenge.new(id: "id", realm: "", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Core::Challenge.new(id: "id", realm: "api", method: "Solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "", request: "x") }
    assert_raises(ArgumentError) { Mpp::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "charge", request: "") }

    challenge = Mpp::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "charge", request: charge_request.to_h)
    refute challenge.expired?
    assert_nil challenge.to_echo.expires
    refute Mpp::Core::Challenge.new(id: "short", realm: challenge.realm, method: challenge.method, intent: challenge.intent, request: challenge.request).verify?("secret")
    assert_raises(ArgumentError) { Mpp::Core::Credential.from_authorization_header("Bearer token") }
    assert_raises(ArgumentError) { Mpp::Core::Credential.from_authorization_header("Payment #{"a" * (Mpp::Core::Credential::MAX_TOKEN_LENGTH + 1)}") }
    assert_raises(ArgumentError) { Mpp::Core::Credential.new(challenge: challenge.to_echo, payload: "bad") }
    assert_raises(ArgumentError) { Mpp::Core::Credential.from_authorization_header("Payment #") }
    assert_raises(ArgumentError) { Mpp::Core::ChallengeEcho.from_h("bad") }
  end

  def test_receipt_header_round_trip
    receipt = Mpp::Core::Receipt.success(method: "solana", reference: "sig", challenge_id: "challenge", external_id: "order")

    parsed = Mpp::Core::Headers.parse_receipt(Mpp::Core::Headers.format_receipt(receipt))

    assert_equal "success", parsed.status
    assert_equal "sig", parsed.reference
    assert_equal "order", parsed.external_id
  end
end
