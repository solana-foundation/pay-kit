# frozen_string_literal: true

require_relative "test_helper"

class CoreTest < Minitest::Test
  include RubyMppTestHelpers

  # Canonical JSON (RFC 8785) tests moved to json_canonical_rfc8785_test.rb;
  # RFC 3339 expires tests moved to expires_rfc3339_test.rb. See PR #102
  # review (inline comment 3298060956). The remaining JSON-touching test
  # below covers Header error branches and the JSON parser error path.

  def test_json_parser_and_header_error_branches
    assert_raises(ArgumentError) { ::PayCore::Json.parse("{") }
    assert_equal "hello", ::PayCore::Base64Url.decode(Base64.strict_encode64("hello"))
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Headers.parse_www_authenticate("Bearer token") }
    # Token-form values are valid per RFC 7235 sec 2.1.
    assert_equal({"id" => "abc"}, Mpp::Protocol::Core::Headers.parse_auth_params("id=abc"))
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Headers.parse_auth_params("=value") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Headers.parse_auth_params("id=a, id=b") }
  end

  def test_parse_auth_params_token_form_values
    params = Mpp::Protocol::Core::Headers.parse_auth_params("id=abc, realm=api, method=solana, intent=charge, request=e30")
    assert_equal "abc", params.fetch("id")
    assert_equal "api", params.fetch("realm")
    assert_equal "solana", params.fetch("method")
    assert_equal "e30", params.fetch("request")
  end

  def test_parse_www_authenticate_all_multi_challenge
    h = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30", Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "a", results[0].id
    assert_equal "b", results[1].id
  end

  def test_parse_www_authenticate_all_ignores_payment_inside_quoted_value
    h = 'Payment id="a", realm="api, Payment realm", method="solana", intent="charge", request="e30", Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "api, Payment realm", results[0].realm
    assert_equal "b", results[1].id
  end

  def test_parse_www_authenticate_all_partial_success
    # First challenge has an invalid method; second is valid. Should yield one challenge.
    h = 'Payment id="bad", realm="r", method="BAD", intent="charge", request="e30", ' \
        'Payment id="ok", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all(h)
    assert_equal 1, results.length
    assert_equal "ok", results[0].id
  end

  def test_split_payment_challenge_values_edges
    # Header that does not contain Payment scheme yields empty.
    assert_empty Mpp::Protocol::Core::Headers.parse_www_authenticate_all(["Bearer xyz"])
    # Tab after Payment.
    h = "Payment\tid=\"x\", realm=\"api\", method=\"solana\", intent=\"charge\", request=\"e30\""
    parsed = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 1, parsed.length
  end

  def test_parse_www_authenticate_all_string_input
    # String (not array) is wrapped via Array().
    h = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all(h)
    assert_equal 1, results.length
  end

  def test_parse_www_authenticate_all_scheme_boundary_single_payment
    h = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 1, results.length
    assert_equal "a", results.first.id
  end

  def test_parse_www_authenticate_all_payment_followed_by_bearer
    h = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", Bearer realm="oauth"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 1, results.length
    assert_equal "a", results.first.id
  end

  def test_parse_www_authenticate_all_bearer_followed_by_payment
    h = 'Bearer realm="oauth", Payment id="a", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 1, results.length
    assert_equal "a", results.first.id
  end

  def test_parse_www_authenticate_all_multiple_payment_schemes
    h = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", ' \
        'Payment id="b", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "a", results[0].id
    assert_equal "b", results[1].id
  end

  def test_parse_www_authenticate_all_interleaved_schemes
    h = 'Bearer realm="oauth", ' \
        'Payment id="a", realm="r", method="solana", intent="charge", request="e30", ' \
        'Basic realm="basic", ' \
        'Payment id="b", realm="r", method="solana", intent="charge", request="e30"'
    results = Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h])
    assert_equal 2, results.length
    assert_equal "a", results[0].id
    assert_equal "b", results[1].id
  end

  def test_payment_scheme_start_negatives
    # "Paymentx" without whitespace is not a scheme start; should yield empty.
    assert_empty Mpp::Protocol::Core::Headers.parse_www_authenticate_all(["Paymentid=x"])
    # Payment preceded by non-comma is not a scheme start.
    assert_empty Mpp::Protocol::Core::Headers.parse_www_authenticate_all(["X Payment id=x"])
  end

  def test_parse_auth_params_branches
    # BWS around `=`.
    params = Mpp::Protocol::Core::Headers.parse_auth_params('id ="x" , realm="api"')
    assert_equal "x", params.fetch("id")
    assert_equal "api", params.fetch("realm")
    # Multi-challenge empty header.
    assert_empty Mpp::Protocol::Core::Headers.parse_www_authenticate_all([])
    # Single-value challenge through all helper.
    h = 'Payment id="x", realm="api", method="solana", intent="charge", request="e30"'
    assert_equal 1, Mpp::Protocol::Core::Headers.parse_www_authenticate_all([h]).length
  end

  def test_header_parser_unescapes_quoted_values
    params = Mpp::Protocol::Core::Headers.parse_auth_params('realm="api\"quoted", id="x"')

    assert_equal 'api"quoted', params.fetch("realm")
    assert_equal "x", params.fetch("id")
    assert_empty Mpp::Protocol::Core::Headers.parse_auth_params(" , \t ")
  end

  def test_challenge_header_round_trip_and_hmac
    request = charge_request
    challenge = Mpp::Protocol::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: request.to_h,
      expires: "2027-01-01T00:00:00Z"
    )

    parsed = Mpp::Protocol::Core::Headers.parse_www_authenticate(Mpp::Protocol::Core::Headers.format_www_authenticate(challenge))

    assert_equal challenge.id, parsed.id
    assert parsed.verify?("secret")
    refute parsed.verify?("other")
    assert_equal request.to_h, parsed.decode_request
  end

  def test_challenge_fails_closed_on_invalid_expiry
    challenge = Mpp::Protocol::Core::Challenge.with_secret(
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
    challenge = Mpp::Protocol::Core::Challenge.with_secret(
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
    challenge = Mpp::Protocol::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: charge_request.to_h
    )
    credential = Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87})

    parsed = Mpp::Protocol::Core::Credential.from_authorization_header(credential.to_authorization_header)

    assert_equal challenge.id, parsed.challenge.id
    assert_equal "1" * 87, parsed.payload["signature"]

    sourced = Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87}, source: "wallet")
    assert_equal "wallet", sourced.to_h.fetch("source")
  end

  def test_challenge_and_credential_validation_edges
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Challenge.new(id: "", realm: "api", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Challenge.new(id: "id", realm: "", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Challenge.new(id: "id", realm: "api", method: "Solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "", request: "x") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "charge", request: "") }

    challenge = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "charge", request: charge_request.to_h)
    refute challenge.expired?
    assert_nil challenge.to_echo.expires
    refute Mpp::Protocol::Core::Challenge.new(id: "short", realm: challenge.realm, method: challenge.method, intent: challenge.intent, request: challenge.request).verify?("secret")
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Credential.from_authorization_header("Bearer token") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Credential.from_authorization_header("Payment #{"a" * (Mpp::Protocol::Core::Credential::MAX_TOKEN_LENGTH + 1)}") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: "bad") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::Credential.from_authorization_header("Payment #") }
    assert_raises(ArgumentError) { Mpp::Protocol::Core::ChallengeEcho.from_h("bad") }
  end

  def test_receipt_header_round_trip
    receipt = Mpp::Protocol::Core::Receipt.success(method: "solana", reference: "sig", challenge_id: "challenge", external_id: "order")

    parsed = Mpp::Protocol::Core::Headers.parse_receipt(Mpp::Protocol::Core::Headers.format_receipt(receipt))

    assert_equal "success", parsed.status
    assert_equal "sig", parsed.reference
    assert_equal "order", parsed.external_id
  end
end
