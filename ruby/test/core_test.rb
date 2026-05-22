# frozen_string_literal: true

require_relative "test_helper"

class CoreTest < Minitest::Test
  include RubyMppTestHelpers

  def test_canonical_json_orders_nested_keys
    value = {"b" => 2, "a" => [{"b" => true, "a" => false}]}

    assert_equal '{"a":[{"a":false,"b":true}],"b":2}', SolanaMpp::Core::Json.canonical_generate(value)
    assert_equal "eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ", SolanaMpp::Core::Base64Url.encode(SolanaMpp::Core::Json.canonical_generate(value))
  end

  def test_json_and_header_error_branches
    assert_raises(ArgumentError) { SolanaMpp::Core::Json.canonical_generate(Object.new) }
    assert_raises(ArgumentError) { SolanaMpp::Core::Json.parse("{") }
    assert_equal "hello", SolanaMpp::Core::Base64Url.decode(Base64.strict_encode64("hello"))
    assert_raises(ArgumentError) { SolanaMpp::Core::Headers.parse_www_authenticate("Bearer token") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Headers.parse_auth_params("id=unquoted") }
  end

  def test_header_parser_unescapes_quoted_values
    params = SolanaMpp::Core::Headers.parse_auth_params('realm="api\"quoted", id="x"')

    assert_equal 'api"quoted', params.fetch("realm")
    assert_equal "x", params.fetch("id")
    assert_empty SolanaMpp::Core::Headers.parse_auth_params(" , \t ")
  end

  def test_challenge_header_round_trip_and_hmac
    request = charge_request
    challenge = SolanaMpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: request.to_h,
      expires: "2027-01-01T00:00:00Z"
    )

    parsed = SolanaMpp::Core::Headers.parse_www_authenticate(SolanaMpp::Core::Headers.format_www_authenticate(challenge))

    assert_equal challenge.id, parsed.id
    assert parsed.verify?("secret")
    refute parsed.verify?("other")
    assert_equal request.to_h, parsed.decode_request
  end

  def test_challenge_fails_closed_on_invalid_expiry
    challenge = SolanaMpp::Core::Challenge.with_secret(
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
    challenge = SolanaMpp::Core::Challenge.with_secret(
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
    challenge = SolanaMpp::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "solana",
      intent: "charge",
      request: charge_request.to_h
    )
    credential = SolanaMpp::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87})

    parsed = SolanaMpp::Core::Credential.from_authorization_header(credential.to_authorization_header)

    assert_equal challenge.id, parsed.challenge.id
    assert_equal "1" * 87, parsed.payload["signature"]

    sourced = SolanaMpp::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => "1" * 87}, source: "wallet")
    assert_equal "wallet", sourced.to_h.fetch("source")
  end

  def test_challenge_and_credential_validation_edges
    assert_raises(ArgumentError) { SolanaMpp::Core::Challenge.new(id: "", realm: "api", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Challenge.new(id: "id", realm: "", method: "solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Challenge.new(id: "id", realm: "api", method: "Solana", intent: "charge", request: "x") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "", request: "x") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Challenge.new(id: "id", realm: "api", method: "solana", intent: "charge", request: "") }

    challenge = SolanaMpp::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "charge", request: charge_request.to_h)
    refute challenge.expired?
    assert_nil challenge.to_echo.expires
    refute SolanaMpp::Core::Challenge.new(id: "short", realm: challenge.realm, method: challenge.method, intent: challenge.intent, request: challenge.request).verify?("secret")
    assert_raises(ArgumentError) { SolanaMpp::Core::Credential.from_authorization_header("Bearer token") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Credential.from_authorization_header("Payment #{"a" * (SolanaMpp::Core::Credential::MAX_TOKEN_LENGTH + 1)}") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Credential.new(challenge: challenge.to_echo, payload: "bad") }
    assert_raises(ArgumentError) { SolanaMpp::Core::Credential.from_authorization_header("Payment #") }
    assert_raises(ArgumentError) { SolanaMpp::Core::ChallengeEcho.from_h("bad") }
  end

  def test_receipt_header_round_trip
    receipt = SolanaMpp::Core::Receipt.success(method: "solana", reference: "sig", challenge_id: "challenge", external_id: "order")

    parsed = SolanaMpp::Core::Headers.parse_receipt(SolanaMpp::Core::Headers.format_receipt(receipt))

    assert_equal "success", parsed.status
    assert_equal "sig", parsed.reference
    assert_equal "order", parsed.external_id
  end
end
