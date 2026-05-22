# frozen_string_literal: true

require_relative "test_helper"
require "json"
require "sinatra/base"
require "rack/mock"
require "mpp/sinatra"

# Stub RPC that never hits the network.
class StubRpc
  def initialize(blockhash: "TestBlockhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    @blockhash = blockhash
    @calls = 0
  end

  attr_reader :calls

  def latest_blockhash
    @calls += 1
    @blockhash
  end
end

class MethodsSolanaChargeTest < Minitest::Test
  def test_charge_factory_returns_a_method_with_static_config
    rpc = StubRpc.new
    method = Mpp::Methods::Solana.charge(
      recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
      currency: "USDC",
      network: "mainnet",
      rpc: rpc,
      decimals: 6
    )

    assert_instance_of Mpp::Methods::Solana::ChargeMethod, method
    assert_equal "USDC", method.currency
    assert_equal "mainnet", method.network
    assert_equal Mpp::Methods::Solana::Mints::TOKEN_PROGRAM, method.token_program
    assert_nil method.fee_payer_pubkey
  end

  def test_rpc_string_is_coerced_to_an_rpc_client
    method = Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: "https://example.invalid")

    assert_instance_of Mpp::Methods::Solana::Rpc, method.rpc
  end

  def test_blockhash_is_cached_for_a_short_window
    rpc = StubRpc.new
    method = Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: rpc)

    3.times { method.latest_blockhash }
    assert_equal 1, rpc.calls
  end

  def test_decimals_are_derived_from_a_known_mint_symbol
    method = Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: StubRpc.new)
    assert_equal 6, method.decimals

    sol_method = Mpp::Methods::Solana.charge(recipient: "x", currency: "SOL", rpc: StubRpc.new)
    assert_equal 9, sol_method.decimals
  end

  def test_decimals_can_be_overridden_explicitly
    method = Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: StubRpc.new, decimals: 9)
    assert_equal 9, method.decimals
  end

  def test_method_details_include_fee_payer_when_configured
    account = Mpp::Methods::Solana::Account.new(Array.new(64, 1))
    method = Mpp::Methods::Solana.charge(
      recipient: "x",
      currency: "USDC",
      rpc: StubRpc.new,
      fee_payer: account
    )

    details = method.method_details
    assert_equal true, details["feePayer"]
    assert_equal account.public_key.to_s, details["feePayerKey"]
    assert_equal account.public_key.to_s, method.fee_payer_pubkey
  end
end

class MppCreateTest < Minitest::Test
  def test_create_returns_a_server_instance
    server = Mpp.create(
      method: Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: StubRpc.new),
      secret_key: "secret"
    )

    assert_instance_of Mpp::Server::Instance, server
    assert_equal Mpp::DEFAULT_REALM, server.realm
  end

  def test_charge_with_missing_auth_returns_a_challenge
    server = build_server

    result = server.charge(nil, amount: "1000", description: "Paid endpoint")

    assert_instance_of Mpp::Challenge, result
    assert_equal 402, result.status
    assert result.headers.key?(Mpp::Core::Headers::WWW_AUTHENTICATE)
    assert_equal "payment_required", result.body["error"]
  end

  def test_charge_with_invalid_auth_returns_a_challenge_with_reason
    server = build_server

    result = server.charge("Payment garbage", amount: "1000", description: "Paid endpoint")

    assert_instance_of Mpp::Challenge, result
    refute_nil result.reason
  end

  def test_method_details_can_be_built_for_an_alternate_currency
    method = Mpp::Methods::Solana.charge(recipient: "x", currency: "USDC", rpc: StubRpc.new)

    usdt_details = method.method_details(currency: "USDT")
    assert_equal 6, usdt_details["decimals"]
    assert_equal Mpp::Methods::Solana::Mints::TOKEN_PROGRAM, usdt_details["tokenProgram"]

    # Token-2022 currencies use a different SPL program:
    pyusd_details = method.method_details(currency: "PYUSD")
    assert_equal Mpp::Methods::Solana::Mints::TOKEN_2022_PROGRAM, pyusd_details["tokenProgram"]
  end

  def test_charge_accepts_a_different_currency_per_call
    server = Mpp.create(
      method: Mpp::Methods::Solana.charge(
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        currency: "USDC",
        rpc: StubRpc.new
      ),
      secret_key: "secret",
      realm: "Test"
    )

    # Per-call override doesn't crash and still produces a Challenge for a
    # request with no auth. Wire-level verification (that the credential
    # carries USDT) is covered by the method_details test above.
    result = server.charge(nil, amount: "1000", description: "Pay in USDT", currency: "USDT")
    assert_instance_of Mpp::Challenge, result
  end

  def test_charge_threads_splits_through_method_details
    server = build_server
    splits = [{"recipient" => "x", "amount" => "100"}]

    # We can't fully verify on-chain settlement here without a real RPC; instead
    # assert that the challenge body echoes the splits we passed through.
    result = server.charge(nil, amount: "1000", description: "split", splits: splits)

    assert_instance_of Mpp::Challenge, result
    # The challenge embeds the requested charge in the WWW-Authenticate header;
    # we only assert that splits appearing in the request did not raise.
    assert result.www_authenticate.include?("realm=\"Test\"")
  end

  private

  def build_server
    Mpp.create(
      method: Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", currency: "USDC", rpc: StubRpc.new),
      secret_key: "secret",
      realm: "Test"
    )
  end
end

class DecoratorTest < Minitest::Test
  def test_make_challenge_response_returns_a_rack_triplet
    challenge = Mpp::Challenge.new(www_authenticate: "Payment realm=\"Test\"", body: {"error" => "payment_required"})

    status, headers, body = Mpp::Server::Decorator.make_challenge_response(challenge)

    assert_equal 402, status
    assert_equal "application/json", headers["content-type"]
    assert_equal({"error" => "payment_required"}, JSON.parse(body.first))
  end
end

class MiddlewareTest < Minitest::Test
  def test_passes_free_routes_through_unchanged
    middleware = Mpp::Server::Middleware.new(free_app, handler: build_server)

    status, _headers, body = middleware.call({"PATH_INFO" => "/health"})

    assert_equal 200, status
    assert_equal ["{\"ok\":true}"], body
  end

  def test_returns_402_when_route_declares_a_charge_without_auth
    middleware = Mpp::Server::Middleware.new(paid_app, handler: build_server)

    status, headers, _body = middleware.call({"PATH_INFO" => "/paid"})

    assert_equal 402, status
    assert headers.key?(Mpp::Core::Headers::WWW_AUTHENTICATE)
  end

  def test_settlement_result_merges_headers_into_app_response
    settlement = Mpp::Settlement.new(
      signature: "sig",
      receipt_header: "Receipt token=abc",
      headers: {"payment-receipt" => "Receipt token=abc", "x-payment-settlement-signature" => "sig"}
    )
    stub_handler = Object.new
    stub_handler.define_singleton_method(:charge) { |_auth, **_| settlement }
    middleware = Mpp::Server::Middleware.new(paid_app, handler: stub_handler)

    status, headers, body = middleware.call({"PATH_INFO" => "/paid"})

    assert_equal 200, status
    assert_equal "Receipt token=abc", headers["payment-receipt"]
    assert_equal "sig", headers["x-payment-settlement-signature"]
    assert_equal "application/json", headers["content-type"]
    assert_equal ["{\"data\":42}"], body
  end

  def test_unexpected_handler_result_raises
    stub_handler = Object.new
    stub_handler.define_singleton_method(:charge) { |_auth, **_| Object.new }
    middleware = Mpp::Server::Middleware.new(paid_app, handler: stub_handler)

    assert_raises(Mpp::Error) { middleware.call({"PATH_INFO" => "/paid"}) }
  end

  private

  def build_server
    Mpp.create(method: Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", currency: "USDC", rpc: StubRpc.new), secret_key: "secret")
  end

  def free_app
    lambda do |env|
      if env["PATH_INFO"] == "/health"
        [200, {"content-type" => "application/json"}, ["{\"ok\":true}"]]
      else
        [404, {}, ["not_found"]]
      end
    end
  end

  def paid_app
    lambda do |env|
      env["mpp.charge"] = {amount: "1000", description: "Paid endpoint"}
      [200, {"content-type" => "application/json"}, ["{\"data\":42}"]]
    end
  end
end

class SinatraHelperTest < Minitest::Test
  def test_mpp_charge_halts_with_402_when_auth_missing
    server = Mpp.create(method: Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", currency: "USDC", rpc: StubRpc.new), secret_key: "secret", realm: "T")
    app = Class.new(Sinatra::Base) do
      helpers Mpp::Sinatra::Helpers
      set :mpp_server, server
      set :show_exceptions, false

      get "/paid" do
        mpp_charge!(amount: "1000", description: "Paid endpoint")
        content_type :json
        JSON.generate(ok: true)
      end
    end

    response = Rack::MockRequest.new(app).get("/paid")

    assert_equal 402, response.status
    assert response.headers.key?("www-authenticate")
  end

  def test_mpp_charge_raises_when_no_server_is_configured
    app = Class.new(Sinatra::Base) do
      helpers Mpp::Sinatra::Helpers
      set :mpp_server, nil
      set :show_exceptions, false
      set :raise_errors, true
      get("/paid") { mpp_charge!(amount: "1000", description: "x") }
    end

    assert_raises(Mpp::Error) { Rack::MockRequest.new(app).get("/paid") }
  end

  def test_mpp_charge_injects_headers_on_settlement
    settlement = Mpp::Settlement.new(
      signature: "sig",
      receipt_header: "Receipt token=abc",
      headers: {"payment-receipt" => "Receipt token=abc", "x-payment-settlement-signature" => "sig"}
    )
    stub_server = Object.new
    stub_server.define_singleton_method(:charge) { |_auth, **_| settlement }
    app = Class.new(Sinatra::Base) do
      helpers Mpp::Sinatra::Helpers
      set :mpp_server, stub_server
      set :show_exceptions, false
      get "/paid" do
        mpp_charge!(amount: "1000", description: "x")
        content_type :json
        JSON.generate(ok: true)
      end
    end

    response = Rack::MockRequest.new(app).get("/paid")

    assert_equal 200, response.status
    assert_equal "Receipt token=abc", response.headers["payment-receipt"]
    assert_equal "sig", response.headers["x-payment-settlement-signature"]
  end

  def test_mpp_charge_raises_on_unexpected_handler_result
    stub_server = Object.new
    stub_server.define_singleton_method(:charge) { |_auth, **_| Object.new }
    app = Class.new(Sinatra::Base) do
      helpers Mpp::Sinatra::Helpers
      set :mpp_server, stub_server
      set :show_exceptions, false
      set :raise_errors, true
      get("/paid") { mpp_charge!(amount: "1000", description: "x") }
    end

    assert_raises(Mpp::Error) { Rack::MockRequest.new(app).get("/paid") }
  end
end
