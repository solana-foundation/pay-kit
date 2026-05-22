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
      mint:      "USDC",
      network:   "mainnet-beta",
      rpc:       rpc,
      decimals:  6
    )

    assert_instance_of Mpp::Methods::Solana::ChargeMethod, method
    assert_equal "USDC", method.mint
    assert_equal "mainnet-beta", method.network
    assert_equal Mpp::Methods::Solana::Mints::TOKEN_PROGRAM, method.token_program
    assert_nil method.fee_payer_pubkey
  end

  def test_rpc_string_is_coerced_to_an_rpc_client
    method = Mpp::Methods::Solana.charge(recipient: "x", mint: "USDC", rpc: "https://example.invalid")

    assert_instance_of Mpp::Methods::Solana::Rpc, method.rpc
  end

  def test_blockhash_is_cached_for_a_short_window
    rpc = StubRpc.new
    method = Mpp::Methods::Solana.charge(recipient: "x", mint: "USDC", rpc: rpc)

    3.times { method.latest_blockhash }
    assert_equal 1, rpc.calls
  end
end

class MppCreateTest < Minitest::Test
  def test_create_returns_a_server_instance
    server = Mpp.create(
      method:     Mpp::Methods::Solana.charge(recipient: "x", mint: "USDC", rpc: StubRpc.new),
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

  private

  def build_server
    Mpp.create(
      method:     Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", mint: "USDC", rpc: StubRpc.new),
      secret_key: "secret",
      realm:      "Test"
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

  private

  def build_server
    Mpp.create(method: Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", mint: "USDC", rpc: StubRpc.new), secret_key: "secret")
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
    server = Mpp.create(method: Mpp::Methods::Solana.charge(recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", mint: "USDC", rpc: StubRpc.new), secret_key: "secret", realm: "T")
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
end
