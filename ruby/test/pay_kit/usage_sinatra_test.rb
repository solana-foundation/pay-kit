# frozen_string_literal: true

require "base64"
require "json"
require "rack/test"

require_relative "../test_helper"
require "pay_kit/usage/sinatra"

class UsageSinatraTest < Minitest::Test
  include Rack::Test::Methods

  # Engine double mounted by the Sinatra extension.
  class StubEngine
    Open = Struct.new(:max_amount)

    def verify_open(_header)
      Open.new(100_000)
    end

    def settle_actual(_open, actual)
      {"success" => true, "transaction" => "SiG#{actual}", "network" => "n", "amount" => actual.to_s}
    end

    def payment_required(resource:)
      "CHALLENGE:#{resource}"
    end
  end

  ENGINE = StubEngine.new

  class DemoApp < ::Sinatra::Base
    set :environment, :test
    set :show_exceptions, false
    register ::PayKit::Usage::Sinatra
    require_usage engine: ENGINE, resource_path: "/usage", settlement_header: "x-payment-settlement-signature"

    get "/usage" do
      content_type :json
      usage_charge.charge(50_000)
      JSON.generate(ok: true, paid: true)
    end
  end

  def app
    DemoApp
  end

  def test_challenge_without_payment
    get "/usage"
    assert_equal 402, last_response.status
    assert_equal "CHALLENGE:/usage", last_response.headers[::PayKit::Protocols::X402::Constants::PAYMENT_REQUIRED_HEADER]
  end

  def test_settles_and_serves_with_payment
    get "/usage", {}, {"HTTP_PAYMENT_SIGNATURE" => "HDR"}

    assert_equal 200, last_response.status
    assert_equal "SiG50000", last_response.headers["x-payment-settlement-signature"]
    settlement = JSON.parse(Base64.strict_decode64(last_response.headers[::PayKit::Protocols::X402::Constants::PAYMENT_RESPONSE_HEADER]))
    assert_equal "50000", settlement["amount"]
    assert_equal true, JSON.parse(last_response.body)["paid"]
  end
end
