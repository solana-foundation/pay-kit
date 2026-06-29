# frozen_string_literal: true

require "base64"
require "json"
require "stringio"

require_relative "../test_helper"
require "pay_kit/usage"

class UsageChargeTest < Minitest::Test
  Charge = ::PayKit::Usage::Charge

  def test_starts_at_zero
    assert_equal 0, Charge.new(100).settled_base_units
  end

  def test_accumulates
    charge = Charge.new(100)
    charge.charge(30)
    charge.charge(20)
    assert_equal 50, charge.settled_base_units
  end

  def test_clamps_to_ceiling
    charge = Charge.new(100)
    charge.charge(250)
    assert_equal 100, charge.settled_base_units
  end

  def test_floors_at_zero
    charge = Charge.new(100)
    charge.charge(-10)
    assert_equal 0, charge.settled_base_units
  end

  def test_exposes_max
    assert_equal 100, Charge.new(100).max_base_units
  end

  def test_deliver_policy_fail_closes_on_zero
    refute ::PayKit::Usage.deliver?(0)
    assert ::PayKit::Usage.deliver?(1)
  end
end

class UsageMiddlewareTest < Minitest::Test
  Constants = ::PayKit::Protocols::X402::Constants

  # Minimal engine double: records verify_open / settle_actual calls.
  class FakeEngine
    attr_reader :settled_with
    attr_accessor :raise_on_verify, :raise_on_settle

    Open = Struct.new(:max_amount)

    def initialize(raise_on_verify: nil)
      @raise_on_verify = raise_on_verify
      @raise_on_settle = nil
      @settled_with = []
    end

    def verify_open(header)
      raise @raise_on_verify if @raise_on_verify

      @verified_header = header
      Open.new(100_000)
    end

    def settle_actual(_open, actual)
      @settled_with << actual
      raise @raise_on_settle if @raise_on_settle

      {"success" => true, "transaction" => "SiG#{actual}", "network" => "n", "amount" => actual.to_s}
    end

    def payment_required(resource:)
      "CHALLENGE:#{resource}"
    end
  end

  # A Rack body that records whether the server (or middleware) closed it.
  class CloseTrackingBody
    attr_reader :closed

    def initialize(chunks)
      @chunks = chunks
      @closed = false
    end

    def each(&block)
      @chunks.each(&block)
    end

    def close
      @closed = true
    end
  end

  def setup
    @engine = FakeEngine.new
    @app = ->(env) {
      env[::PayKit::Usage::CHARGE_ENV_KEY]&.charge(env.fetch("test.meter", 0))
      [200, {"content-type" => "application/json"}, [JSON.generate({ok: true})]]
    }
    @mw = ::PayKit::Usage::Middleware.new(@app, engine: @engine, resource_path: "/usage",
      settlement_header: "x-payment-settlement-signature")
  end

  def test_no_payment_returns_402_challenge
    status, headers, = @mw.call(env_for("/usage"))
    assert_equal 402, status
    assert_equal "CHALLENGE:/usage", headers[Constants::PAYMENT_REQUIRED_HEADER]
  end

  def test_paid_nonzero_settles_and_delivers
    status, headers, body = @mw.call(env_for("/usage", header: "HDR", meter: 50_000))

    assert_equal 200, status
    assert_equal [50_000], @engine.settled_with
    assert headers.key?(Constants::PAYMENT_RESPONSE_HEADER)
    assert_equal "SiG50000", headers["x-payment-settlement-signature"]
    settlement = JSON.parse(Base64.strict_decode64(headers[Constants::PAYMENT_RESPONSE_HEADER]))
    assert_equal "50000", settlement["amount"]
    assert_equal JSON.generate({ok: true}), body.join
  end

  def test_zero_charge_fails_closed_but_still_settles
    status, headers, = @mw.call(env_for("/usage", header: "HDR", meter: 0))

    assert_equal 402, status
    assert_equal [0], @engine.settled_with, "engine still settles 0 on-chain to close the channel"
    assert_equal "CHALLENGE:/usage", headers[Constants::PAYMENT_REQUIRED_HEADER]
  end

  def test_meter_above_ceiling_settles_at_ceiling
    @mw.call(env_for("/usage", header: "HDR", meter: 10_000_000))
    assert_equal [100_000], @engine.settled_with
  end

  def test_passes_through_other_paths
    status, _, body = @mw.call(env_for("/other"))
    assert_equal 200, status
    assert_equal JSON.generate({ok: true}), body.join
  end

  def test_detects_legacy_x_payment_header
    status, = @mw.call(env_for("/usage", legacy_header: "HDR", meter: 1))
    assert_equal 200, status
  end

  def test_verify_failure_returns_402
    @engine.raise_on_verify = ::PayKit::Protocols::X402::Error::PaymentInvalid.new("bad open")
    status, headers, body = @mw.call(env_for("/usage", header: "HDR"))

    assert_equal 402, status
    assert_equal "bad open", JSON.parse(body.join)["invalidReason"]
    assert headers.key?(Constants::PAYMENT_REQUIRED_HEADER)
  end

  def test_settlement_failure_is_a_server_error_not_a_challenge
    @engine.raise_on_settle = RuntimeError.new("rpc timeout")
    status, headers, body = @mw.call(env_for("/usage", header: "HDR", meter: 50_000))

    assert_equal 502, status
    refute headers.key?(Constants::PAYMENT_REQUIRED_HEADER), "must not tell the client to pay again"
    assert_equal "settlement_failed", JSON.parse(body.join)["error"]
  end

  def test_closes_dropped_body_on_zero_charge
    body = CloseTrackingBody.new([JSON.generate({ok: true})])
    app = ->(env) {
      env[::PayKit::Usage::CHARGE_ENV_KEY]&.charge(0)
      [200, {}, body]
    }
    mw = ::PayKit::Usage::Middleware.new(app, engine: @engine, resource_path: "/usage")

    status, = mw.call(env_for("/usage", header: "HDR"))
    assert_equal 402, status
    assert body.closed, "fail-closed path must close the dropped body"
  end

  def test_closes_dropped_body_on_settlement_failure
    @engine.raise_on_settle = RuntimeError.new("rpc timeout")
    body = CloseTrackingBody.new([JSON.generate({ok: true})])
    app = ->(env) {
      env[::PayKit::Usage::CHARGE_ENV_KEY]&.charge(50_000)
      [200, {}, body]
    }
    mw = ::PayKit::Usage::Middleware.new(app, engine: @engine, resource_path: "/usage")

    status, = mw.call(env_for("/usage", header: "HDR"))
    assert_equal 502, status
    assert body.closed
  end

  private

  def env_for(path, header: nil, legacy_header: nil, meter: 0)
    env = {
      "REQUEST_METHOD" => "GET", "PATH_INFO" => path, "QUERY_STRING" => "",
      "rack.input" => StringIO.new(""), "test.meter" => meter
    }
    env["HTTP_PAYMENT_SIGNATURE"] = header if header
    env["HTTP_X_PAYMENT"] = legacy_header if legacy_header
    env
  end
end
