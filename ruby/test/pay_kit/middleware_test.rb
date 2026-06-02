# frozen_string_literal: true

require_relative "test_helper"

require "rack/test"
require "sinatra/base"
require "solana_pay_kit/sinatra"

class PayKitMiddlewareTest < Minitest::Test
  include Rack::Test::Methods

  class TestPricing < PayKit::Pricing
    def build_gates
      gate :report, amount: usd("0.10"), description: "Test report"
      gate :tiered do |req|
        amount usd((req.params["tier"] == "premium") ? "5.00" : "0.10")
      end
    end
  end

  # In-memory fake of both scheme adapters so we can drive the
  # middleware end-to-end without hitting Solana RPC or signing
  # transactions. The fake reads a synthetic X-Test-Payment header
  # to decide pay/no-pay.
  module FakeSchemes
    SENTINEL = "FAKE_OK"
    FAKE_SETTLEMENT_HEADER = "x-fake-settlement"

    def self.install_into(dispatcher)
      dispatcher.instance_variable_set(:@x402_adapter, FakeAdapter.new(protocol: :x402, scheme: :exact))
      dispatcher.instance_variable_set(:@mpp_adapter, FakeAdapter.new(protocol: :mpp, scheme: :charge))
    end

    class FakeAdapter
      def initialize(protocol:, scheme:)
        @protocol = protocol
        @scheme = scheme
      end

      def detect?(request)
        request.env["HTTP_X_TEST_PAYMENT"] == SENTINEL
      end

      def accepts_entry(gate, _request)
        {protocol: @protocol.to_s, scheme: @scheme.to_s, amount: gate.total.amount, payTo: gate.pay_to}
      end

      def challenge_headers(_gate, _request)
        {"x-fake-challenge-#{@protocol}" => "1"}
      end

      def verify_and_settle(_gate, _request)
        PayKit::Payment.new(
          protocol: @protocol,
          scheme: @scheme,
          transaction: "FAKE_TX_#{@protocol.upcase}",
          settlement_headers: {FAKE_SETTLEMENT_HEADER => "fake-#{@protocol}"},
          raw: "fake"
        )
      end
    end
  end

  def app
    @app ||= build_app
  end

  def setup
    PayKitTestHelpers.with_config { @pricing = TestPricing.new }
    # Carry the booted config out of the helper since the helper
    # restores it after the block. Rack::Test runs the app outside
    # the helper's scope.
    PayKit.reset!
    PayKit.configure do |c|
      c.operator { |op| op.recipient = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj" }
      c.network = :solana_devnet
      c.accept = %i[x402 mpp]
      c.stablecoins = %i[USDC]
      c.rpc_url = "https://example.test"
      c.mpp.realm = "Test"
      c.mpp.challenge_binding_secret = "test"
    end
    PayKit.pricing = TestPricing.new
  end

  def teardown
    PayKit.reset!
    @app = nil
  end

  def test_unpaid_request_returns_402
    get "/report"

    assert_equal 402, last_response.status
    assert_equal "application/json", last_response.headers["content-type"]
    assert_equal "1", last_response.headers["x-fake-challenge-x402"]
    assert_equal "1", last_response.headers["x-fake-challenge-mpp"]

    body = JSON.parse(last_response.body)
    assert_equal "payment_required", body["error"]
    assert_equal "/report", body["resource"]
    schemes = body["accepts"].map { |a| a["protocol"] }
    assert_equal %w[x402 mpp], schemes
  end

  def test_paid_request_passes_and_merges_settlement_headers
    header "X-Test-Payment", FakeSchemes::SENTINEL
    get "/report"

    assert_equal 200, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal true, body["ok"]
    assert_equal "x402", body["paid_by"]
    assert_equal "fake-x402", last_response.headers[FakeSchemes::FAKE_SETTLEMENT_HEADER]
  end

  def test_paid_predicate_does_not_halt_free_route
    get "/stats"
    assert_equal 200, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal false, body["premium"]
    assert_nil last_response.headers[FakeSchemes::FAKE_SETTLEMENT_HEADER]
  end

  def test_paid_predicate_returns_true_when_proof_present
    header "X-Test-Payment", FakeSchemes::SENTINEL
    get "/stats"
    assert_equal 200, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal true, body["premium"]
  end

  def test_dynamic_gate_resolves_through_sinatra_helper
    get "/tiered?tier=premium"
    assert_equal 402, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal "5.00", body["accepts"].first["amount"]
  end

  def test_inline_form_returns_402_with_inline_amount
    get "/oneoff"
    assert_equal 402, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal "0.25", body["accepts"].first["amount"]
  end

  # Regression: all PayKit 402 responses (payment_required challenge) must
  # include Cache-Control: no-store so that proxies and browsers do not
  # cache payment challenges or invalid-proof responses.
  def test_402_payment_required_includes_cache_control_no_store
    get "/report"

    assert_equal 402, last_response.status
    assert_equal "no-store", last_response.headers["cache-control"],
      "PayKit 402 challenge response must include Cache-Control: no-store"
  end

  def test_render_402_class_method_includes_cache_control_no_store
    challenge = PayKit::Challenge.new(
      resource: "/report",
      accepts: [],
      headers: {}
    )
    _status, headers, _body = PayKit::Rack::PaymentRequired.render_402(challenge)

    assert_equal "no-store", headers["cache-control"],
      "render_402 must include Cache-Control: no-store"
  end

  def test_render_invalid_class_method_includes_cache_control_no_store
    error = PayKit::InvalidProof.new(:bad_proof, "test error")
    _status, headers, _body = PayKit::Rack::PaymentRequired.render_invalid(error)

    assert_equal "no-store", headers["cache-control"],
      "render_invalid must include Cache-Control: no-store"
  end

  private

  def build_app
    Class.new(Sinatra::Base) do
      helpers PayKit::Sinatra
      use PayKit::Rack::PaymentRequired

      set :show_exceptions, false
      set :raise_errors, true
      # Sinatra 4.x ships host authorization; Rack::Test sends `example.org`
      # which isn't on the default allowlist. Permit any host in tests.
      set :host_authorization, permitted_hosts: []
      disable :protection

      before do
        dispatcher = request.env[PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY]
        FakeSchemes.install_into(dispatcher)
      end

      get "/report" do
        require_payment! :report
        content_type :json
        JSON.generate(ok: true, paid_by: payment.protocol.to_s)
      end

      get "/stats" do
        content_type :json
        JSON.generate(ok: true, premium: paid?(:report))
      end

      get "/oneoff" do
        require_payment! usd("0.25"), description: "One-off"
        content_type :json
        JSON.generate(ok: true)
      end

      get "/tiered" do
        require_payment! :tiered
        content_type :json
        JSON.generate(ok: true, tier: params["tier"])
      end
    end
  end
end
