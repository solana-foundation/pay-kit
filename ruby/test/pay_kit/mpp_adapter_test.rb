# frozen_string_literal: true

require_relative "test_helper"

class PayKitMppAdapterTest < Minitest::Test
  RECIPIENT = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
  FEE_RECIPIENT_A = "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP"
  FEE_RECIPIENT_B = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"

  def teardown
    PayKit.reset!
  end

  def amount_usd_010
    ::PayKit::Helpers::Pricing.build_price(:USD, "0.10", [:USDC])
  end

  def fee(recipient:, amount:, kind: :within)
    ::PayKit::Fee.new(
      recipient: recipient,
      price: ::PayKit::Helpers::Pricing.build_price(:USD, amount, [:USDC]),
      kind: kind
    )
  end

  def adapter
    fake_server = Object.new
    def fake_server.charge(*)
    end
    ::PayKit::Protocols::MppAdapter.new(server: fake_server)
  end

  def test_splits_is_nil_when_gate_has_no_fees
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [],
        accept: %i[mpp]
      )
      assert_nil adapter.send(:splits_for, gate, 100_000)
    end
  end

  def test_splits_excludes_primary_recipient
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [fee(recipient: FEE_RECIPIENT_A, amount: "0.01", kind: :within)],
        accept: %i[mpp]
      )

      result = adapter.send(:splits_for, gate, 100_000)
      assert_equal 1, result.length
      assert_equal FEE_RECIPIENT_A, result.first["recipient"]
      refute(result.any? { |s| s["recipient"] == RECIPIENT },
        "primary recipient must NOT appear in splits[] (verifier computes primary = total - sum(splits))")
    end
  end

  def test_splits_carries_only_fees_in_order
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [
          fee(recipient: FEE_RECIPIENT_A, amount: "0.01", kind: :within),
          fee(recipient: FEE_RECIPIENT_B, amount: "0.005", kind: :on_top)
        ],
        accept: %i[mpp]
      )

      result = adapter.send(:splits_for, gate, 100_000)
      assert_equal 2, result.length
      assert_equal FEE_RECIPIENT_A, result[0]["recipient"]
      assert_equal "10000", result[0]["amount"]
      assert_equal FEE_RECIPIENT_B, result[1]["recipient"]
      assert_equal "5000", result[1]["amount"]
    end
  end

  def test_invalid_proof_carries_spec_code_from_mpp_challenge_body
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [],
        accept: %i[mpp]
      )

      challenge_with_code = ::PayKit::Protocols::Mpp::Challenge.new(
        www_authenticate: "Payment realm=\"X\"",
        body: {"code" => "challenge_expired", "error" => "challenge_expired", "message" => "challenge expired"},
        reason: "challenge expired"
      )

      fake_server = Object.new
      fake_server.define_singleton_method(:charge) { |_authorization, **_kwargs| challenge_with_code }

      adapter = ::PayKit::Protocols::MppAdapter.new(server: fake_server)

      env = ::Rack::MockRequest.env_for("/", "HTTP_AUTHORIZATION" => "Payment fake")
      request = ::Rack::Request.new(env)
      err = assert_raises(::PayKit::InvalidProof) { adapter.verify_and_settle(gate, request) }
      assert_equal :payment_required, err.code
      assert_equal "challenge_expired", err.spec_code
    end
  end

  def test_perform_forwards_external_id_to_mpp_server
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :order_42,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [],
        accept: %i[mpp],
        external_id: "order:42"
      )

      captured = {}
      fake_server = Object.new
      fake_server.define_singleton_method(:charge) do |authorization, **kwargs|
        captured[:authorization] = authorization
        captured[:kwargs] = kwargs
        nil
      end

      adapter = ::PayKit::Protocols::MppAdapter.new(server: fake_server)
      adapter.send(:perform, gate, nil, authorization: "Payment fake")

      assert_equal "order:42", captured[:kwargs][:external_id]
      assert_equal 100_000, captured[:kwargs][:amount]
    end
  end

  def test_gate_external_id_defaults_to_nil
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [],
        accept: %i[mpp]
      )
      assert_nil gate.external_id
    end
  end

  def test_dynamic_gate_resolves_external_id_from_block
    klass = Class.new(::PayKit::Pricing) do
      define_method(:build_gates) do
        gate :order do |req|
          amount usd("0.10")
          external_id req.params["order_id"]
        end
      end
    end

    PayKitTestHelpers.with_config do
      pricing = klass.new
      dyn = pricing[:order]
      mock = Struct.new(:params).new({"order_id" => "abc-123"})
      resolved = dyn.resolve(mock)
      assert_equal "abc-123", resolved.external_id
    end
  end

  def test_accepts_entry_exposes_primary_via_pay_to_not_splits
    PayKitTestHelpers.with_config do
      gate = ::PayKit::Gate.new(
        name: :report,
        pay_to: RECIPIENT,
        amount: amount_usd_010,
        fees: [fee(recipient: FEE_RECIPIENT_A, amount: "0.01", kind: :within)],
        accept: %i[mpp]
      )

      env = ::Rack::MockRequest.env_for("/report")
      request = ::Rack::Request.new(env)
      entry = adapter.accepts_entry(gate, request)
      assert_equal RECIPIENT, entry[:payTo]
      assert_equal 1, entry[:splits].length
      assert_equal FEE_RECIPIENT_A, entry[:splits].first["recipient"]
    end
  end
end
