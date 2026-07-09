# frozen_string_literal: true

require_relative "test_helper"

class PayKitDispatcherTest < Minitest::Test
  def teardown
    PayKit.reset!
  end

  def with_dispatcher
    middleware = ::PayKit::Rack::PaymentRequired.new(->(_env) { [200, {}, [""]] }, config: PayKit.config)
    env = {}
    middleware.call(env.merge!("PATH_INFO" => "/", "REQUEST_METHOD" => "GET", "rack.input" => StringIO.new))
    yield middleware, env[::PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY]
  end

  def make_gate(name:, pay_to:)
    amount = ::PayKit::Helpers::Pricing.build_price(:USD, "0.10", [:USDC])
    ::PayKit::Gate.new(
      name: name,
      pay_to: pay_to,
      amount: amount,
      fees: [],
      accept: %i[x402 mpp]
    )
  end

  def test_delegated_x402_mode_raises_not_implemented_error
    PayKitTestHelpers.with_config(x402_facilitator_url: "https://facilitator.example.com") do
      with_dispatcher do |_middleware, dispatcher|
        err = assert_raises(::PayKit::NotImplementedError) { dispatcher.send(:x402_adapter) }
        assert_includes err.message, "delegated x402 mode"
        assert_includes err.message, "facilitator_url"
      end
    end
  end

  def test_self_hosted_x402_mode_does_not_raise
    PayKitTestHelpers.with_config do
      with_dispatcher do |_middleware, dispatcher|
        refute_nil dispatcher.send(:x402_adapter)
      end
    end
  end

  def test_x402_settlement_cache_is_shared_across_requests
    PayKitTestHelpers.with_config do
      with_dispatcher do |middleware, _dispatcher|
        cache = middleware.instance_variable_get(:@x402_settlement_cache)
        refute_nil cache
        assert_kind_of ::PayKit::Protocols::X402::Server::Exact::SettlementCache, cache

        assert cache.put_if_absent("sig:abc")
        refute cache.put_if_absent("sig:abc"), "second put should observe the first"
      end
    end
  end

  def test_mpp_method_cache_returns_same_server_for_identical_gates
    PayKitTestHelpers.with_config do
      with_dispatcher do |_middleware, dispatcher|
        gate_a = make_gate(name: :report_a, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
        gate_b = make_gate(name: :report_b, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")

        first = dispatcher.send(:mpp_server_for, gate_a)
        second = dispatcher.send(:mpp_server_for, gate_b)

        assert_same first, second, "gates with the same recipient/currency/network/rpc must share an MPP server"
      end
    end
  end

  def test_mpp_method_cache_separates_servers_for_distinct_recipients
    PayKitTestHelpers.with_config do
      with_dispatcher do |_middleware, dispatcher|
        gate_a = make_gate(name: :a, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
        gate_b = make_gate(name: :b, pay_to: "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP")

        first = dispatcher.send(:mpp_server_for, gate_a)
        second = dispatcher.send(:mpp_server_for, gate_b)

        refute_same first, second
        refute_equal first.method.recipient, second.method.recipient
      end
    end
  end

  def test_operator_fee_payer_true_wires_signer_account_into_mpp_method
    PayKitTestHelpers.with_config do
      with_dispatcher do |_middleware, dispatcher|
        gate = make_gate(name: :report, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
        server = dispatcher.send(:mpp_server_for, gate)
        # The Solana method stores the PayCore::Solana::Account so its
        # public key surfaces as feePayerKey when method_details is
        # serialised at request time (the blockhash call is what we
        # avoid here; the pubkey is computed locally).
        assert_equal PayKit.config.operator.signer.pubkey, server.method.fee_payer_pubkey
      end
    end
  end

  def test_operator_fee_payer_false_leaves_mpp_method_fee_payer_nil
    PayKitTestHelpers.with_config(fee_payer: false) do
      with_dispatcher do |_middleware, dispatcher|
        gate = make_gate(name: :report, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
        server = dispatcher.send(:mpp_server_for, gate)
        assert_nil server.method.fee_payer, "fee_payer Account must be nil when operator.fee_payer? is false"
        assert_nil server.method.fee_payer_pubkey
      end
    end
  end

  def test_mpp_method_cache_threads_expires_in_into_challenge_store
    PayKitTestHelpers.with_config(mpp_expires_in: 42) do
      with_dispatcher do |_middleware, dispatcher|
        gate = make_gate(name: :report, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
        server = dispatcher.send(:mpp_server_for, gate)
        store = server.instance_variable_get(:@challenge_store)
        assert_equal 42, store.default_expires_seconds
      end
    end
  end

  def test_mpp_method_cache_survives_across_dispatchers_on_the_same_middleware
    PayKitTestHelpers.with_config do
      middleware = ::PayKit::Rack::PaymentRequired.new(->(_env) { [200, {}, [""]] }, config: PayKit.config)
      env1 = {"PATH_INFO" => "/", "REQUEST_METHOD" => "GET", "rack.input" => StringIO.new}
      env2 = {"PATH_INFO" => "/", "REQUEST_METHOD" => "GET", "rack.input" => StringIO.new}
      middleware.call(env1)
      middleware.call(env2)

      dispatcher1 = env1[::PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY]
      dispatcher2 = env2[::PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY]
      refute_same dispatcher1, dispatcher2

      gate = make_gate(name: :report, pay_to: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
      s1 = dispatcher1.send(:mpp_server_for, gate)
      s2 = dispatcher2.send(:mpp_server_for, gate)
      assert_same s1, s2, "method cache is per-middleware, so two dispatchers must hit the same cached server"
    end
  end
end
