# frozen_string_literal: true

require "rack"
require "json"

require_relative "../errors"
require_relative "../challenge"
require_relative "../pricing"
require_relative "../protocols"

module PayKit
  module Rack
    # Rack middleware that brackets the app's request cycle. It is
    # deliberately small: gate selection and payment verification
    # happen inside the helper (`require_payment!`), not here. The
    # middleware's only jobs are:
    #
    # 1. Install a `Dispatcher` on the env so helpers can reach the
    #    protocol adapters without re-resolving config.
    # 2. Rescue `PayKit::PaymentRequired` and serialize the 402.
    # 3. Rescue `PayKit::InvalidProof` and serialize the 402 with
    #    detail.
    # 4. Merge `settlement_headers` from the verified `Payment`
    #    into the success response.
    #
    # The helper layer (`PayKit::Sinatra`, `PayKit::Controller`)
    # owns "did the client send a proof, is it valid, what gate
    # are we checking against."
    class PaymentRequired
      ENV_PAYMENT_KEY = "pay_kit.payment"
      ENV_DISPATCHER_KEY = "pay_kit.dispatcher"
      ENV_EXPECTED_GATE_KEY = "pay_kit.expected_gate"

      def initialize(app, config: nil, pricing: nil)
        @app = app
        @config = config || PayKit.config
        @pricing = pricing
      end

      def call(env)
        env[ENV_DISPATCHER_KEY] = Dispatcher.new(config: @config, pricing: @pricing)

        status, headers, body = @app.call(env)

        if (settled = env[ENV_PAYMENT_KEY])
          settled.settlement_headers.each { |name, value| headers[name] ||= value }
        end

        [status, headers, body]
      rescue ::PayKit::PaymentRequired => e
        render_402(e.challenge)
      rescue ::PayKit::InvalidProof => e
        render_invalid(e)
      end

      private

      def render_402(challenge)
        body = JSON.generate(challenge.to_h)
        headers = {"content-type" => "application/json"}.merge(challenge.headers)
        [402, headers, [body]]
      end

      def render_invalid(error)
        body = JSON.generate(error: error.code.to_s, message: error.detail)
        [402, {"content-type" => "application/json"}, [body]]
      end
    end

    # Per-request dispatcher. Holds the resolved adapters so the
    # helper can build challenges and verify proofs without touching
    # the underlying server constructors.
    class Dispatcher
      def initialize(config:, pricing:)
        @config = config
        @pricing_override = pricing
      end

      def pricing(env)
        env["pay_kit.pricing"] || @pricing_override || PayKit.pricing
      end

      def resolve(arg, request:, inline_defaults: {})
        registry = pricing(request.env)
        ::PayKit::Pricing.coerce(arg, registry: registry, request: request, inline_defaults: inline_defaults)
      end

      def materialize(gate, request)
        return gate.resolve(request) if gate.is_a?(::PayKit::DynamicGate)

        gate
      end

      # Build a `Challenge` for `gate` against `request`. Combines
      # `accepts[]` entries from each accepted scheme and merges
      # protocol-specific headers.
      def challenge_for(gate, request)
        accepts = []
        headers = {}

        if gate.x402_accepted?
          accepts << x402_adapter.accepts_entry(gate, request)
          headers.merge!(x402_adapter.challenge_headers(gate, request))
        end

        if gate.mpp_accepted?
          accepts << mpp_adapter.accepts_entry(gate, request)
          headers.merge!(mpp_adapter.challenge_headers(gate, request))
        end

        Challenge.new(resource: request.path, accepts: accepts, headers: headers)
      end

      # Verify whichever scheme this request carries. Returns a
      # `Payment` on success; raises `InvalidProof` on bad proof.
      # Returns nil when the request has no payment header at all
      # (caller should respond with a challenge).
      def verify(gate, request)
        if gate.x402_accepted? && x402_adapter.detect?(request)
          return x402_adapter.verify_and_settle(gate, request)
        end

        if gate.mpp_accepted? && mpp_adapter.detect?(request)
          return mpp_adapter.verify_and_settle(gate, request)
        end

        nil
      end

      def x402_adapter
        @x402_adapter ||= ::PayKit::Protocols::X402.new(
          config: @config,
          exact_config_for: ->(gate, request) { build_x402_config(gate, request) }
        )
      end

      def mpp_adapter
        @mpp_adapter ||= ::PayKit::Protocols::MPP.new(server: build_mpp_server)
      end

      private

      def build_x402_config(gate, request)
        ::X402::Server::Exact::Config.new(
          rpc_url: @config.x402.facilitator || raise(::PayKit::ConfigurationError, "PayKit.config.x402.facilitator not set"),
          pay_to: gate.pay_to,
          facilitator_secret_key: @config.x402.facilitator_secret_key,
          amount: gate.total.amount,
          network: caip2_for(@config.network),
          mint: mint_for(gate.amount.primary_coin, @config.network),
          resource_path: request.path
        )
      end

      def build_mpp_server
        secret = @config.mpp.secret || raise(::PayKit::ConfigurationError, "PayKit.config.mpp.secret not set")
        method = ::Mpp::Protocol::Solana.charge(
          recipient: @config.pay_to || raise(::PayKit::ConfigurationError, "PayKit.config.pay_to not set"),
          currency: mint_for(@config.stablecoins.first, @config.network),
          network: mpp_network_label_for(@config.network),
          rpc: @config.x402.facilitator || ""
        )
        ::Mpp.create(
          method: method,
          secret_key: secret,
          realm: @config.mpp.realm
        )
      end

      # CAIP-2 IDs go on the x402 wire. Localnet has no CAIP-2 entry
      # in the Solana registry, so the harness convention is to send
      # devnet's CAIP-2 (Surfpool clones devnet) when the client says
      # "localnet".
      def caip2_for(network)
        case network
        when :solana_mainnet then ::PayCore::Solana::Caip2::MAINNET
        when :solana_devnet, :solana_localnet then ::PayCore::Solana::Caip2::DEVNET
        else
          raise ::PayKit::ConfigurationError, "no CAIP-2 mapping for network #{network.inspect}"
        end
      end

      # Plain network label for the MPP server (`mainnet`/`devnet`/
      # `localnet`). MPP does not require CAIP-2 on the wire; the
      # `Mpp::Protocol::Solana.charge` factory takes the plain name.
      def mpp_network_label_for(network)
        case network
        when :solana_mainnet then "mainnet"
        when :solana_devnet then "devnet"
        when :solana_localnet then "localnet"
        else
          raise ::PayKit::ConfigurationError, "no MPP network label for #{network.inspect}"
        end
      end

      def mint_for(coin, network)
        net_key = case network
        when :solana_mainnet then "mainnet"
        when :solana_devnet then "devnet"
        when :solana_localnet then "localnet"
        else
          raise ::PayKit::ConfigurationError, "no mint table for network #{network.inspect}"
        end
        # Unknown symbol passes through as a literal mint pubkey. This
        # lets the interop harness and other call sites supply mint
        # addresses directly (`usd("1.00", "4zMMC9srt5...".to_sym)`)
        # without forcing them through the symbol table.
        coin_str = coin.to_s
        table = ::PayCore::Solana::Mints::MINTS[coin_str]
        return coin_str if table.nil?

        table.fetch(net_key) do
          raise ::PayKit::ConfigurationError, "stablecoin #{coin.inspect} not configured for network #{network.inspect}"
        end
      end
    end
  end

  # Hoist Config attribute so the dispatcher can read facilitator
  # secret without a separate accessor.
  class Config
    class X402Config
      attr_accessor :facilitator_secret_key
    end
  end
end
