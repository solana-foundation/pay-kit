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
        # Long-lived caches shared across every request this middleware
        # instance handles. x402's SettlementCache prevents the same
        # signature from being broadcast twice; the MPP method cache
        # avoids rebuilding `PayKit::Protocols::Mpp.create(...)` for every gate hit (the
        # underlying ChallengeStore allocates buffers on construction).
        @x402_settlement_cache = ::PayKit::Protocols::X402::Server::Exact::SettlementCache.new
        @mpp_method_cache = MppMethodCache.new
      end

      def call(env)
        env[ENV_DISPATCHER_KEY] = Dispatcher.new(
          config: @config,
          pricing: @pricing,
          x402_settlement_cache: @x402_settlement_cache,
          mpp_method_cache: @mpp_method_cache
        )

        status, headers, body = @app.call(env)

        if (settled = env[ENV_PAYMENT_KEY])
          settled.settlement_headers.each { |name, value| headers[name.to_s.downcase] ||= value }
        end

        [status, headers, body]
      rescue ::PayKit::PaymentRequired => e
        self.class.render_402(e.challenge)
      rescue ::PayKit::InvalidProof => e
        self.class.render_invalid(e)
      end

      # Build a Rack 402 tuple from a `PayKit::Challenge`. Class methods
      # so the Sinatra helper path (`require_payment!` → `halt`) and
      # the middleware-rescue path can share the exact same rendering
      # logic — no drift between the two.
      class << self
        def render_402(challenge)
          body = JSON.generate(challenge.to_h)
          headers = {
            "content-type" => "application/json",
            "cache-control" => "no-store"
          }.merge(normalize_headers(challenge.headers))
          [402, headers, [body]]
        end

        def render_invalid(error)
          payload = {error: error.code.to_s, message: error.detail}
          payload[:spec_code] = error.spec_code if error.spec_code
          [402, {"content-type" => "application/json", "cache-control" => "no-store"}, [JSON.generate(payload)]]
        end

        # Rack 3 requires response header names to be lowercase. The
        # x402/MPP wire constants are upper/mixed case to match the spec
        # and the Rust spine — downcase only at this boundary so the
        # wire constants stay canonical.
        def normalize_headers(headers)
          headers.each_with_object({}) { |(k, v), h| h[k.to_s.downcase] = v }
        end
      end
    end

    # Long-lived, thread-safe cache of `PayKit::Protocols::Mpp::Server::Charge` instances
    # keyed by the tuple that defines a charge method: recipient +
    # currency + network + rpc URL + secret + realm + expires_in. Two
    # gates with the same tuple share a server (and its underlying
    # ChallengeStore allocations); gates that differ on any field get
    # their own. Lives on the Rack middleware so it survives across
    # requests.
    class MppMethodCache
      def initialize
        @entries = {}
        @mutex = Mutex.new
      end

      def fetch(key)
        @mutex.synchronize do
          @entries[key] ||= yield
        end
      end

      def size
        @mutex.synchronize { @entries.size }
      end
    end

    # Per-request dispatcher. Holds the resolved adapters so the
    # helper can build challenges and verify proofs without touching
    # the underlying server constructors. The shared caches
    # (`x402_settlement_cache`, `mpp_method_cache`) are owned by the
    # Rack middleware and threaded in here.
    class Dispatcher
      def initialize(config:, pricing:, x402_settlement_cache: nil, mpp_method_cache: nil)
        @config = config
        @pricing_override = pricing
        @x402_settlement_cache = x402_settlement_cache || ::PayKit::Protocols::X402::Server::Exact::SettlementCache.new
        @mpp_method_cache = mpp_method_cache || MppMethodCache.new
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
        @x402_adapter ||= begin
          if @config.x402.delegated?
            raise ::PayKit::NotImplementedError,
              "PayKit.config.x402.facilitator_url is set, which enables delegated x402 mode " \
              "(POST /verify + /settle to the facilitator). The delegated HTTP client is not " \
              "wired in this release; unset c.x402.facilitator_url to run x402 self-hosted, or " \
              "drop :x402 from c.accept to use MPP only."
          end

          ::PayKit::Protocols::X402Adapter.new(
            config: @config,
            exact_config_for: ->(gate, request) { build_x402_config(gate, request) }
          )
        end
      end

      def mpp_adapter
        @mpp_adapter ||= ::PayKit::Protocols::MppAdapter.new(
          server_for: ->(gate) { mpp_server_for(gate) }
        )
      end

      private

      def build_x402_config(gate, request)
        signer = @config.x402.effective_signer ||
          raise(::PayKit::ConfigurationError, "PayKit.config.operator.signer not set")
        ::PayKit::Protocols::X402::Server::Exact::Config.new(
          rpc_url: @config.effective_rpc_url,
          pay_to: gate.pay_to,
          facilitator_secret_key: signer.to_json_array,
          # x402 v2 wire format expects amount in smallest-units integer
          # string (the Rust spine parses requirement.amount as u64;
          # decimal forms like "0.001" trip "Invalid amount" on the
          # client). PayKit's Gate carries the human-readable decimal,
          # so convert here using the gate's currency decimals.
          amount: to_smallest_units_string(gate.total),
          network: caip2_for(@config.network),
          mint: mint_for(gate.amount.primary_coin, @config.network),
          resource_path: request.path,
          settlement_cache: @x402_settlement_cache
        )
      end

      # Convert a Price (decimal "0.001") into the SPL smallest-units
      # integer string ("1000"). 6 decimals is the canonical default for
      # USDC/USDT/EURC; if a future gate carries a non-6-decimal coin
      # this needs to look up decimals_for(coin, network) instead.
      def to_smallest_units_string(price)
        whole, _, fraction = price.amount.partition(".")
        fraction = fraction.ljust(6, "0")[0, 6]
        units = (Integer(whole, 10) * 1_000_000) + Integer(fraction.empty? ? "0" : fraction, 10)
        units.to_s
      end

      # Per-gate MPP server built once, cached on the middleware. The
      # cache key is the full tuple that defines the on-chain charge
      # intent — two gates with the same recipient/currency/network/rpc
      # share a server; gates that differ on any field (e.g. a
      # different `gate.pay_to`) get their own server with its own
      # ChallengeStore. `PayKit::Protocols::Mpp.create(...)` allocates per-instance HMAC
      # state, so this is meaningful work to avoid per request.
      def mpp_server_for(gate)
        secret = @config.mpp.challenge_binding_secret ||
          raise(::PayKit::ConfigurationError, "PayKit.config.mpp.challenge_binding_secret not set")
        recipient = gate.pay_to || @config.operator.effective_recipient
        currency = mint_for(gate.amount.primary_coin, @config.network)
        network = mpp_network_label_for(@config.network)
        rpc = @config.effective_rpc_url
        realm = @config.mpp.realm
        expires_in = @config.mpp.expires_in
        fee_payer_account = if @config.operator.fee_payer? && @config.operator.signer.respond_to?(:to_pay_core_account)
          @config.operator.signer.to_pay_core_account
        end
        fee_payer_pubkey = fee_payer_account&.public_key&.to_s

        key = [recipient, currency, network, rpc, secret, realm, expires_in, fee_payer_pubkey].freeze

        @mpp_method_cache.fetch(key) do
          method = ::PayKit::Protocols::Mpp::Protocol::Solana.charge(
            recipient: recipient,
            currency: currency,
            network: network,
            rpc: rpc,
            fee_payer: fee_payer_account
          )
          ::PayKit::Protocols::Mpp.create(
            method: method,
            secret_key: secret,
            realm: realm,
            expires_in: expires_in
          )
        end
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
      # `PayKit::Protocols::Mpp::Protocol::Solana.charge` factory takes the plain name.
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
        # lets the harness and other call sites supply mint
        # addresses directly (`usd("1.00", "4zMMC9srt5...".to_sym)`)
        # without forcing them through the symbol table.
        coin_str = coin.to_s
        table = ::PayCore::Solana::Mints::MINTS[coin_str]
        return coin_str if table.nil?

        # MINTS has no `localnet` row — local validators (Surfpool) clone
        # mainnet, so fall back to the mainnet mint. Matches
        # `PayCore::Solana::Mints.resolve` and the Rust spine.
        table[net_key] || table.fetch("mainnet") do
          raise ::PayKit::ConfigurationError, "stablecoin #{coin.inspect} not configured for network #{network.inspect}"
        end
      end
    end
  end
end
