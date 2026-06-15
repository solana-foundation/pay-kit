# frozen_string_literal: true

require "logger"

require_relative "errors"
require_relative "operator"
require_relative "signer"

module PayKit
  # Boot-time configuration. Mutable inside the `PayKit.configure`
  # block; frozen when the block returns. The surface centres
  # everything on the single `c.operator` value (recipient + signer +
  # fee-payer role), with `c.rpc_url` for the Solana endpoint and
  # `c.mpp.challenge_binding_secret` for the stateless challenge HMAC.
  class Config
    VALID_NETWORKS = %i[solana_mainnet solana_devnet solana_localnet].freeze
    VALID_PROTOCOLS = %i[x402 mpp].freeze
    DEFAULT_NETWORK = :solana_localnet

    PUBLIC_RPC_URLS = {
      solana_mainnet: "https://api.mainnet-beta.solana.com",
      solana_devnet: "https://api.devnet.solana.com",
      solana_localnet: "https://402.surfnet.dev:8899"
    }.freeze

    attr_reader :network, :accept, :stablecoins, :x402, :mpp

    def initialize
      @network = DEFAULT_NETWORK
      @accept = %i[x402 mpp].freeze
      @stablecoins = %i[USDC].freeze
      @rpc_url = nil
      @operator = ::PayKit::Operator.new
      @x402 = X402Config.new(self)
      @mpp = MppConfig.new
      @preflight = true
    end

    # Boot-time soundness check. When `true` (default), `freeze!` runs
    # `PayKit::Preflight.run(self)` to confirm the fee payer has SOL
    # and every `c.stablecoins` mint has an ATA at the operator's
    # recipient. On `:solana_localnet` with the demo signer, missing
    # accounts are auto-created via Surfnet cheatcodes instead of
    # raising. RPC failures are logged, not raised, so an unreachable
    # endpoint never blocks boot. Set `c.preflight = false` (or export
    # `PAY_KIT_DISABLE_PREFLIGHT=1`) to skip — typically used in test
    # suites that do not have a live validator at hand.
    attr_accessor :preflight

    # --- new surface ---------------------------------------------------

    # The `c.operator` accessor doubles as a builder. With a block, it
    # yields the current operator for in-place mutation (matches the
    # `c.x402 do |x| ... end` / `c.mpp do |m| ... end` shape). Without
    # a block, it returns the current operator object so callers can
    # read fields.
    def operator(&block)
      return @operator unless block_given?

      block.call(@operator)
      @operator
    end

    # Replace the operator wholesale with a pre-built `PayKit::Operator`.
    def operator=(value)
      unless value.is_a?(::PayKit::Operator)
        raise ::PayKit::ConfigurationError,
          "c.operator must be assigned a PayKit::Operator instance, got #{value.class.name}"
      end

      @operator = value
    end

    # Solana RPC endpoint. `nil` resolves to the public RPC for the
    # active network at `effective_rpc_url` read time. The public
    # mainnet RPC is rate-limited and unsuitable for production
    # traffic; a warning fires at `freeze!` when network=mainnet and no
    # explicit override is set.
    attr_accessor :rpc_url

    def effective_rpc_url
      @rpc_url || PUBLIC_RPC_URLS.fetch(@network)
    end

    def using_public_rpc_default?
      @rpc_url.nil?
    end

    # --- core knobs (unchanged) ---------------------------------------

    def accept=(protocols)
      list = Array(protocols).map(&:to_sym)
      unknown = list - VALID_PROTOCOLS
      raise ConfigurationError, "unknown protocol(s) in accept: #{unknown.inspect}" unless unknown.empty?
      raise ConfigurationError, "accept must not be empty" if list.empty?

      @accept = list.uniq.freeze
    end

    def stablecoins=(coins)
      list = Array(coins).map(&:to_sym)
      raise ConfigurationError, "stablecoins must not be empty" if list.empty?

      @stablecoins = list.uniq.freeze
    end

    def network=(value)
      sym = value.to_sym
      unless VALID_NETWORKS.include?(sym)
        raise ConfigurationError, "unknown network #{sym.inspect}, expected one of #{VALID_NETWORKS.inspect}"
      end

      @network = sym
    end

    # --- freeze + safety checks ---------------------------------------

    # Called by `PayKit.configure` once the user block returns. Locks
    # the config and enforces boot-time safety rules (mainnet refusal
    # for the demo signer, warning when the mainnet public RPC default
    # is silently in use).
    def freeze!
      enforce_demo_signer_on_mainnet
      warn_about_public_mainnet_rpc
      run_preflight
      @x402.freeze!
      @mpp.freeze!
      freeze
    end

    # --- subconfigs ---------------------------------------------------

    class X402Config
      VALID_SCHEMES = %i[exact].freeze

      attr_reader :scheme, :facilitator_url, :signer

      def initialize(parent_config)
        @parent_config = parent_config
        @scheme = :exact
        @facilitator_url = nil
        @signer = nil
      end

      # x402 v2 facilitator URL. When `nil`, PayKit operates in
      # self-hosted mode (verify + settle on-chain locally with
      # `c.rpc_url` + `c.operator.signer`). When set, PayKit POSTs to
      # the facilitator's `/verify` and `/settle` endpoints and never
      # touches the chain itself. The delegated client is wired in a
      # follow-up; today `c.x402.delegated?` flags the mode and the
      # dispatcher raises `PayKit::NotImplementedError` on hit.
      attr_writer :facilitator_url

      # Convenience predicate: `true` when a facilitator URL is set.
      def delegated?
        !@facilitator_url.nil? && !@facilitator_url.empty?
      end

      # Advanced override: use a distinct signer for x402 without
      # disturbing the operator's MPP fee-payer key. Falls back to
      # `c.operator.signer` when nil (the common case).
      def signer=(value)
        return if value.nil?
        unless value.respond_to?(:pubkey) && value.respond_to?(:sign)
          raise ::PayKit::ConfigurationError,
            "c.x402.signer must satisfy the PayKit signer duck-type"
        end

        @signer = value
      end

      def effective_signer
        @signer || @parent_config.operator.signer
      end

      def scheme=(value)
        sym = value.to_sym
        unless VALID_SCHEMES.include?(sym)
          raise ::PayKit::ConfigurationError, "unknown x402 scheme #{sym.inspect} (only :exact is supported today)"
        end

        @scheme = sym
      end

      def freeze!
        freeze
      end
    end

    class MppConfig
      attr_accessor :realm, :expires_in
      attr_reader :challenge_binding_secret

      def initialize
        @realm = "App"
        @challenge_binding_secret = nil
        @expires_in = 300
      end

      # Server-side HMAC secret used for stateless challenge binding
      # (`draft-httpauth-payment-00` §"Challenge-Binding Secret"). The
      # spec calls this the "server secret" / "shared secret"; the
      # PayKit field name names the function instead of the storage to
      # disambiguate from `c.operator.signer`.
      attr_writer :challenge_binding_secret

      def freeze!
        freeze
      end
    end

    private

    def enforce_demo_signer_on_mainnet
      return unless @network == :solana_mainnet
      return unless @operator.signer.demo?

      raise ::PayKit::DemoSignerOnMainnetError, @operator.signer.pubkey
    end

    def run_preflight
      return unless @preflight
      return if ENV["PAY_KIT_DISABLE_PREFLIGHT"] == "1"

      require_relative "preflight"
      ::PayKit::Preflight.run(self)
    end

    def warn_about_public_mainnet_rpc
      return unless @network == :solana_mainnet
      return unless using_public_rpc_default?

      logger_warn(
        "PayKit.config.network = :solana_mainnet uses the public Solana RPC by default. " \
        "Public mainnet RPC is rate-limited and unsuitable for production traffic. " \
        "Set c.rpc_url to a dedicated endpoint (Helius, QuickNode, your own validator)."
      )
    end

    class << self
      # Fallback `$stderr` logger used for boot-time warnings (e.g. the
      # public-mainnet-RPC notice) when the host app has not set
      # `PayKit.logger`.
      def default_logger
        @default_logger ||= ::Logger.new($stderr).tap do |logger|
          logger.formatter = proc { |_severity, _datetime, _progname, msg| "[PayKit] WARN: #{msg}\n" }
        end
      end
    end

    def logger_warn(message)
      logger = ::PayKit.logger || self.class.default_logger
      logger.warn(message)
    end
  end

  # Module-level configure / config / pricing accessors. Mirrors
  # Clearance's `Clearance.configuration`.
  class << self
    def configure
      @config ||= Config.new
      yield @config
      @config.freeze!
      @config
    end

    def config
      @config ||= Config.new
    end

    attr_reader :pricing

    def pricing=(registry)
      registry.freeze unless registry.frozen?
      @pricing = registry
    end

    def reset!
      @config = nil
      @pricing = nil
    end
  end
end
