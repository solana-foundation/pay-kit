# frozen_string_literal: true

require "logger"

require_relative "errors"
require_relative "operator"
require_relative "signer"

module PayKit
  # Boot-time configuration. Mutable inside the `PayKit.configure`
  # block; frozen when the block returns. The new surface centres
  # everything that used to be scattered ("`c.pay_to`",
  # "`c.x402.facilitator_secret_key`", "manual SOL fee management") on
  # the single `c.operator` value. The old knobs still work for one
  # release through deprecation shims that emit a `Logger.warn`.
  class Config
    VALID_NETWORKS = %i[solana_mainnet solana_devnet solana_localnet].freeze
    VALID_SCHEMES = %i[x402 mpp].freeze
    DEFAULT_NETWORK = :solana_localnet

    PUBLIC_RPC_URLS = {
      solana_mainnet: "https://api.mainnet-beta.solana.com",
      solana_devnet: "https://api.devnet.solana.com",
      solana_localnet: "http://localhost:8899"
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
    end

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

    def accept=(schemes)
      list = Array(schemes).map(&:to_sym)
      unknown = list - VALID_SCHEMES
      raise ConfigurationError, "unknown scheme(s) in accept: #{unknown.inspect}" unless unknown.empty?
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

    # --- deprecated shims (cascade to operator + rpc_url) -------------

    # Deprecated. Was the merchant recipient at the top of config.
    # New surface: `c.operator do |op| op.recipient = ... end`.
    def pay_to
      deprecation_warning(:pay_to, "use c.operator.recipient (or c.operator do |op| op.recipient = ... end)")
      @operator.effective_recipient
    end

    def pay_to=(value)
      deprecation_warning(:pay_to=, "use c.operator do |op| op.recipient = #{value.inspect} end")
      @operator.recipient = value
    end

    # --- freeze + safety checks ---------------------------------------

    # Called by `PayKit.configure` once the user block returns. Locks
    # the config and enforces boot-time safety rules (mainnet refusal
    # for the demo signer, warning when the mainnet public RPC default
    # is silently in use).
    def freeze!
      enforce_demo_signer_on_mainnet
      warn_about_public_mainnet_rpc
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

      # --- deprecated shims ------------------------------------------

      # The old `c.x402.facilitator` field was historically misused to
      # carry a Solana RPC URL (the demo even pointed at
      # `https://402.surfnet.dev:8899`, a validator). The semantically
      # correct routing is now `c.rpc_url`. The deprecation shim sends
      # the value there and emits a warning that explains the historical
      # mistake so the new `c.x402.facilitator_url` (delegation only)
      # never gets confused with the old field.
      def facilitator=(value)
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"x402.facilitator=",
          "this field historically held the Solana RPC URL; use c.rpc_url instead. " \
          "The new c.x402.facilitator_url is for delegated facilitator delegation only."
        )
        @parent_config.rpc_url = value
      end

      def facilitator
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"x402.facilitator",
          "use c.rpc_url (this field is the Solana RPC URL, not an x402 facilitator)"
        )
        @parent_config.effective_rpc_url
      end

      # The old explicit secret-key field is replaced by
      # `c.operator.signer`. The shim converts the JSON-array literal
      # to a `PayKit::Signer::Local` and slots it onto the operator,
      # emitting a deprecation warning.
      def facilitator_secret_key=(value)
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"x402.facilitator_secret_key=",
          "use c.operator do |op| op.signer = PayKit::Signer.json(...) end"
        )
        return if value.nil?
        # The legacy field accepted "[]" as a "boot without a real
        # signer" sentinel (mpp-only demos used to set it that way).
        # The new operator default is Signer.demo, so an empty JSON
        # array routes to a no-op — the operator keeps its default
        # signer rather than failing at parse time.
        if value.is_a?(String)
          stripped = value.strip
          return if stripped.empty? || stripped == "[]"
        end

        @parent_config.operator.signer = ::PayKit::Signer.json(value)
      end

      def facilitator_secret_key
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"x402.facilitator_secret_key",
          "use c.operator.signer"
        )
        signer = @parent_config.operator.signer
        signer.respond_to?(:to_json_array) ? signer.to_json_array : nil
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

      # --- deprecated shim -------------------------------------------

      # The old `c.mpp.secret` field is renamed to
      # `c.mpp.challenge_binding_secret` (tracks the spec heading). The
      # shim delegates with a one-line warning.
      def secret=(value)
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"mpp.secret=",
          "use c.mpp.challenge_binding_secret (matches draft-httpauth-payment-00 spec vocabulary)"
        )
        @challenge_binding_secret = value
      end

      def secret
        ::PayKit::Config.send(
          :deprecation_warning_for,
          self,
          :"mpp.secret",
          "use c.mpp.challenge_binding_secret"
        )
        @challenge_binding_secret
      end

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

    def warn_about_public_mainnet_rpc
      return unless @network == :solana_mainnet
      return unless using_public_rpc_default?

      logger_warn(
        "PayKit.config.network = :solana_mainnet uses the public Solana RPC by default. " \
        "Public mainnet RPC is rate-limited and unsuitable for production traffic. " \
        "Set c.rpc_url to a dedicated endpoint (Helius, QuickNode, your own validator)."
      )
    end

    def deprecation_warning(field, suggestion)
      self.class.send(:deprecation_warning_for, self, field, suggestion)
    end

    class << self
      # Shared formatter for deprecation warnings emitted by any of the
      # config shims. Each key is warned at most once per process to
      # avoid spamming the log when the deprecated setter is used in a
      # loop or in a configure block that gets evaluated repeatedly.
      def deprecation_warning_for(_object, key, suggestion)
        @warned_deprecations ||= {}
        return if @warned_deprecations.key?(key)

        @warned_deprecations[key] = true
        logger = ::PayKit.logger || default_deprecation_logger
        logger.warn("PayKit deprecation: c.#{key} is deprecated; #{suggestion}")
      end

      # Reset memo of warned deprecations. Test-only — production code
      # should never need this. Public because the gem's own test suite
      # exercises the warn-once contract per field.
      def reset_deprecation_memo!
        @warned_deprecations = {}
      end

      private

      def default_deprecation_logger
        @default_deprecation_logger ||= ::Logger.new($stderr).tap do |logger|
          logger.formatter = proc { |_severity, _datetime, _progname, msg| "[PayKit] WARN: #{msg}\n" }
        end
      end
    end

    def logger_warn(message)
      logger = ::PayKit.logger || self.class.send(:default_deprecation_logger)
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
      Config.reset_deprecation_memo!
    end
  end
end
