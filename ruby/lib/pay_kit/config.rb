# frozen_string_literal: true

require_relative "errors"

module PayKit
  # Boot-time configuration. Mutable inside the `PayKit.configure`
  # block; frozen when the block returns.
  class Config
    VALID_NETWORKS = %i[solana_mainnet solana_devnet solana_localnet].freeze
    VALID_SCHEMES = %i[x402 mpp].freeze

    attr_accessor :pay_to
    attr_reader :network, :accept, :stablecoins, :x402, :mpp

    def initialize
      @pay_to = nil
      @network = :solana_devnet
      @accept = %i[x402 mpp].freeze
      @stablecoins = %i[USDC].freeze
      @x402 = X402Config.new
      @mpp = MppConfig.new
    end

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

    # Called by PayKit.configure after the block returns. Freezes
    # the config so post-boot mutation is impossible.
    def freeze!
      @x402.freeze!
      @mpp.freeze!
      freeze
    end

    # Subconfigs ------------------------------------------------------

    class X402Config
      attr_accessor :facilitator
      attr_reader :scheme

      def initialize
        @facilitator = nil
        @scheme = :exact
      end

      def scheme=(value)
        sym = value.to_sym
        unless %i[exact].include?(sym)
          raise ConfigurationError, "unknown x402 scheme #{sym.inspect} (only :exact is supported today)"
        end

        @scheme = sym
      end

      def freeze!
        freeze
      end
    end

    class MppConfig
      attr_accessor :realm, :secret, :expires_in

      def initialize
        @realm = "App"
        @secret = nil
        @expires_in = 300
      end

      def freeze!
        freeze
      end
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

    # Assigning the registry freezes it. Mutating after this point
    # raises FrozenError at write sites.
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
