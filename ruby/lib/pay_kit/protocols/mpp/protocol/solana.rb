# frozen_string_literal: true

require "pay_core/error_codes"
require "pay_core/solana/rpc"
require "pay_core/solana/mints"
require "pay_core/solana/public_key"

module PayKit::Protocols::Mpp
  module Protocol
    module Solana
      # Network slug allowlist (audit #37). The spec requires `network` to be
      # one of these canonical slugs. `"mainnet-beta"` is a Solana RPC hostname
      # convention only and is rejected here in favour of `"mainnet"`.
      NETWORK_MAINNET = "mainnet"
      NETWORK_DEVNET = "devnet"
      NETWORK_LOCALNET = "localnet"
      NETWORKS = [NETWORK_MAINNET, NETWORK_DEVNET, NETWORK_LOCALNET].freeze
      DEFAULT_NETWORK = NETWORK_MAINNET

      # Validate a network slug against the allowlist. Raises on anything
      # outside {mainnet, devnet, localnet} — in particular "mainnet-beta" and
      # "testnet" — so a misconfigured server fails fast at boot rather than
      # silently resolving the mainnet mint (audit #37).
      def self.validate_network!(network)
        slug = network.to_s
        raise Error.new("network is required", code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID) if slug.empty?
        return if NETWORKS.include?(slug)

        raise Error.new(
          "Unsupported network #{slug.inspect}: must be one of #{NETWORKS.join(", ")} " \
          "(use \"mainnet\", not \"mainnet-beta\")",
          code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID
        )
      end

      # Build a Solana charge method bundling all static config (recipient,
      # currency, network, RPC, optional fee payer, decimals). Pass the result
      # to PayKit::Protocols::Mpp.create(method:, ...).
      #
      # `currency` accepts a symbol like "USDC" or "SOL" (looked up against
      # the built-in stablecoin table) or a raw 32-byte mint address.
      #
      #   method = PayKit::Protocols::Mpp::Protocol::Solana.charge(
      #     recipient: "CXhr...",
      #     currency:  "USDC",
      #     network:   "mainnet",
      #     rpc:       "https://api.mainnet-beta.solana.com",
      #   )
      def self.charge(recipient:, currency:, rpc:, network: DEFAULT_NETWORK, fee_payer: nil, decimals: nil)
        validate_network!(network)
        wire_currency = wire_currency_for(currency, network)
        ChargeMethod.new(
          recipient: recipient,
          currency: wire_currency,
          network: network,
          rpc: rpc.is_a?(String) ? ::PayCore::Solana::Rpc.new(rpc) : rpc,
          fee_payer: fee_payer,
          decimals: decimals.nil? ? decimals_for!(wire_currency, network) : Integer(decimals)
        )
      end

      # Wire value of native SOL in `currency`.
      SOL_CURRENCY = "sol"

      # Resolve a configured currency (a symbol such as "USDC" or "SOL", or a
      # mint address) to its wire form. draft-solana-charge-00 `currency`:
      # "For native SOL, MUST be the lowercase string "sol". For SPL tokens,
      # MUST be the base58-encoded mint address." A symbol is accepted in
      # configuration but never reaches the wire (RULINGS C1).
      def self.wire_currency_for(currency, network)
        raise ArgumentError, "currency is required" if currency.to_s.empty?
        return SOL_CURRENCY if currency.to_s.casecmp("SOL").zero?

        mint = ::PayCore::Solana::Mints.resolve(currency.to_s, network)
        begin
          ::PayCore::Solana::PublicKey.new(mint)
        rescue ArgumentError
          raise ArgumentError, "currency #{currency.inspect} is neither SOL, a known stablecoin symbol, nor a mint address"
        end
        mint
      end

      # Decimals for a currency whose precision the stablecoin table knows.
      # An arbitrary mint has no safe default: `decimals` goes on the wire and
      # the client must not assume one (RULINGS C2), so the caller has to pass
      # it explicitly.
      def self.decimals_for!(wire_currency, network)
        return ::PayCore::Solana::Mints::DECIMALS.fetch("SOL") if wire_currency == SOL_CURRENCY
        unless ::PayCore::Solana::Mints.known_currency?(wire_currency, network)
          raise ArgumentError, "decimals is required for mint #{wire_currency} (not a known stablecoin)"
        end

        ::PayCore::Solana::Mints.decimals_for(wire_currency, network)
      end

      # Per-rail config for a Solana charge endpoint. Owns the RPC client,
      # verifier, network identity, and (optionally) a server-side fee payer.
      class ChargeMethod
        BLOCKHASH_TTL_SECONDS = 2.0

        attr_reader :recipient, :currency, :network, :rpc, :fee_payer, :decimals, :verifier

        def initialize(recipient:, currency:, network:, rpc:, fee_payer:, decimals:)
          @recipient = recipient
          @currency = currency
          @network = network
          @rpc = rpc
          @fee_payer = fee_payer
          @decimals = decimals
          @verifier = Verifier.new
          @blockhash = nil
          @blockhash_at = 0.0
        end

        # Public key of the server-side fee payer, or nil when not configured.
        def fee_payer_pubkey
          fee_payer&.public_key&.to_s
        end

        # Default SPL token program for this method's currency+network pair.
        #
        # SOL has no token program. Known stablecoins resolve from the static
        # table. For an ARBITRARY mint address (not in the table), the static
        # table's legacy-Token default is unsafe (audit #28): the mint may be
        # owned by the Token-2022 program. We fetch the mint's on-chain owner
        # once, lazily, and cache it; we reject any owner that is neither the
        # Token nor Token-2022 program. The result is `nil` for SOL.
        def token_program
          return nil if currency == SOL_CURRENCY
          return ::PayCore::Solana::Mints.token_program_for(currency, network) if ::PayCore::Solana::Mints.known_currency?(currency, network)

          resolve_arbitrary_mint_token_program
        end

        # Short-window blockhash cache: every protected request would otherwise
        # spend an RPC round-trip just to get a fresh blockhash. 2s amortizes
        # this without risk to challenge validity (Solana keeps blockhashes
        # valid for ~60s).
        def latest_blockhash
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return @blockhash if @blockhash && (now - @blockhash_at) < BLOCKHASH_TTL_SECONDS

          @blockhash = rpc.latest_blockhash
          @blockhash_at = now
          @blockhash
        end

        # Build the wire-level method_details hash for a charge request.
        # Pass `currency:` to override the method's default — useful when one
        # endpoint accepts multiple currencies (USDC, USDT, ...) and selects
        # one per request.
        #
        # draft-solana-charge-00: `decimals` "MUST be present when `currency`
        # is a mint address; MUST be absent when `currency` is "sol"", and
        # `tokenProgram` "MUST NOT be present when `currency` is "sol""
        # (RULINGS C2/C3). Both are emitted for a mint and omitted for SOL.
        def method_details(currency: self.currency)
          currency = wire_currency(currency)
          details = {"network" => network}
          unless currency == SOL_CURRENCY
            details["decimals"] = (currency == self.currency) ? decimals : Solana.decimals_for!(currency, network)
            details["tokenProgram"] = token_program_for(currency)
          end
          details["recentBlockhash"] = latest_blockhash
          if fee_payer
            details["feePayer"] = true
            details["feePayerKey"] = fee_payer_pubkey
          end
          details
        end

        # Wire form ("sol" or a mint address) of a currency on this method's
        # network. Per-request overrides go through this so a symbol such as
        # "USDT" is resolved before it reaches the challenge.
        def wire_currency(currency)
          (currency == self.currency) ? currency : Solana.wire_currency_for(currency, network)
        end

        private

        # Resolve the token program for a currency on THIS method, routing
        # arbitrary mints through the on-chain owner lookup (audit #28).
        def token_program_for(currency)
          return token_program if currency == self.currency
          return ::PayCore::Solana::Mints.token_program_for(currency, network) if ::PayCore::Solana::Mints.known_currency?(currency, network)

          resolve_arbitrary_mint_token_program(currency)
        end

        # Fetch the on-chain owner of an arbitrary mint and validate it is one
        # of the two SPL token programs. Cached per resolved mint so we issue
        # at most one RPC round-trip per mint for the life of the method.
        # Rejects (rather than silently defaulting to legacy Token) when the
        # owner is unexpected or the mint cannot be fetched (audit #28).
        def resolve_arbitrary_mint_token_program(mint = currency)
          @token_program_cache ||= {}
          @token_program_cache.fetch(mint) do
            owner =
              begin
                rpc.account_owner(mint)
              rescue => error
                raise Error.new(
                  "Could not resolve the token program for mint #{mint}: #{error.message}. " \
                  "Pass the mint's token program explicitly or use a known stablecoin symbol.",
                  code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID
                )
              end
            valid = [::PayCore::Solana::Mints::TOKEN_PROGRAM, ::PayCore::Solana::Mints::TOKEN_2022_PROGRAM]
            unless valid.include?(owner)
              raise Error.new(
                "Mint #{mint} is owned by #{owner.inspect}, not the SPL Token or Token-2022 program",
                code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID
              )
            end
            @token_program_cache[mint] = owner
          end
        end
      end
    end
  end
end
