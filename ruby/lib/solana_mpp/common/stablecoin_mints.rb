# frozen_string_literal: true

module SolanaMpp
  module Common
    # Known stablecoin mint and token-program helpers.
    module StablecoinMints
      TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
      SYSTEM_PROGRAM = "11111111111111111111111111111111"
      ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
      MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
      COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"

      MINTS = {
        "USDC" => {
          "devnet" => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
          "localnet" => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
          "mainnet-beta" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        },
        "USDT" => {
          "mainnet-beta" => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        },
        "USDG" => {
          "devnet" => "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
          "mainnet-beta" => "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
        },
        "PYUSD" => {
          "devnet" => "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
          "mainnet-beta" => "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
        },
        "CASH" => {
          "mainnet-beta" => "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
        }
      }.freeze

      TOKEN_2022_SYMBOLS = ["PYUSD", "USDG", "CASH"].freeze

      module_function

      # Resolve a currency symbol or mint into a mint address.
      def resolve(currency, network)
        return nil if currency.to_s.casecmp("SOL").zero?
        return currency if currency.to_s.length >= 32

        entries = MINTS[currency.to_s.upcase]
        entries&.[](network) || entries&.[]("mainnet-beta") || currency
      end

      # Return the default SPL token program for a currency.
      def token_program_for(currency, network)
        symbol = symbol_for(currency, network)
        TOKEN_2022_SYMBOLS.include?(symbol) ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM
      end

      def symbol_for(currency, network)
        upper = currency.to_s.upcase
        return upper if MINTS.key?(upper)

        resolved = resolve(currency, network)
        MINTS.each do |symbol, entries|
          return symbol if entries.value?(resolved)
        end
        nil
      end
    end
  end
end
