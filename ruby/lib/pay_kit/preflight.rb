# frozen_string_literal: true

require "logger"

require_relative "errors"
require_relative "../pay_core/solana/rpc"
require_relative "../pay_core/solana/ata"
require_relative "../pay_core/solana/mints"

module PayKit
  # Boot-time soundness checks for the operator wallet:
  #
  # 1. The fee payer (operator.signer) has enough SOL to settle.
  # 2. Every stablecoin in `c.stablecoins` has an ATA owned by the
  #    operator's recipient.
  #
  # On `:solana_localnet` with the demo signer, missing accounts are
  # auto-provisioned via the Surfnet cheatcodes (`surfnet_setAccount`,
  # `surfnet_setTokenAccount`) so the example apps "just work" against
  # https://402.surfnet.dev:8899 without manual setup. Anywhere else,
  # a missing account raises `PayKit::ConfigurationError` at boot so the
  # operator is told immediately rather than at the first 402 retry.
  #
  # Opt-in: set `c.preflight = true` inside `PayKit.configure`. RPC errors
  # are logged (not raised) so an unreachable endpoint does not block
  # boot — the runtime will surface that on the first request anyway.
  module Preflight
    # 0.001 SOL — enough for ~200 settlement txs at 5000 lamports/tx.
    MIN_FEE_PAYER_LAMPORTS = 1_000_000

    # 10 SOL — generous local sandbox budget so a developer can poke the
    # example for hours without re-funding.
    AUTOFUND_LAMPORTS = 10_000_000_000

    SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"

    module_function

    def run(config)
      rpc = ::PayCore::Solana::Rpc.new(config.effective_rpc_url)
      autofix = autofix?(config)
      network_label = mints_network_label(config.network)

      check_fee_payer_sol(config, rpc, autofix: autofix)
      Array(config.stablecoins).each do |coin|
        check_recipient_ata(config, rpc, coin, network_label, autofix: autofix)
      end
    rescue ::PayCore::Solana::Rpc::RpcError => e
      logger.warn(
        "[PayKit preflight] skipped — RPC #{config.effective_rpc_url} unreachable (#{e.message}). " \
        "The runtime will surface this again on the first request."
      )
    end

    # Localnet + the gem-shipped demo signer is the only combination
    # where we silently mutate on-chain state. Both gates matter: we
    # never want preflight to touch a real wallet's funds, and we never
    # want to issue cheatcodes against a network that does not support
    # them.
    def autofix?(config)
      config.network == :solana_localnet && config.operator.signer.demo?
    end

    def check_fee_payer_sol(config, rpc, autofix:)
      return unless config.operator.fee_payer?

      pubkey = config.operator.signer.pubkey
      lamports = rpc.call("getBalance", [pubkey, {"commitment" => "confirmed"}]).fetch("value", 0)
      return if lamports >= MIN_FEE_PAYER_LAMPORTS

      if autofix
        autofund_sol(rpc, pubkey)
      else
        raise ::PayKit::ConfigurationError,
          "fee-payer #{pubkey} has #{lamports} lamports on #{config.network} " \
          "(need >= #{MIN_FEE_PAYER_LAMPORTS}). Fund the account before booting."
      end
    end

    def check_recipient_ata(config, rpc, coin, network_label, autofix:)
      mint = ::PayCore::Solana::Mints.resolve(coin.to_s, network_label)
      return if mint.nil? # native SOL — no ATA to check

      token_program = ::PayCore::Solana::Mints.token_program_for(coin.to_s, network_label)
      recipient = config.operator.effective_recipient
      ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: token_program)

      account = rpc.call(
        "getAccountInfo",
        [ata, {"encoding" => "base64", "commitment" => "confirmed"}]
      ).fetch("value", nil)
      return unless account.nil?

      if autofix
        autoprovision_ata(rpc, recipient, mint, token_program, coin)
      else
        raise ::PayKit::ConfigurationError,
          "recipient #{recipient} has no #{coin} ATA on #{config.network} (expected #{ata}). " \
          "Create the ATA before booting (e.g. `spl-token create-account #{mint} --owner #{recipient}`)."
      end
    end

    def autofund_sol(rpc, pubkey)
      logger.info(
        "[PayKit preflight] funding demo fee-payer #{pubkey} with #{AUTOFUND_LAMPORTS} lamports via surfnet_setAccount"
      )
      rpc.call("surfnet_setAccount", [
        pubkey,
        {
          "lamports" => AUTOFUND_LAMPORTS,
          "data" => "",
          "executable" => false,
          "owner" => SYSTEM_PROGRAM_ID,
          "rentEpoch" => 0
        }
      ])
    end

    def autoprovision_ata(rpc, recipient, mint, token_program, coin)
      logger.info(
        "[PayKit preflight] provisioning #{coin} ATA for #{recipient} (mint=#{mint}) via surfnet_setTokenAccount"
      )
      rpc.call("surfnet_setTokenAccount", [
        recipient,
        mint,
        {"amount" => 0, "state" => "initialized"},
        token_program
      ])
    end

    def mints_network_label(network)
      case network
      when :solana_mainnet then "mainnet"
      when :solana_devnet then "devnet"
      when :solana_localnet then "localnet"
      else
        raise ::PayKit::ConfigurationError, "no mints network label for #{network.inspect}"
      end
    end

    def logger
      ::PayKit.logger || (@default_logger ||= ::Logger.new($stderr).tap do |l|
        l.formatter = proc { |_severity, _time, _prog, msg| "#{msg}\n" }
      end)
    end
  end
end
