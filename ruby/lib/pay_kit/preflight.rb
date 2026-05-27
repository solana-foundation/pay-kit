# frozen_string_literal: true

require "logger"
require "securerandom"

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
  # 3. `c.mpp.challenge_binding_secret` is non-nil — resolved from the
  #    `PAY_KIT_MPP_CHALLENGE_BINDING_SECRET` env var, then `./.env`,
  #    then auto-generated and persisted to `./.env` when neither
  #    source is available.
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

    # Env var name + on-disk key. Matches the convention from
    # the Sinatra example (`PAY_KIT_MPP_CHALLENGE_BINDING_SECRET`).
    MPP_SECRET_ENV_VAR = "PAY_KIT_MPP_CHALLENGE_BINDING_SECRET"

    module_function

    def run(config)
      # The secret resolution runs first because it doesn't need RPC
      # and shouldn't be skipped when the network is unreachable.
      ensure_challenge_binding_secret!(config)

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

    # Resolve `c.mpp.challenge_binding_secret` when the user didn't
    # set it explicitly inside `PayKit.configure`. Resolution order,
    # first hit wins:
    #
    #   1. `ENV[MPP_SECRET_ENV_VAR]` — the production pattern
    #      (orchestrator-supplied env var).
    #   2. `./.env` file in the current working directory — sticky
    #      across restarts and shared by Puma workers in the same
    #      project root.
    #   3. `SecureRandom.hex(32)` — newly generated. Persisted to
    #      `./.env` so subsequent boots reuse the same secret.
    #
    # Falls back to a per-process random value and a logged warning
    # if `./.env` is unwritable (e.g. read-only containers) — the
    # server still boots, just without secret stickiness across
    # restarts.
    def ensure_challenge_binding_secret!(config)
      return if config.mpp.challenge_binding_secret

      from_env = ENV[MPP_SECRET_ENV_VAR]
      if from_env && !from_env.empty?
        config.mpp.challenge_binding_secret = from_env
        return
      end

      from_dotenv = read_dotenv_value(MPP_SECRET_ENV_VAR)
      if from_dotenv
        ENV[MPP_SECRET_ENV_VAR] = from_dotenv
        config.mpp.challenge_binding_secret = from_dotenv
        return
      end

      generated = ::SecureRandom.hex(32)
      persisted = persist_dotenv_value(MPP_SECRET_ENV_VAR, generated)
      if persisted
        logger.info(
          "[PayKit preflight] generated #{MPP_SECRET_ENV_VAR} and wrote it to ./.env. " \
          "Add `.env` to .gitignore (it almost certainly is already) and override via " \
          "your orchestrator's secret manager in production."
        )
      else
        logger.warn(
          "[PayKit preflight] generated #{MPP_SECRET_ENV_VAR} but could not persist to ./.env — " \
          "secret will rotate on every boot, which invalidates in-flight challenges. " \
          "Set #{MPP_SECRET_ENV_VAR} explicitly in your environment to make it sticky."
        )
      end
      ENV[MPP_SECRET_ENV_VAR] = generated
      config.mpp.challenge_binding_secret = generated
    end

    # Read a single key from `./.env`. Returns `nil` if the file does
    # not exist, the key is absent, or the line is malformed. Tolerant
    # parser: ignores blank lines + `#` comments + supports both
    # `KEY=value` and `KEY="value"` forms. Doesn't pull in the
    # `dotenv` gem to keep the dependency surface minimal.
    def read_dotenv_value(key)
      path = dotenv_path
      return nil unless ::File.readable?(path)

      ::File.foreach(path) do |line|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")
        name, _, raw_value = stripped.partition("=")
        next unless name.strip == key

        value = raw_value.strip
        value = value[1..-2] if value.start_with?('"') && value.end_with?('"')
        value = value[1..-2] if value.start_with?("'") && value.end_with?("'")
        return value
      end
      nil
    end

    # Append a `KEY="value"` line to `./.env`, creating the file at
    # mode 0600 if absent. Returns `true` on success, `false` if the
    # directory is unwritable.
    def persist_dotenv_value(key, value)
      path = dotenv_path
      created = !::File.exist?(path)
      ::File.open(path, "a") do |f|
        f.write("\n") if !created && !::File.read(path).end_with?("\n")
        f.write("#{key}=\"#{value}\"\n")
      end
      ::File.chmod(0o600, path) if created
      true
    rescue ::SystemCallError
      false
    end

    def dotenv_path
      ::File.join(::Dir.pwd, ".env")
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
