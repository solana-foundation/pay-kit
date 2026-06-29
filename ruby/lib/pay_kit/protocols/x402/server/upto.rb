# frozen_string_literal: true

require "pay_core/solana/account"
require "pay_core/solana/caip2"
require "pay_core/solana/mints"
require "pay_core/solana/message_builder"
require "pay_core/solana/payment_channels"
require "pay_core/solana/rpc"
require "pay_core/solana/transaction"

require_relative "../constants"
require_relative "../error"
require_relative "../protocol/schemes/upto/types"
require_relative "../protocol/schemes/upto/verify"

module PayKit::Protocols::X402
  module Server
    # Server-side x402 `upto` payment-channel engine (facilitator). Validates
    # and broadcasts the client's channel `open`, binds the on-chain channel,
    # then settles the metered actual amount with a single operator voucher and
    # a settle_and_finalize + distribute that refunds the unused remainder.
    #
    # Ruby is server-only for x402: the open-transaction builder and client
    # envelope live in the Rust/Go/Python adapters, and the cross-language
    # harness pairs this engine against those clients. Mirrors the Go engine
    # `go/protocols/x402/upto.go` (`X402Upto`) and the Rust spine.
    #
    # The engine HONORS a zero-actual settlement at the protocol layer (full
    # refund, channel closed, empty transaction signature). The fail-closed
    # treatment of a zero charge is an app-layer policy that lives one level up
    # in the usage middleware (`PayKit::Usage`), not here.
    class Upto
      Types = ::PayKit::Protocols::X402::Protocol::Schemes::Upto
      Verifier = ::PayKit::Protocols::X402::Protocol::Schemes::Upto::Verifier
      Constants = ::PayKit::Protocols::X402::Constants
      PaymentChannels = ::PayCore::Solana::PaymentChannels
      MessageBuilder = ::PayCore::Solana::MessageBuilder
      Account = ::PayCore::Solana::Account
      Rpc = ::PayCore::Solana::Rpc

      DEFAULT_MAX_TIMEOUT_SECONDS = 300
      DEFAULT_DECIMALS = 6
      DEFAULT_RESOURCE_PATH = "/usage"
      DEFAULT_TOKEN_PROGRAM = ::PayCore::Solana::Mints::TOKEN_PROGRAM
      DEFAULT_NETWORK = ::PayCore::Solana::Caip2::DEVNET
      DEFAULT_CONFIRMATION_ATTEMPTS = 40
      DEFAULT_CONFIRMATION_DELAY_SECONDS = 0.25
      CONFIRMED_STATUSES = ["confirmed", "finalized"].freeze

      CAPABILITY_PAYLOAD = {
        implementation: "ruby",
        role: "server",
        capabilities: ["upto"]
      }.freeze

      # A confirmed channel open, carried from `verify_open` into
      # `settle_actual`. `release` frees the in-flight reservation.
      VerifiedOpen = Struct.new(
        :channel_id, :payer, :rent_payer, :mint, :token_program, :program_id,
        :deposit, :max_amount, :expires_at, :network, :release, keyword_init: true
      ) do
        def release!
          release&.call
        end
      end

      # `Config` holds the resolved RPC URL, operator (facilitator) keypair,
      # advertised mint / ceiling / network, and the channel program. Test
      # callers inject `transaction_sender`, `signature_confirmer`,
      # `channel_fetcher`, and `recent_blockhash_provider` to exercise the
      # engine without a live validator; production leaves them nil.
      class Config
        attr_reader :rpc_url, :pay_to, :amount, :mint, :network, :decimals,
          :token_program, :channel_program, :max_timeout_seconds, :resource_path,
          :settlement_header, :operator, :operator_pubkey
        attr_accessor :transaction_sender, :signature_confirmer, :channel_fetcher,
          :recent_blockhash_provider

        def initialize(
          rpc_url:,
          pay_to:,
          facilitator_secret_key:,
          amount:,
          mint:,
          network: DEFAULT_NETWORK,
          decimals: DEFAULT_DECIMALS,
          token_program: DEFAULT_TOKEN_PROGRAM,
          channel_program: PaymentChannels::PROGRAM_ID,
          max_timeout_seconds: DEFAULT_MAX_TIMEOUT_SECONDS,
          resource_path: DEFAULT_RESOURCE_PATH,
          settlement_header: "x-payment-settlement-signature",
          transaction_sender: nil,
          signature_confirmer: nil,
          channel_fetcher: nil,
          recent_blockhash_provider: nil
        )
          raise ArgumentError, "rpc_url is required" if blank?(rpc_url)
          raise ArgumentError, "pay_to is required" if blank?(pay_to)
          raise ArgumentError, "facilitator_secret_key is required" if blank?(facilitator_secret_key)
          raise ArgumentError, "amount is required" if blank?(amount.to_s)
          raise ArgumentError, "mint is required" if blank?(mint)

          @rpc_url = rpc_url
          @pay_to = pay_to
          @amount = amount.to_s
          @mint = mint
          @network = network
          @decimals = decimals
          @token_program = token_program
          @channel_program = blank?(channel_program) ? PaymentChannels::PROGRAM_ID : channel_program
          @max_timeout_seconds = max_timeout_seconds
          @resource_path = blank?(resource_path) ? DEFAULT_RESOURCE_PATH : resource_path
          @settlement_header = settlement_header
          @operator = Account.from_json_array(facilitator_secret_key)
          @operator_pubkey = @operator.public_key.to_s
          @transaction_sender = transaction_sender
          @signature_confirmer = signature_confirmer
          @channel_fetcher = channel_fetcher
          @recent_blockhash_provider = recent_blockhash_provider
        end

        def rpc
          @rpc ||= Rpc.new(@rpc_url)
        end

        private

        def blank?(value)
          value.nil? || value.empty?
        end
      end

      def initialize(config)
        @config = config
        @in_flight = {}
        @mutex = Mutex.new
      end

      # Operator / facilitator public key (base58).
      def operator
        @config.operator_pubkey
      end

      # Build the route-pinned upto requirement, embedding a freshly fetched
      # recent blockhash so the client can build its `open` against the chain
      # the server settles on (issue #175 §4.1, extra.recentBlockhash).
      def requirement(recent_blockhash: fetch_recent_blockhash)
        Types.requirement(
          network: @config.network,
          amount: @config.amount,
          asset: @config.mint,
          pay_to: @config.pay_to,
          max_timeout_seconds: @config.max_timeout_seconds,
          decimals: @config.decimals,
          token_program: @config.token_program,
          fee_payer: operator,
          channel_program: @config.channel_program,
          recent_blockhash: recent_blockhash
        )
      end

      # Base64-encoded PAYMENT-REQUIRED header value for an upto challenge.
      def payment_required(resource: @config.resource_path)
        Types.encode_payment_required(Types.challenge(requirement, resource: resource))
      end

      # Phase 3: validate the payload + the on-chain channel open, broadcast and
      # confirm the open, and return a `VerifiedOpen` bound to the channel. The
      # in-flight reservation guards against a concurrent settle on the same
      # channel and is released on any failure or once settlement completes.
      def verify_open(header, now: Time.now.to_i)
        envelope = Types.parse_payment_signature(header)
        payload = envelope[:payload]
        raise reject("payment signature is missing payload") unless payload.is_a?(Hash)

        req = requirement(recent_blockhash: nil)
        parsed = Verifier.verify_payload!(payload, req, operator, now)

        unless envelope[:network] == req["network"]
          raise reject("network mismatch: payload #{envelope[:network].inspect}, expected #{req["network"].inspect}")
        end
        raise reject("extra.feePayer is not this server's key") unless req.dig("extra", "feePayer") == operator

        program_id = @config.channel_program
        channel_id = payload["channelId"]
        payer = payload["from"]
        raise reject("payment-channel profile requires openTransaction (pull)") if blank?(payload["openTransaction"])

        reserve_channel(channel_id)
        released = false
        begin
          transaction = ::PayCore::Solana::Transaction.from_base64(payload["openTransaction"])
          Verifier.validate_open_instruction!(
            transaction,
            program_id: program_id, operator: operator, payer: payer,
            payee: @config.pay_to, mint: @config.mint, token_program: @config.token_program,
            channel_id: channel_id, max: parsed[:max]
          )
          unless Verifier.fee_payer?(transaction, operator)
            raise reject("open transaction fee payer must be the advertised operator")
          end

          transaction.sign_with(@config.operator)
          broadcast_and_confirm(transaction.to_base64)

          channel = fetch_channel(channel_id)
          validate_channel!(channel, payer: payer, max: parsed[:max])

          verified = VerifiedOpen.new(
            channel_id: channel_id, payer: payer, rent_payer: channel.rent_payer,
            mint: @config.mint, token_program: @config.token_program, program_id: program_id,
            deposit: channel.deposit, max_amount: parsed[:max], expires_at: parsed[:expires_at],
            network: req["network"], release: -> { release_channel(channel_id) }
          )
          released = true
          verified
        ensure
          release_channel(channel_id) unless released
        end
      end

      # Phase 4: settle the metered `actual` amount against a verified open. The
      # operator signs one voucher for `actual`, settle_and_finalize closes the
      # channel, and distribute pays the payee + refunds the payer. A zero
      # actual settles with no voucher and an empty transaction signature is
      # returned (issue #175 §4 Phase 4 step 4).
      def settle_actual(open, actual)
        raise ArgumentError, "verified open is required" if open.nil?

        begin
          Verifier.assert_within_ceiling!(actual, open.max_amount)
          instructions = settlement_instructions(open, actual)
          blockhash = fetch_recent_blockhash || raise(reject("blockhash fetch failed"))
          transaction = MessageBuilder.build_legacy(
            fee_payer: operator, recent_blockhash: blockhash, instructions: instructions
          )
          transaction.sign_with(@config.operator)
          signature = broadcast_and_confirm(transaction.to_base64)

          Types.settlement_response(
            success: true, network: open.network, amount: actual,
            payer: open.payer, transaction: signature
          )
        ensure
          open.release!
        end
      end

      # ---- internals -------------------------------------------------------
      def settlement_instructions(open, actual)
        signature = nil
        if actual.positive?
          message = PaymentChannels.voucher_message_bytes(open.channel_id, actual, open.expires_at)
          signature = @config.operator.sign(message)
          unless signature.bytesize == 64
            raise reject("voucher signature length #{signature.bytesize}, want 64")
          end
        end

        instructions = PaymentChannels.settle_and_finalize_instructions(
          merchant: operator, channel: open.channel_id, authorized_signer: operator,
          signature: signature, cumulative: actual, expires_at: open.expires_at,
          program_id: open.program_id
        )
        instructions << PaymentChannels.create_idempotent_ata_instruction(
          payer: operator, owner: @config.pay_to, mint: open.mint, token_program: open.token_program
        )
        instructions << PaymentChannels.create_idempotent_ata_instruction(
          payer: operator, owner: PaymentChannels::TREASURY_OWNER, mint: open.mint, token_program: open.token_program
        )
        instructions << PaymentChannels.distribute_instruction(
          channel: open.channel_id, payer: open.payer, rent_payer: open.rent_payer,
          payee: @config.pay_to, mint: open.mint, token_program: open.token_program,
          program_id: open.program_id
        )
        instructions
      end

      def validate_channel!(channel, payer:, max:)
        raise reject("channel is not open after broadcast") unless channel.status == PaymentChannels::STATUS_OPEN
        raise reject("token mint mismatch: expected #{@config.mint}, got #{channel.mint}") unless channel.mint == @config.mint
        raise reject("recipient mismatch: expected #{@config.pay_to}, got #{channel.payee}") unless channel.payee == @config.pay_to
        unless channel.distribution_hash == PaymentChannels::EMPTY_DISTRIBUTION_HASH
          raise reject("x402 upto currently supports only empty-recipient payment channels")
        end
        raise reject("channel authorized_signer is not the operator") unless channel.authorized_signer == operator
        raise reject("channel rent_payer is not the operator") unless channel.rent_payer == operator
        raise reject("on-chain deposit #{channel.deposit} must equal authorized maximum #{max}") unless channel.deposit == max
        raise reject("channel payer #{channel.payer} does not match payload.from #{payer}") unless channel.payer == payer
      end

      def reserve_channel(channel_id)
        @mutex.synchronize do
          if @in_flight.key?(channel_id)
            raise reject("channel is already being processed (concurrent request)")
          end

          @in_flight[channel_id] = true
        end
      end

      def release_channel(channel_id)
        @mutex.synchronize { @in_flight.delete(channel_id) }
      end

      def broadcast_and_confirm(transaction_base64)
        signature = if @config.transaction_sender
          @config.transaction_sender.call(@config, transaction_base64)
        else
          @config.rpc.send_raw_transaction(transaction_base64)
        end
        if @config.signature_confirmer
          @config.signature_confirmer.call(@config, signature)
        else
          await_confirmation(signature)
        end
        signature
      end

      def await_confirmation(signature, attempts: DEFAULT_CONFIRMATION_ATTEMPTS, delay: DEFAULT_CONFIRMATION_DELAY_SECONDS)
        attempts.times do
          status = Array(@config.rpc.signature_statuses([signature])).first
          if status.is_a?(Hash)
            raise reject("transaction #{signature} failed on-chain: #{status["err"].inspect}") unless status["err"].nil?
            return signature if CONFIRMED_STATUSES.include?(status["confirmationStatus"])
          end
          sleep(delay)
        end
        raise reject("timed out awaiting confirmation for #{signature}")
      end

      def fetch_channel(channel_id)
        return @config.channel_fetcher.call(@config, channel_id) if @config.channel_fetcher

        info = @config.rpc.get_account_info(channel_id)
        raise reject("channel account fetch failed: missing account data") if info.nil? || info[:data].empty?

        PaymentChannels.decode_channel(info[:data])
      end

      def fetch_recent_blockhash
        return @config.recent_blockhash_provider.call if @config.recent_blockhash_provider

        @config.rpc.latest_blockhash
      rescue Rpc::RpcError
        nil
      end

      def blank?(value)
        value.nil? || value.empty?
      end

      def reject(message)
        ::PayKit::Protocols::X402::Error::PaymentInvalid.new(message)
      end
    end
  end
end
