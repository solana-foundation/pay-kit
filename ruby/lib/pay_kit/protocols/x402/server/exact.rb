# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"

require "pay_core/solana/mints"
require "pay_core/solana/caip2"
require "pay_core/solana/rpc"

require_relative "../constants"
require_relative "../error"
require_relative "../protocol/schemes/exact/types"
require_relative "../protocol/schemes/exact/verify"

module PayKit::Protocols::X402
  module Server
    # Production x402-exact server. Mirrors the Rust spine
    # `rust/crates/x402/src/server/exact.rs` (`Config`, `X402`) plus the
    # interop binary's request loop at
    # `rust/crates/x402/src/bin/interop_server.rs`.
    #
    # Responsibilities:
    # - Build `PAYMENT-REQUIRED` challenge envelopes from `Config`.
    # - Verify incoming `PAYMENT-SIGNATURE` envelopes against the
    #   11-rule `Protocol::Schemes::Exact::Verifier`.
    # - Apply the facilitator signature and broadcast.
    # - Enforce L8 settlement order:
    #     broadcast -> confirm (getSignatureStatuses) -> put_if_absent
    #   keyed on `x402-svm-exact:consumed:<base58_signature>`.
    # - Emit canonical `PAYMENT-RESPONSE` on success.
    class Exact
      # Aliases for readability inside the class body.
      Types = ::PayKit::Protocols::X402::Protocol::Schemes::Exact
      Verifier = ::PayKit::Protocols::X402::Protocol::Schemes::Exact::Verifier
      Constants = ::PayKit::Protocols::X402::Constants

      CAPABILITY_PAYLOAD = {
        implementation: "ruby",
        role: "server",
        capabilities: ["exact"]
      }.freeze

      DEFAULT_RESOURCE_PATH = "/protected"
      DEFAULT_PRICE = "$0.001"
      DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement"

      # Canonical x402 v2 response header (spine constants.rs:31 +
      # rust/crates/x402/src/bin/interop_server.rs:221-231).
      PAYMENT_RESPONSE_HEADER = Constants::PAYMENT_RESPONSE_HEADER

      DEFAULT_TOKEN_PROGRAM = ::PayCore::Solana::Mints::TOKEN_PROGRAM
      DEFAULT_TOKEN_DECIMALS = ::PayCore::Solana::Mints::DEFAULT_DECIMALS
      DEFAULT_MAX_TIMEOUT_SECONDS = 60
      DEFAULT_NETWORK = ::PayCore::Solana::Caip2::DEVNET
      DEFAULT_MINT = ::PayCore::Solana::Mints::MINTS.fetch("USDC").fetch("devnet")
      DEVNET_PYUSD_MINT = ::PayCore::Solana::Mints::MINTS.fetch("PYUSD").fetch("devnet")

      DEFAULT_CONFIRMATION_ATTEMPTS = 40
      DEFAULT_CONFIRMATION_DELAY_SECONDS = 0.25
      CONFIRMED_STATUSES = ["confirmed", "finalized"].freeze

      # Replay store for confirmed Solana signatures. Keys are scheme-
      # namespaced ("x402-svm-exact:consumed:<base58_signature>") so the
      # keyspace cannot bleed into MPP's `solana-charge:consumed:<sig>`
      # namespace. Entries are TTL-pruned so memory stays bounded;
      # Solana's own per-signature uniqueness inside the blockhash
      # window is the durable replay primitive.
      class SettlementCache
        DEFAULT_TTL_SECONDS = 120

        def initialize(ttl_seconds: DEFAULT_TTL_SECONDS)
          @ttl_seconds = ttl_seconds
          @entries = {}
          @mutex = Mutex.new
        end

        def put_if_absent(key, now: Time.now)
          @mutex.synchronize do
            prune(now)
            return false if @entries.key?(key)

            @entries[key] = now
            true
          end
        end

        # Back-compat probe kept for tests asserting TTL eviction
        # semantics. New code on the settlement path MUST use
        # `put_if_absent` so broadcast->confirm->mark stays explicit.
        def duplicate?(key, now: Time.now)
          !put_if_absent(key, now: now)
        end

        private

        def prune(now)
          cutoff = now - @ttl_seconds
          @entries.delete_if { |_key, seen_at| seen_at < cutoff }
        end
      end

      # `Config` mirrors `rust/crates/x402/src/server/exact.rs:21`
      # (the spine `Config` struct). Holds resolved RPC URL,
      # facilitator signer, accepted mints, pay-to, and the replay
      # store. Constructed directly with typed kwargs; harness-
      # specific env-var parsing (X402_INTEROP_*) lives in the
      # interop bin, not in this library.
      class Config
        attr_reader :rpc_url, :network, :mint, :extra_offered_mints, :pay_to, :fee_payer,
          :fee_payer_secret_key, :amount, :resource_path, :settlement_header

        attr_accessor :transaction_sender, :settlement_cache, :account_checker, :signature_confirmer,
          :recent_blockhash_provider

        def initialize(
          rpc_url:,
          pay_to:,
          facilitator_secret_key:,
          amount:,
          network: DEFAULT_NETWORK,
          mint: DEFAULT_MINT,
          extra_offered_mints: [],
          resource_path: DEFAULT_RESOURCE_PATH,
          settlement_header: DEFAULT_SETTLEMENT_HEADER,
          transaction_sender: nil,
          settlement_cache: nil,
          account_checker: nil,
          signature_confirmer: nil,
          recent_blockhash_provider: nil
        )
          raise ArgumentError, "rpc_url is required" if rpc_url.nil? || rpc_url.empty?
          raise ArgumentError, "pay_to is required" if pay_to.nil? || pay_to.empty?
          raise ArgumentError, "facilitator_secret_key is required" if facilitator_secret_key.nil? || facilitator_secret_key.empty?

          @rpc_url = rpc_url
          @network = network
          @mint = mint
          @extra_offered_mints = extra_offered_mints
          @pay_to = pay_to
          @fee_payer_secret_key = facilitator_secret_key
          @fee_payer = Types.private_key_from_json(@fee_payer_secret_key)
          @amount = (amount.is_a?(String) && amount.start_with?("$")) ? Exact.normalize_amount(amount) : amount.to_s
          @resource_path = (resource_path.nil? || resource_path.empty?) ? DEFAULT_RESOURCE_PATH : resource_path
          @settlement_header = (settlement_header.nil? || settlement_header.empty?) ? DEFAULT_SETTLEMENT_HEADER : settlement_header
          @transaction_sender = transaction_sender || Exact.method(:send_transaction)
          @settlement_cache = settlement_cache || SettlementCache.new
          @account_checker = account_checker || Exact.method(:account_exists?)
          @signature_confirmer = signature_confirmer || Exact.method(:await_confirmation)
          @recent_blockhash_provider = recent_blockhash_provider
        end

        # Fetch a recent blockhash from the server's RPC for embedding
        # in the x402 challenge's `extra.recentBlockhash`. Lets the
        # client sign against the server's chain even when the wire
        # CAIP-2 maps to a different public RPC (the localnet → devnet
        # CAIP-2 case for Surfpool / surfnet). Falls back to `nil` on
        # any RPC error — the client then fetches its own blockhash,
        # which is the historical behaviour.
        #
        # The x402 v2 spec does not define a `recentBlockhash` field,
        # but `accepted.extra` is documented as free-form protocol-
        # specific data; pay-kit's Rust client honours it through that
        # extension point (`rust/crates/x402/src/protocol/schemes/
        # exact/types.rs:279-283`).
        def latest_blockhash
          provider = @recent_blockhash_provider || method(:fetch_recent_blockhash)
          provider.call
        end

        def fetch_recent_blockhash
          ::PayCore::Solana::Rpc.new(@rpc_url).latest_blockhash
        rescue ::PayCore::Solana::Rpc::RpcError
          nil
        end
        private :fetch_recent_blockhash

        # Build a `Config` from the harness env vars
        # (X402_INTEROP_*). Only used by the harness x402 adapter at
        # `harness/ruby-x402-server/server.rb`; production callers
        # should call `.new(...)` with typed kwargs directly.
        def self.from_interop_env(env = ENV)
          new(
            rpc_url: required_env(env, "X402_INTEROP_RPC_URL"),
            pay_to: required_env(env, "X402_INTEROP_PAY_TO"),
            facilitator_secret_key: required_env(env, "X402_INTEROP_FACILITATOR_SECRET_KEY"),
            amount: env.fetch("X402_INTEROP_PRICE", DEFAULT_PRICE),
            network: env.fetch("X402_INTEROP_NETWORK", DEFAULT_NETWORK),
            mint: env.fetch("X402_INTEROP_MINT", DEFAULT_MINT),
            extra_offered_mints: env.fetch("X402_INTEROP_EXTRA_OFFERED_MINTS", "")
              .split(",").map(&:strip).reject(&:empty?),
            resource_path: env.fetch("X402_INTEROP_RESOURCE_PATH", DEFAULT_RESOURCE_PATH),
            settlement_header: env.fetch("X402_INTEROP_SETTLEMENT_HEADER", DEFAULT_SETTLEMENT_HEADER)
          )
        end

        def self.required_env(env, name)
          value = env[name]
          raise "#{name} is required" if value.nil? || value.empty?

          value
        end
      end

      # Back-compat alias so existing callers that used the
      # `State` name continue to work.
      State = Config

      # =====================================================================
      # Module-level helpers. These are stateless and exposed at the
      # `PayKit::Protocols::X402::Server::Exact` namespace so callers can reuse the
      # envelope codecs and amount normalizer without instantiating
      # a full server. The production request loop in the bin still
      # threads through a `Config` instance.
      # =====================================================================

      class << self
        def normalize_amount(price)
          amount = price.strip.delete_prefix("$").split.first
          whole, dot, fraction = amount.partition(".")
          raise "X402_INTEROP_PRICE has too many decimal places: #{price}" if dot && fraction.length > DEFAULT_TOKEN_DECIMALS

          fraction = fraction.ljust(DEFAULT_TOKEN_DECIMALS, "0")
          ((Integer(whole, 10) * 1_000_000) + Integer(fraction.empty? ? "0" : fraction, 10)).to_s
        end

        def exact_requirement(config, mint: config.mint, resource: nil)
          extra = {
            "feePayer" => Types.base58_encode(config.fee_payer.raw_public_key),
            "decimals" => DEFAULT_TOKEN_DECIMALS,
            "tokenProgram" => token_program_for_mint(mint)
          }
          # Bind the payment to the resource being unlocked. Without this,
          # a payment built for /resource/a can be replayed against
          # /resource/b. Mirrors the TS reference behavior in
          # `typescript/packages/x402/src/facilitator/exact/scheme.ts` where
          # `requirements.extra.memo` is compared against the on-chain memo
          # instruction.
          extra["memo"] = resource if resource.is_a?(String) && !resource.empty?
          # Embed the server's recent blockhash so the client signs
          # against the chain the server will settle on, not the public
          # cluster the wire CAIP-2 happens to advertise. Required for
          # local validators (Surfpool / surfnet) that present as devnet
          # on the wire but expose a different ledger. `nil` is dropped
          # so the client falls back to its own `getLatestBlockhash`.
          if (blockhash = config.latest_blockhash)
            extra["recentBlockhash"] = blockhash
          end
          {
            "scheme" => Constants::EXACT_SCHEME,
            "network" => config.network,
            "asset" => mint,
            # Emit both `amount` (spine canonical, also what
            # Types#accepted_requirement_matches?  identity tuple
            # checks) and `maxAmountRequired` (what the ts-x402
            # client adapter reads via `offer.maxAmountRequired`).
            # Rust spine's parser accepts either spelling
            # (rust/crates/x402/src/protocol/schemes/exact/types.rs:337-339).
            "amount" => config.amount,
            "maxAmountRequired" => config.amount,
            "payTo" => config.pay_to,
            "maxTimeoutSeconds" => DEFAULT_MAX_TIMEOUT_SECONDS,
            "extra" => extra
          }
        end

        def exact_requirements(config, resource: nil)
          ([config.mint] + config.extra_offered_mints).map do |mint|
            exact_requirement(config, mint: mint, resource: resource)
          end
        end

        def exact_challenge(config, resource: nil)
          {
            "x402Version" => Constants::X402_VERSION_V2,
            # Rust spine deserialises this into `ResourceInfo {url,
            # description?, mimeType?}` and the TS server fixture emits
            # the URI as a top-level string. Emit both `url` and `uri`
            # so either client parser accepts the envelope.
            "resource" => {
              "type" => "http",
              "url" => resource || config.resource_path,
              "uri" => resource || config.resource_path
            },
            "accepts" => exact_requirements(config, resource: resource)
          }
        end

        def token_program_for_mint(mint)
          (mint == DEVNET_PYUSD_MINT) ? Types::TOKEN_2022_PROGRAM : DEFAULT_TOKEN_PROGRAM
        end

        def payment_requirement_matches?(left, right)
          Types.accepted_requirement_matches?(left, right)
        end

        def header_value(headers, name)
          normalized = name.downcase
          pair = headers.find { |key, _value| key.downcase == normalized }
          pair && pair[1]
        end

        def encode_payment_required(challenge)
          Base64.strict_encode64(JSON.generate(challenge))
        end

        def signature_consumed_key(signature)
          "x402-svm-exact:consumed:#{signature}"
        end

        # ---- L8 settlement: verify + broadcast + confirm + record ----
        #
        # Order MUST be:
        #   (1) decode envelope
        #   (2) verify structural constraints (11-rule Verifier)
        #   (3) verify client signatures
        #   (4) apply facilitator signature
        #   (5) broadcast
        #   (6) confirm via getSignatureStatuses poll
        #   (7) put_if_absent("x402-svm-exact:consumed:<base58_sig>")
        #
        # Mirrors MPP `server/charge.rs:535-556` and the spine ordering
        # at `rust/crates/x402/src/bin/interop_server.rs:316-324`.
        def settle_exact_payment(config, payment_header, resource: nil)
          decoded = Types.decode_payment_signature(payment_header)
          requirements = exact_requirements(config, resource: resource)
          raise "unsupported x402Version: #{decoded["x402Version"]}" unless decoded["x402Version"] == Constants::X402_VERSION_V2

          accepted = decoded["accepted"]
          if resource.is_a?(String) && !resource.empty? && accepted.is_a?(Hash)
            accepted_memo = accepted.dig("extra", "memo")
            unless accepted_memo == resource
              raise "invalid_exact_svm_payload_resource_mismatch"
            end
          end

          requirement = if accepted.is_a?(Hash)
            requirements.find { |candidate| payment_requirement_matches?(accepted, candidate) }
          end
          unless requirement
            # Mirrors Go reference (go/cmd/interop-server/main.go:856).
            raise "No matching payment requirements: accepted payment requirement does not match server challenge"
          end

          payload = decoded["payload"]
          unless payload.is_a?(Hash) && payload["transaction"].is_a?(String)
            raise "payment payload is missing transaction"
          end

          transaction = Types.decode_transaction_payload(payload["transaction"])

          transfer = Verifier.verify(
            transaction,
            requirement,
            managed_signers: [config.fee_payer.raw_public_key]
          )
          Verifier.verify_client_signatures!(transaction, [config.fee_payer.raw_public_key])
          verify_token_accounts_exist!(config, transfer)

          signed_transaction = Types.sign_transaction_with_fee_payer(
            transaction: transaction,
            fee_payer_secret_key: config.fee_payer_secret_key
          )

          # L8 settlement order. There is no release-on-failure path;
          # the durable replay primitive is Solana's per-signature
          # uniqueness inside the blockhash window.
          signature = config.transaction_sender.call(config, signed_transaction)
          config.signature_confirmer.call(config, signature)

          unless config.settlement_cache.put_if_absent(signature_consumed_key(signature))
            raise ::PayKit::Protocols::X402::Error::SignatureConsumed::TOKEN
          end

          signature
        end

        def verify_token_accounts_exist!(config, transfer)
          unless config.account_checker.call(config, Types.base58_encode(transfer.fetch(:source)))
            raise "source token account does not exist"
          end

          # Per the official x402 SVM exact contract the destination ATA MUST
          # pre-exist; the verifier rejects any in-band ATA-create, so the
          # destination is always checked here.
          unless config.account_checker.call(config, Types.base58_encode(transfer.fetch(:destination)))
            raise "destination token account does not exist"
          end
        end

        # ---- JSON-RPC helpers ----------------------------------------
        def send_transaction(config, signed_transaction)
          uri = URI(config.rpc_url)
          request = Net::HTTP::Post.new(uri)
          request["content-type"] = "application/json"
          request.body = JSON.generate(
            jsonrpc: "2.0",
            id: 1,
            method: "sendTransaction",
            params: [
              Base64.strict_encode64(signed_transaction),
              {
                encoding: "base64",
                skipPreflight: false,
                preflightCommitment: "processed",
                maxRetries: 3
              }
            ]
          )
          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") do |http|
            http.request(request)
          end
          raise "sendTransaction HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          payload = JSON.parse(response.body)
          raise "sendTransaction RPC error: #{rpc_error_message(payload["error"])}" if payload["error"]

          result = payload["result"]
          raise "sendTransaction returned empty signature" unless result.is_a?(String) && !result.empty?

          result
        end

        def await_confirmation(config, signature, attempts: DEFAULT_CONFIRMATION_ATTEMPTS,
          delay_seconds: DEFAULT_CONFIRMATION_DELAY_SECONDS, sleeper: method(:sleep))
          attempts.times do
            statuses = fetch_signature_statuses(config, [signature])
            status = statuses.first
            if status.is_a?(Hash)
              err = status["err"]
              raise "transaction #{signature} failed on-chain: #{err.inspect}" unless err.nil?
              return signature if CONFIRMED_STATUSES.include?(status["confirmationStatus"])
            end
            sleeper.call(delay_seconds)
          end
          raise "timed out awaiting confirmation for #{signature}"
        end

        def fetch_signature_statuses(config, signatures)
          uri = URI(config.rpc_url)
          request = Net::HTTP::Post.new(uri)
          request["content-type"] = "application/json"
          request.body = JSON.generate(
            jsonrpc: "2.0",
            id: 1,
            method: "getSignatureStatuses",
            params: [signatures, {searchTransactionHistory: false}]
          )
          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") do |http|
            http.request(request)
          end
          raise "getSignatureStatuses HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          payload = JSON.parse(response.body)
          raise "getSignatureStatuses RPC error: #{rpc_error_message(payload["error"])}" if payload["error"]

          result = payload["result"]
          (result.is_a?(Hash) ? result["value"] : nil) || []
        end

        def account_exists?(config, account)
          uri = URI(config.rpc_url)
          request = Net::HTTP::Post.new(uri)
          request["content-type"] = "application/json"
          request.body = JSON.generate(
            jsonrpc: "2.0",
            id: 1,
            method: "getAccountInfo",
            params: [account, {encoding: "base64"}]
          )
          response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") do |http|
            http.request(request)
          end
          raise "getAccountInfo HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

          payload = JSON.parse(response.body)
          raise "getAccountInfo RPC error: #{rpc_error_message(payload["error"])}" if payload["error"]

          result = payload["result"]
          result.is_a?(Hash) && !result["value"].nil?
        end

        def rpc_error_message(error)
          return error["message"] if error.is_a?(Hash) && error["message"].is_a?(String)

          error.to_s
        end

        def payment_error_body(error)
          reason = error.message
          {
            error: "payment_invalid",
            message: reason,
            invalidReason: reason
          }
        end

        # ---- HTTP request dispatch -----------------------------------
        # Mirrors the spine request loop at
        # `rust/crates/x402/src/bin/interop_server.rs` and returns the
        # tuple shape `[status, headers, body]` that the bin's TCP
        # adapter serializes.
        def response_for(path, headers, config)
          case path
          when "/health"
            [200, {}, {ok: true}]
          when "/capabilities"
            [200, {}, CAPABILITY_PAYLOAD]
          when "/exact"
            [
              402,
              {Constants::PAYMENT_REQUIRED_HEADER => encode_payment_required(exact_challenge(config))},
              {error: "payment_required"}
            ]
          when config.resource_path
            payment_signature = header_value(headers, Constants::PAYMENT_SIGNATURE_HEADER)
            return payment_required_response(config, resource: path) if payment_signature.nil? || payment_signature.empty?

            begin
              settlement = settle_exact_payment(config, payment_signature, resource: path)
              payment_response = JSON.generate(
                success: true,
                network: config.network,
                transaction: settlement
              )
              [
                200,
                {
                  config.settlement_header => settlement,
                  PAYMENT_RESPONSE_HEADER => payment_response
                },
                {
                  ok: true,
                  paid: true,
                  settlement: {
                    success: true,
                    transaction: settlement,
                    network: config.network
                  }
                }
              ]
            rescue => e
              [
                402,
                {Constants::PAYMENT_REQUIRED_HEADER => encode_payment_required(exact_challenge(config, resource: path))},
                payment_error_body(e)
              ]
            end
          else
            [404, {}, {error: "not_found"}]
          end
        end

        def payment_required_response(config, resource: nil)
          [
            402,
            {Constants::PAYMENT_REQUIRED_HEADER => encode_payment_required(exact_challenge(config, resource: resource))},
            {error: "payment_required"}
          ]
        end
      end
    end
  end
end
