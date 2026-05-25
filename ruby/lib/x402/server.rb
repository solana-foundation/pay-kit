# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"

require "x402/exact"

module X402
  module Interop
    module Server
      module_function

      CAPABILITY_PAYLOAD = {
        implementation: "ruby",
        role: "server",
        capabilities: ["exact"]
      }.freeze

      DEFAULT_RESOURCE_PATH = "/protected"
      DEFAULT_PRICE = "$0.001"
      DEFAULT_SETTLEMENT_HEADER = "x-fixture-settlement"
      DEFAULT_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      DEFAULT_TOKEN_DECIMALS = 6
      DEFAULT_MAX_TIMEOUT_SECONDS = 60
      DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
      DEFAULT_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
      DEVNET_PYUSD_MINT = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"

      class State
        attr_reader :rpc_url, :network, :mint, :extra_offered_mints, :pay_to, :fee_payer, :fee_payer_secret_key, :amount,
                    :transaction_sender, :settlement_cache, :account_checker

        def initialize(env: ENV, transaction_sender: nil, settlement_cache: nil, account_checker: nil)
          @rpc_url = required_env(env, "X402_INTEROP_RPC_URL")
          @network = env.fetch("X402_INTEROP_NETWORK", DEFAULT_NETWORK)
          @mint = env.fetch("X402_INTEROP_MINT", DEFAULT_MINT)
          @extra_offered_mints = env.fetch("X402_INTEROP_EXTRA_OFFERED_MINTS", "")
                                    .split(",")
                                    .map(&:strip)
                                    .reject(&:empty?)
          @pay_to = required_env(env, "X402_INTEROP_PAY_TO")
          @fee_payer_secret_key = required_env(env, "X402_INTEROP_FACILITATOR_SECRET_KEY")
          @fee_payer = Exact.private_key_from_json(@fee_payer_secret_key)
          @amount = Server.normalize_amount(env.fetch("X402_INTEROP_PRICE", DEFAULT_PRICE))
          @transaction_sender = transaction_sender || Server.method(:send_transaction)
          @settlement_cache = settlement_cache || SettlementCache.new
          @account_checker = account_checker || Server.method(:account_exists?)
        end

        private

        def required_env(env, name)
          value = env[name]
          raise "#{name} is required" if value.nil? || value.empty?

          value
        end
      end

      class SettlementCache
        DEFAULT_TTL_SECONDS = 120

        def initialize(ttl_seconds: DEFAULT_TTL_SECONDS)
          @ttl_seconds = ttl_seconds
          @entries = {}
        end

        def duplicate?(key, now: Time.now)
          prune(now)
          return true if @entries.key?(key)

          @entries[key] = now
          false
        end

        def release(key)
          @entries.delete(key)
        end

        private

        def prune(now)
          cutoff = now - @ttl_seconds
          @entries.delete_if { |_key, seen_at| seen_at < cutoff }
        end
      end

      def normalize_amount(price)
        amount = price.strip.delete_prefix("$").split.first
        whole, dot, fraction = amount.partition(".")
        raise "X402_INTEROP_PRICE has too many decimal places: #{price}" if dot && fraction.length > DEFAULT_TOKEN_DECIMALS

        fraction = fraction.ljust(DEFAULT_TOKEN_DECIMALS, "0")
        ((Integer(whole, 10) * 1_000_000) + Integer(fraction.empty? ? "0" : fraction, 10)).to_s
      end

      def exact_requirement(state, mint: state.mint, resource: nil)
        extra = {
          "feePayer" => Exact.base58_encode(state.fee_payer.raw_public_key),
          "decimals" => DEFAULT_TOKEN_DECIMALS,
          "tokenProgram" => token_program_for_mint(mint)
        }
        # Bind the payment to the resource being unlocked. Without this, a
        # payment built for /resource/a can be replayed against /resource/b.
        # Mirrors the TS reference behavior in
        # `typescript/packages/x402/src/facilitator/exact/scheme.ts` where
        # `requirements.extra.memo` is compared against the on-chain memo
        # instruction. The resource string becomes the canonical memo.
        extra["memo"] = resource if resource.is_a?(String) && !resource.empty?
        {
          "scheme" => "exact",
          "network" => state.network,
          "asset" => mint,
          "amount" => state.amount,
          "payTo" => state.pay_to,
          "maxTimeoutSeconds" => DEFAULT_MAX_TIMEOUT_SECONDS,
          "extra" => extra
        }
      end

      def exact_requirements(state, resource: nil)
        ([state.mint] + state.extra_offered_mints).map do |mint|
          exact_requirement(state, mint: mint, resource: resource)
        end
      end

      def exact_challenge(state, resource: nil)
        {
          "x402Version" => 2,
          "resource" => {
            "type" => "http",
            "uri" => resource || DEFAULT_RESOURCE_PATH
          },
          "accepts" => exact_requirements(state, resource: resource)
        }
      end

      def token_program_for_mint(mint)
        mint == DEVNET_PYUSD_MINT ? Exact::TOKEN_2022_PROGRAM : DEFAULT_TOKEN_PROGRAM
      end

      def payment_requirement_matches?(left, right)
        Exact.accepted_requirement_matches?(left, right)
      end

      def header_value(headers, name)
        normalized = name.downcase
        pair = headers.find { |key, _value| key.downcase == normalized }
        pair && pair[1]
      end

      def encode_payment_required(challenge)
        Base64.strict_encode64(JSON.generate(challenge))
      end

      def settle_exact_payment(state, payment_header, resource: nil)
        decoded = decode_payment_signature(payment_header)
        requirements = exact_requirements(state, resource: resource)
        raise "unsupported x402Version: #{decoded["x402Version"]}" unless decoded["x402Version"] == 2

        accepted = decoded["accepted"]
        # P1.2: Bind the payment to the resource being unlocked. If a resource
        # is expected, the accepted requirement MUST carry the matching memo
        # — otherwise an attacker can replay a payment for resource A against
        # resource B. Raise a typed error before the generic match check so
        # the caller sees the precise reason.
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
          # Mirrors the Go reference at go/cmd/interop-server/main.go:856 which
          # responds with `{"error":"payment_invalid"}` for this class of
          # reject. The canonical token "No matching payment requirements" is
          # included in the raised message so the cross-server scenarios
          # harness (tests/interop/test/cross-server-scenarios.test.ts) can
          # detect it via substring match on the HTTP body.
          raise "No matching payment requirements: accepted payment requirement does not match server challenge"
        end

        payload = decoded["payload"]
        unless payload.is_a?(Hash) && payload["transaction"].is_a?(String)
          raise "payment payload is missing transaction"
        end

        transaction_payload = payload["transaction"]
        transaction = decode_transaction_payload(transaction_payload)
        # Order mirrors the Rust spine at rust/src/bin/interop_server.rs:316-324:
        #   (1) decode envelope, (2) verify all structural constraints,
        #   (3) verify client signatures, (4) apply facilitator signature,
        #   (5) send. We MUST verify the client signature before adding the
        #   facilitator signature; otherwise a malformed envelope still
        #   produces a partially-signed transaction that leaks back to the
        #   caller.
        transfer = Exact.verify_exact_transaction!(
          transaction: transaction,
          requirement: requirement,
          managed_signers: [state.fee_payer.raw_public_key]
        )
        Exact.verify_client_signatures!(transaction, [state.fee_payer.raw_public_key])
        verify_token_accounts_exist!(state, transfer)
        raise "duplicate_settlement" if state.settlement_cache.duplicate?(transaction_payload)

        begin
          signed_transaction = Exact.sign_transaction_with_fee_payer(
            transaction: transaction,
            fee_payer_secret_key: state.fee_payer_secret_key
          )
          state.transaction_sender.call(state, signed_transaction)
        rescue StandardError
          state.settlement_cache.release(transaction_payload)
          raise
        end
      end

      def verify_token_accounts_exist!(state, transfer)
        unless state.account_checker.call(state, Exact.base58_encode(transfer.fetch(:source)))
          raise "source token account does not exist"
        end
        return if transfer.fetch(:destination_create_ata)

        unless state.account_checker.call(state, Exact.base58_encode(transfer.fetch(:destination)))
          raise "destination token account does not exist"
        end
      end

      def decode_payment_signature(payment_header)
        decoded = Base64.strict_decode64(payment_header)
        payload = JSON.parse(decoded)
        raise "payment signature must be a JSON object" unless payload.is_a?(Hash)

        payload
      rescue ArgumentError
        raise "invalid payment signature encoding"
      rescue JSON::ParserError
        raise "invalid payment signature JSON"
      end

      def decode_transaction_payload(transaction)
        Base64.strict_decode64(transaction)
      rescue ArgumentError
        raise "payment payload transaction is not valid base64"
      end

      def send_transaction(state, signed_transaction)
        uri = URI(state.rpc_url)
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

      def account_exists?(state, account)
        uri = URI(state.rpc_url)
        request = Net::HTTP::Post.new(uri)
        request["content-type"] = "application/json"
        request.body = JSON.generate(
          jsonrpc: "2.0",
          id: 1,
          method: "getAccountInfo",
          params: [
            account,
            { encoding: "base64" }
          ]
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
        # Mirrors Go reference at go/cmd/interop-server/main.go:855-858 which
        # uses {"error":"payment_invalid","message":<reason>}. The canonical
        # token "payment_invalid" is one of the reject substrings accepted by
        # the cross-server scenarios harness, so any reject body produced by
        # this server is recognised without depending on the raised message.
        {
          error: "payment_invalid",
          message: reason,
          invalidReason: reason
        }
      end

      def response_for(path, headers, state)
        case path
        when "/health"
          [200, {}, { ok: true }]
        when "/capabilities"
          [200, {}, CAPABILITY_PAYLOAD]
        when "/exact"
          [
            402,
            { "PAYMENT-REQUIRED" => encode_payment_required(exact_challenge(state)) },
            { error: "payment_required" }
          ]
        when DEFAULT_RESOURCE_PATH
          payment_signature = header_value(headers, "PAYMENT-SIGNATURE")
          return payment_required_response(state, resource: path) if payment_signature.nil? || payment_signature.empty?

          begin
            settlement = settle_exact_payment(state, payment_signature, resource: path)
            [
              200,
              { DEFAULT_SETTLEMENT_HEADER => settlement },
              {
                ok: true,
                paid: true,
                settlement: {
                  success: true,
                  transaction: settlement,
                  network: state.network
                }
              }
            ]
          rescue StandardError => e
            [
              402,
              { "PAYMENT-REQUIRED" => encode_payment_required(exact_challenge(state, resource: path)) },
              payment_error_body(e)
            ]
          end
        else
          [
            404,
            {},
            {
              error: "not_found"
            }
          ]
        end
      end

      def payment_required_response(state, resource: nil)
        [
          402,
          { "PAYMENT-REQUIRED" => encode_payment_required(exact_challenge(state, resource: resource)) },
          { error: "payment_required" }
        ]
      end
    end
  end
end
