# frozen_string_literal: true

require "base64"
require "json"

require_relative "../../../constants"
require_relative "../../../error"

module PayKit::Protocols::X402
  module Protocol
    module Schemes
      # `Upto` is the SVM usage-based (`upto`) payment scheme,
      # `payment-channel` profile. The client authorizes a ceiling by opening a
      # payment channel whose `deposit` is the maximum and whose
      # `authorizedSigner` is the operator; the operator (facilitator) settles
      # the actual metered amount with a single voucher after the resource is
      # served. Ruby ships SERVER support only — the open-transaction builder
      # and the client envelope live in the TS/Rust/Go/Python adapters; the
      # cross-language harness pairs this server against those clients.
      #
      # Mirrors the Rust spine `rust/crates/x402/src/protocol/schemes/upto/*`
      # and the Go engine `go/protocols/x402/upto.go`.
      module Upto
        module_function

        # Scheme value advertised in PaymentRequirements.scheme (issue #175 §4.1).
        UPTO_SCHEME = "upto"
        # The single normative v1 profile (issue #175 §3.1).
        PROFILE_PAYMENT_CHANNEL = "payment-channel"

        # Scheme-specific reject token: actual settlement exceeds the signed
        # ceiling (issue #175 §6). Substring-matched by the harness.
        ERROR_SETTLEMENT_EXCEEDS_AMOUNT = "invalid_upto_svm_payload_settlement_exceeds_amount"

        Constants = ::PayKit::Protocols::X402::Constants

        # ---- Envelope decode -------------------------------------------------
        # Decode a base64 PAYMENT-SIGNATURE header into an envelope hash with a
        # symbolized top level and the raw `payload` hash. Falls back to the
        # `accepted` object for scheme/network when the envelope omits them,
        # matching the Go reference (upto.go:384-405).
        def parse_payment_signature(header)
          decoded = Base64.strict_decode64(header)
          envelope = JSON.parse(decoded)
          raise ArgumentError, "payment signature must be a JSON object" unless envelope.is_a?(Hash)

          scheme = envelope["scheme"]
          network = envelope["network"]
          accepted = envelope["accepted"]
          if (scheme.nil? || scheme.empty?) && accepted.is_a?(Hash)
            scheme = accepted["scheme"]
            network = accepted["network"]
          end
          unless scheme == UPTO_SCHEME
            raise ::PayKit::Protocols::X402::Error::InvalidPayloadType, "invalid payload type: #{scheme}"
          end

          {
            x402_version: envelope["x402Version"],
            scheme: scheme,
            network: network,
            accepted: accepted,
            payload: envelope["payload"]
          }
        rescue ArgumentError => error
          raise ::PayKit::Protocols::X402::Error::InvalidPaymentRequired, "invalid 402 response: #{error.message}"
        rescue JSON::ParserError => error
          raise ::PayKit::Protocols::X402::Error::InvalidPaymentRequired, "invalid 402 response: #{error.message}"
        end

        # Parse a base-unit u64 string field, raising a stable message on a
        # malformed value.
        def parse_base_units(value, field)
          Integer(value, 10)
        rescue ArgumentError, TypeError
          raise ::PayKit::Protocols::X402::Error::PaymentInvalid, "invalid upto #{field} #{value.inspect}"
        end

        # ---- Requirement + challenge build -----------------------------------
        # Build the route-pinned upto requirement advertised in
        # PAYMENT-REQUIRED.accepts[] (issue #175 §4.1).
        def requirement(network:, amount:, asset:, pay_to:, max_timeout_seconds:, decimals:, token_program:, fee_payer:, channel_program:, recent_blockhash: nil)
          extra = {
            "profiles" => [PROFILE_PAYMENT_CHANNEL],
            "decimals" => decimals,
            "tokenProgram" => token_program,
            "feePayer" => fee_payer,
            "channelProgram" => channel_program
          }
          extra["recentBlockhash"] = recent_blockhash unless recent_blockhash.nil?
          {
            "scheme" => UPTO_SCHEME,
            "network" => network,
            "amount" => amount.to_s,
            "asset" => asset,
            "payTo" => pay_to,
            "maxTimeoutSeconds" => max_timeout_seconds,
            "extra" => extra
          }
        end

        # Build the full PAYMENT-REQUIRED envelope for an upto challenge.
        def challenge(requirement, resource: nil)
          envelope = {
            "x402Version" => Constants::X402_VERSION_V2,
            "accepts" => [requirement]
          }
          if resource.is_a?(String) && !resource.empty?
            envelope["resource"] = {"type" => "http", "url" => resource, "uri" => resource}
          end
          envelope
        end

        def encode_payment_required(envelope)
          Base64.strict_encode64(JSON.generate(envelope))
        end

        # ---- Settlement response ---------------------------------------------
        # Build the PAYMENT-RESPONSE settlement body (issue #175 §4.3). The
        # transaction signature is the empty string when no token moved
        # (zero-actual), and `amount` is the actual base units charged.
        def settlement_response(success:, network:, amount:, payer: nil, transaction: "", error_reason: nil)
          body = {
            "success" => success,
            "payer" => payer,
            "transaction" => transaction.to_s,
            "network" => network,
            "amount" => amount.to_s
          }
          body["errorReason"] = error_reason unless error_reason.nil?
          body.compact
        end

        def encode_settlement_response(body)
          Base64.strict_encode64(JSON.generate(body))
        end
      end
    end
  end
end
