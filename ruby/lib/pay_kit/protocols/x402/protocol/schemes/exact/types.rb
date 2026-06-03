# frozen_string_literal: true

require "base64"
require "ed25519"
require "json"
require "securerandom"

require "pay_core/solana/base58"
require "pay_core/solana/mints"
require "pay_core/solana/programs"
require "pay_core/solana/public_key"
require "pay_core/solana/ata"
require "pay_core/solana/rpc"
require "pay_core/solana/transaction"

require_relative "../../../constants"
require_relative "../../../error"

module PayKit::Protocols::X402
  module Protocol
    module Schemes
      # `Exact` is the SVM "exact" payment scheme. This module hosts the
      # server-side value-object helpers, the wire-envelope decoders, and
      # the fee-payer co-signing step. Ruby ships server support only, so
      # the client-side transaction builder is NOT here; production
      # clients live in the TS/Rust/Go/Python adapters.
      #
      # Mirrors the Rust spine
      # `rust/crates/x402/src/protocol/schemes/exact/types.rs` which
      # likewise consumes `solana-pay-core` rather than redefining
      # program IDs in the x402 crate.
      module Exact
        module_function

        # ---- Shared core aliases (PayCore Solana primitives) -----------
        Base58 = ::PayCore::Solana::Base58
        Mints = ::PayCore::Solana::Mints
        Programs = ::PayCore::Solana::Programs
        PublicKey = ::PayCore::Solana::PublicKey
        ATA = ::PayCore::Solana::ATA
        Rpc = ::PayCore::Solana::Rpc
        TransactionCodec = ::PayCore::Solana::Transaction

        # ---- Program IDs (spine types.rs:55-63) ------------------------
        COMPUTE_BUDGET_PROGRAM = ::PayKit::Protocols::X402::Constants::COMPUTE_BUDGET_PROGRAM
        MEMO_PROGRAM = ::PayKit::Protocols::X402::Constants::MEMO_PROGRAM
        ASSOCIATED_TOKEN_PROGRAM = ::PayKit::Protocols::X402::Constants::ASSOCIATED_TOKEN_PROGRAM
        SYSTEM_PROGRAM = ::PayKit::Protocols::X402::Constants::SYSTEM_PROGRAM
        TOKEN_2022_PROGRAM = ::PayKit::Protocols::X402::Constants::TOKEN_2022_PROGRAM
        LIGHTHOUSE_PROGRAM = ::PayKit::Protocols::X402::Constants::LIGHTHOUSE_PROGRAM

        # ---- Compute budget bounds (spine verify.rs compute price gate) -
        DEFAULT_COMPUTE_UNIT_LIMIT = ::PayKit::Protocols::X402::Constants::DEFAULT_COMPUTE_UNIT_LIMIT
        DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = ::PayKit::Protocols::X402::Constants::DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = ::PayKit::Protocols::X402::Constants::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
        MAX_MEMO_BYTES = ::PayKit::Protocols::X402::Constants::MAX_MEMO_BYTES

        # Thin Ed25519 signer adapter. Mirrors spine signer interface:
        # builds an `Ed25519::SigningKey` from a 32-byte Solana seed and
        # signs raw message bytes with no pre-hashing.
        class Ed25519PrivateKey
          attr_reader :raw_public_key

          def initialize(seed)
            @signing_key = ::Ed25519::SigningKey.new(seed)
            @raw_public_key = @signing_key.verify_key.to_bytes
          end

          def sign(_digest, message)
            @signing_key.sign(message)
          end
        end

        # Apply the facilitator-managed (fee-payer) signature to a
        # client-signed transaction. Mirrors the spine fee-payer
        # signing step at `rust/crates/x402/src/bin/interop_server.rs:316-324`.
        def sign_transaction_with_fee_payer(transaction:, fee_payer_secret_key:)
          private_key = private_key_from_json(fee_payer_secret_key)
          bytes = transaction.b
          signature_count, offset = read_short_vec(bytes, 0)
          signatures_offset = offset
          message_offset = signatures_offset + (signature_count * 64)
          raise ArgumentError, "transaction has no message bytes" if message_offset >= bytes.bytesize

          message = bytes.byteslice(message_offset, bytes.bytesize - message_offset)
          signer_index = required_signer_index(message, private_key.raw_public_key)
          raise ArgumentError, "fee payer is not present in transaction signatures" if signer_index >= signature_count

          signed = bytes.dup
          signed[signatures_offset + (signer_index * 64), 64] = private_key.sign(nil, message)
          signed
        end

        # Match on identifying fields only (scheme/network/asset/payTo
        # and the canonical `extra` knobs feePayer/tokenProgram/memo).
        # Amount and maxTimeoutSeconds are intentionally excluded: the
        # TS reference server (harness/src/fixtures/typescript/
        # exact-server.ts:141-143) only matches scheme/network/asset
        # and the v2 client leaves `amount` out of `accepted` to allow
        # a per-request facilitator to fill it in. Comparing them
        # strictly broke cross-language interop ("No matching payment
        # requirements" against structurally compatible payloads).
        REQUIREMENT_IDENTITY_KEYS = %w[scheme network asset payTo].freeze
        REQUIREMENT_EXTRA_IDENTITY_KEYS = %w[feePayer tokenProgram memo].freeze

        def accepted_requirement_matches?(left, right)
          return false unless left.is_a?(Hash) && right.is_a?(Hash)
          return false unless REQUIREMENT_IDENTITY_KEYS.all? { |key| left[key] == right[key] }

          left_extra = left["extra"] || {}
          right_extra = right["extra"] || {}
          REQUIREMENT_EXTRA_IDENTITY_KEYS.all? do |key|
            !right_extra.key?(key) || left_extra[key] == right_extra[key]
          end
        end

        # ---- Versioned transaction codec ------------------------------
        def parse_versioned_transaction(transaction)
          bytes = transaction.b
          signature_count, offset = read_short_vec(bytes, 0)
          message_offset = offset + (signature_count * 64)
          raise "transaction has no message bytes" if message_offset >= bytes.bytesize

          message = bytes.byteslice(message_offset, bytes.bytesize - message_offset)
          parse_versioned_message(message)
        end

        def parse_versioned_message(message)
          raise "expected versioned transaction message" unless message.getbyte(0) == 0x80
          raise "transaction message header extends beyond input" if message.bytesize < 4

          account_count, offset = read_short_vec(message, 4)
          account_keys = account_count.times.map do |index|
            start = offset + (index * 32)
            raise "message account key extends beyond input" if start + 32 > message.bytesize

            message.byteslice(start, 32)
          end
          offset += account_count * 32
          raise "message recent blockhash extends beyond input" if offset + 32 > message.bytesize

          offset += 32
          instruction_count, offset = read_short_vec(message, offset)
          instructions = instruction_count.times.map do
            raise "instruction program index extends beyond input" if offset >= message.bytesize

            program_index = message.getbyte(offset)
            offset += 1
            account_index_count, offset = read_short_vec(message, offset)
            raise "instruction account indexes extend beyond input" if offset + account_index_count > message.bytesize

            accounts = message.byteslice(offset, account_index_count).bytes
            offset += account_index_count
            data_length, offset = read_short_vec(message, offset)
            raise "instruction data extends beyond input" if offset + data_length > message.bytesize

            data = message.byteslice(offset, data_length)
            offset += data_length
            {program_index: program_index, accounts: accounts, data: data}
          end

          read_short_vec(message, offset) if offset < message.bytesize
          {account_keys: account_keys, instructions: instructions}
        end

        # ---- Envelope codecs ------------------------------------------
        # PaymentSignatureEnvelope decode. Mirrors spine deserialize at
        # `rust/crates/x402/src/protocol/schemes/exact/types.rs:482-493`.
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

        # ---- x402 v2 extensions (spine types.rs:479-585) ---------------
        #
        # The `extensions` object rides on BOTH the inbound PAYMENT-REQUIRED
        # challenge and the outbound PAYMENT-SIGNATURE credential. The wire
        # JSON key for the payment-identifier extension is kebab-case
        # `payment-identifier` (spine `#[serde(rename = "payment-identifier")]`);
        # its `info` is camelCase `{ required?, id? }` and `schema?` is echoed
        # verbatim. Unknown extensions are preserved verbatim under their own
        # key so the echo-and-append rule (x402 v2 §5.1.2) never drops a
        # forward-compatible payload (spine `PaymentExtensions.other` flatten).
        #
        # Ruby ships SERVER support only, so the echo-and-append (client) path
        # is exercised by the conformance reference; the SDK uses these helpers
        # to ADVERTISE the extension on a challenge and to PARSE/GATE an
        # inbound credential's echoed extension on verify.

        # kebab-case wire key for the payment-identifier extension.
        PAYMENT_IDENTIFIER_KEY = "payment-identifier"

        # Spec pattern for a client-side idempotency id, ^[A-Za-z0-9_-]{16,128}$
        # (spine types.rs:488).
        PAYMENT_IDENTIFIER_ID_PATTERN = /\A[A-Za-z0-9_-]{16,128}\z/

        # Spine `generate_payment_identifier_id`: `pay_` + 32 lowercase hex
        # (36 total). Satisfies the spec pattern above and the canonical
        # Solana `^pay_[a-zA-Z0-9_-]{10,120}$` shape. Reuse across retries of
        # the same logical request for idempotency.
        def generate_payment_identifier_id
          "pay_" + SecureRandom.hex(16)
        end

        # Spine `PaymentExtensions::echoing`: deep-copy the inbound extensions
        # blob so unknown keys round-trip verbatim. Returns nil when the server
        # advertised no extensions (so the outbound omits the object). Raises
        # when the inbound is present but not a JSON object.
        def echo_extensions(inbound)
          return nil if inbound.nil?
          raise ArgumentError, "extensions must be a JSON object" unless inbound.is_a?(Hash)

          deep_dup_json(inbound)
        end

        # Spine `PaymentExtensions::requires_payment_identifier`:
        # payment-identifier.info.required == true.
        def requires_payment_identifier?(extensions)
          return false unless extensions.is_a?(Hash)

          pid = extensions[PAYMENT_IDENTIFIER_KEY]
          pid.is_a?(Hash) && pid.dig("info", "required") == true
        end

        # Spine `PaymentExtensions::with_payment_identifier_id`: set the
        # client-side id, creating the entry if the server did not advertise
        # one, preserving the server-side `info.required` and `schema`
        # verbatim (does NOT overwrite server fields).
        def with_payment_identifier_id(extensions, id)
          next_ext = extensions.is_a?(Hash) ? deep_dup_json(extensions) : {}
          entry = next_ext[PAYMENT_IDENTIFIER_KEY]
          entry = {"info" => {}} unless entry.is_a?(Hash)
          info = entry["info"].is_a?(Hash) ? entry["info"] : {}
          entry["info"] = info.merge("id" => id)
          next_ext[PAYMENT_IDENTIFIER_KEY] = entry
          next_ext
        end

        # Spine `PaymentExtensions::is_empty`: no payment_identifier and no
        # other keys. Callers use this to avoid emitting an empty
        # `extensions: {}` object (spine skip_serializing_if = Option::is_none).
        def extensions_empty?(extensions)
          return true unless extensions.is_a?(Hash)

          extensions.empty?
        end

        # Echoed payment-identifier id off a parsed credential's extensions,
        # or nil. Used by the server reject gate.
        def payment_identifier_id(extensions)
          return nil unless extensions.is_a?(Hash)

          extensions.dig(PAYMENT_IDENTIFIER_KEY, "info", "id")
        end

        # True when `id` is a non-empty string matching the spec pattern.
        def payment_identifier_id_valid?(id)
          id.is_a?(String) && !id.empty? && PAYMENT_IDENTIFIER_ID_PATTERN.match?(id)
        end

        def deep_dup_json(value)
          case value
          when Hash then value.each_with_object({}) { |(k, v), acc| acc[k] = deep_dup_json(v) }
          when Array then value.map { |v| deep_dup_json(v) }
          else value
          end
        end

        # ---- Keypair / signer helpers ---------------------------------
        def private_key_from_json(raw)
          bytes = JSON.parse(raw)
          unless bytes.is_a?(Array) && bytes.length == 64
            raise ArgumentError, "expected a 64-byte Solana secret key JSON array"
          end

          seed = bytes.first(32).pack("C*")
          Ed25519PrivateKey.new(seed)
        end

        # Derive the associated token account address as raw 32-byte pubkey.
        # Delegates to `PayCore::Solana::ATA.derive`.
        def associated_token_address(wallet, token_program, mint)
          ata_base58 = ATA.derive(
            owner: wallet,
            mint: mint,
            token_program: token_program
          )
          base58_decode(ata_base58)
        end

        # Verify an Ed25519 signature against a message and public key.
        # Backed by the `ed25519` runtime gem.
        def verify_ed25519(public_key, message, signature)
          return false unless signature.is_a?(String) && signature.bytesize == 64
          return false unless public_key.is_a?(String) && public_key.bytesize == 32

          ::Ed25519::VerifyKey.new(public_key).verify(signature, message)
          true
        rescue ::Ed25519::VerifyError
          false
        end

        def base58_decode(value)
          Base58.decode(value)
        end

        def base58_encode(bytes)
          Base58.encode(bytes)
        end

        def short_vec(length)
          TransactionCodec.short_vec(length)
        end

        def read_short_vec(bytes, offset)
          TransactionCodec.read_short_vec(bytes, offset)
        end

        def required_signer_index(message, public_key)
          raise ArgumentError, "expected versioned transaction message" unless message.getbyte(0) == 0x80

          required_signatures = message.getbyte(1)
          account_count, account_offset = read_short_vec(message, 4)
          keys = account_count.times.map do |index|
            start = account_offset + (index * 32)
            raise ArgumentError, "message account key extends beyond input" if start + 32 > message.bytesize

            message.byteslice(start, 32)
          end
          signer_keys = keys.first(required_signatures)
          signer_index = signer_keys.index(public_key)
          raise ArgumentError, "fee payer not found in required signer accounts" if signer_index.nil?

          signer_index
        end

        def integer_extra(requirement, key)
          value = requirement.fetch("extra").fetch(key)
          value.is_a?(String) ? Integer(value, 10) : Integer(value)
        rescue KeyError, ArgumentError, TypeError
          raise ArgumentError, "payment requirement has invalid extra.#{key}"
        end

        def string_extra(requirement, key, required: true)
          value = requirement.fetch("extra").fetch(key)
          raise ArgumentError, "payment requirement has invalid extra.#{key}" unless value.is_a?(String)

          value
        rescue KeyError
          raise ArgumentError, "payment requirement has invalid extra.#{key}" if required

          nil
        end
      end
    end
  end
end
