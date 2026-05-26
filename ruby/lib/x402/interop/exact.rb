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

module X402
  module Interop
    # x402 exact-scheme primitives. Protocol-specific structural validation
    # lives here; cryptography, Base58, ATA derivation, RPC, program IDs,
    # and short_vec live in the shared `PayCore::Solana::*` layer and are
    # reused via the local aliases below.
    module Exact
      module_function

      # Shared core aliases. All Solana primitives come from the
      # gem-level `PayCore::Solana` layer so that x402 does not redeclare
      # or reimplement constants, Base58, ATA, PDA, RPC, or short_vec
      # helpers. Mirrors the Rust spine
      # `rust/crates/x402/src/protocol/schemes/exact/types.rs` which
      # likewise consumes `solana-pay-core` rather than redefining
      # program IDs in the x402 crate.
      Base58 = ::PayCore::Solana::Base58
      Mints = ::PayCore::Solana::Mints
      Programs = ::PayCore::Solana::Programs
      PublicKey = ::PayCore::Solana::PublicKey
      ATA = ::PayCore::Solana::ATA
      Rpc = ::PayCore::Solana::Rpc
      TransactionCodec = ::PayCore::Solana::Transaction

      # Program IDs sourced from the shared Programs table.
      COMPUTE_BUDGET_PROGRAM = Programs::COMPUTE_BUDGET_PROGRAM
      MEMO_PROGRAM = Programs::MEMO_PROGRAM
      ASSOCIATED_TOKEN_PROGRAM = Programs::ASSOCIATED_TOKEN_PROGRAM
      SYSTEM_PROGRAM = Programs::SYSTEM_PROGRAM
      TOKEN_2022_PROGRAM = Programs::TOKEN_2022_PROGRAM
      LIGHTHOUSE_PROGRAM = Programs::LIGHTHOUSE_PROGRAM

      DEFAULT_COMPUTE_UNIT_LIMIT = 20_000
      DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1
      MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000
      MAX_MEMO_BYTES = 256

      # Thin Ed25519 signer adapter: builds an `Ed25519::SigningKey` from a
      # 32-byte Solana seed and exposes the raw public key plus a `sign`
      # method whose shape matches the spine ed25519 signer interface
      # (sign raw message bytes, no pre-hashing).
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

      # Build a client-signed x402 payment envelope. Used by the server
      # interop tests to construct fixture payloads; production client
      # signing happens in the TS/Rust/Go/Python adapters, not Ruby.
      def build_exact_payment_signature(requirement:, client_secret_key:, recent_blockhash:, resource: nil)
        raise ArgumentError, "only exact payment requirements can be signed" unless requirement["scheme"] == "exact"

        private_key = private_key_from_json(client_secret_key)
        transaction = build_transaction(
          requirement: requirement,
          private_key: private_key,
          recent_blockhash: recent_blockhash
        )
        envelope = {
          x402Version: 2,
          accepted: requirement,
          payload: {transaction: Base64.strict_encode64(transaction)}
        }
        envelope[:resource] = resource if resource.is_a?(Hash)

        Base64.strict_encode64(JSON.generate(envelope))
      end

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

      def verify_exact_transaction!(transaction:, requirement:, managed_signers:)
        parsed = parse_versioned_transaction(transaction)
        verify_exact_instructions!(
          account_keys: parsed.fetch(:account_keys),
          instructions: parsed.fetch(:instructions),
          requirement: requirement,
          managed_signers: managed_signers
        )
      end

      # Verify all non-managed client signatures on a versioned transaction
      # against the message bytes. Mirrors the Rust spine ordering in
      # `rust/src/bin/interop_server.rs:316-324`, where `process_payment`
      # validates the envelope BEFORE `sign_fee_payer` is called. We must
      # never apply the facilitator signature to a transaction whose
      # client-provided signatures are forged or missing, otherwise the
      # partially-signed envelope leaks back to the attacker.
      def verify_client_signatures!(transaction, managed_signers)
        bytes = transaction.b
        signature_count, signatures_offset = read_short_vec(bytes, 0)
        message_offset = signatures_offset + (signature_count * 64)
        raise "invalid_exact_svm_payload_signature" if message_offset >= bytes.bytesize

        message = bytes.byteslice(message_offset, bytes.bytesize - message_offset)
        raise "invalid_exact_svm_payload_signature" unless message.getbyte(0) == 0x80

        required_signatures = message.getbyte(1)
        raise "invalid_exact_svm_payload_signature" if required_signatures > signature_count
        account_count, account_offset = read_short_vec(message, 4)
        raise "invalid_exact_svm_payload_signature" if required_signatures > account_count

        zero_signature = "\x00".b * 64
        required_signatures.times do |index|
          signer_key_start = account_offset + (index * 32)
          raise "invalid_exact_svm_payload_signature" if signer_key_start + 32 > message.bytesize

          signer_key = message.byteslice(signer_key_start, 32)
          # Facilitator-managed signers sign in a later step. Skip here; an
          # empty placeholder is expected at envelope-decode time.
          next if managed_signers.include?(signer_key)

          signature = bytes.byteslice(signatures_offset + (index * 64), 64)
          raise "invalid_exact_svm_payload_signature" if signature == zero_signature
          raise "invalid_exact_svm_payload_signature" unless verify_ed25519(signer_key, message, signature)
        end
      end

      def accepted_requirement_matches?(left, right)
        left == right
      end

      def build_transaction(requirement:, private_key:, recent_blockhash:)
        signer = private_key.raw_public_key
        fee_payer = base58_decode(string_extra(requirement, "feePayer"))
        mint = base58_decode(requirement.fetch("asset"))
        pay_to = base58_decode(requirement.fetch("payTo"))
        token_program = base58_decode(string_extra(requirement, "tokenProgram"))
        blockhash = base58_decode(recent_blockhash)
        decimals = integer_extra(requirement, "decimals")
        amount = Integer(requirement.fetch("amount"), 10)
        source_ata = associated_token_address(signer, token_program, mint)
        destination_ata = associated_token_address(pay_to, token_program, mint)
        compute_budget_program = base58_decode(COMPUTE_BUDGET_PROGRAM)
        memo_program = base58_decode(MEMO_PROGRAM)

        account_keys = [
          fee_payer,
          signer,
          source_ata,
          destination_ata,
          compute_budget_program,
          token_program,
          mint,
          memo_program
        ]

        instructions = [
          compiled_instruction(4, [], [2].pack("C") + [DEFAULT_COMPUTE_UNIT_LIMIT].pack("V")),
          compiled_instruction(4, [], [3].pack("C") + [DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS].pack("Q<")),
          compiled_instruction(5, [2, 6, 3, 1], [12].pack("C") + [amount].pack("Q<") + [decimals].pack("C")),
          compiled_instruction(7, [], memo_bytes(requirement))
        ]

        message = [
          [0x80, 2, 1, 4].pack("C*"),
          short_vec(account_keys.length),
          account_keys.join,
          blockhash,
          short_vec(instructions.length),
          instructions.join,
          short_vec(0)
        ].join
        signature = private_key.sign(nil, message)

        [
          short_vec(2),
          ("\x00".b * 64),
          signature,
          message
        ].join
      end

      def compiled_instruction(program_index, account_indexes, data)
        [
          [program_index].pack("C"),
          short_vec(account_indexes.length),
          account_indexes.pack("C*"),
          short_vec(data.bytesize),
          data
        ].join
      end

      def memo_bytes(requirement)
        memo = string_extra(requirement, "memo", required: false)
        memo = SecureRandom.hex(16) if memo.nil? || memo.empty?
        bytes = memo.b
        raise ArgumentError, "extra.memo exceeds maximum #{MAX_MEMO_BYTES} bytes" if bytes.bytesize > MAX_MEMO_BYTES

        bytes
      end

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

      def verify_exact_instructions!(account_keys:, instructions:, requirement:, managed_signers:)
        unless (3..6).cover?(instructions.length)
          raise "invalid_exact_svm_payload_transaction_instructions_length"
        end

        verify_compute_limit_instruction!(instructions.fetch(0), account_keys)
        verify_compute_price_instruction!(instructions.fetch(1), account_keys)
        transfer = verify_transfer_instruction!(instructions.fetch(2), account_keys, requirement, managed_signers)
        reject_fee_payer_in_instruction_accounts!(instructions, account_keys, managed_signers)

        destination_create_ata = false
        invalid_reason_by_index = [
          "invalid_exact_svm_payload_unknown_fourth_instruction",
          "invalid_exact_svm_payload_unknown_fifth_instruction",
          "invalid_exact_svm_payload_unknown_sixth_instruction"
        ]
        # INTENTIONAL_DIVERGENCE from spine: the Rust spine
        # (`rust/src/protocol/schemes/exact/verify.rs:266`) and the TypeScript
        # spine (`typescript/packages/x402/src/facilitator/exact/scheme.ts:300`)
        # permit only Memo + Lighthouse in slots 3-5. This port additionally
        # allows `AssociatedTokenAccount::Create` / `CreateIdempotent` in slots
        # 3-4 so a buyer can fund their own destination ATA in-band; the shape
        # of that exception is structurally validated by
        # `valid_destination_ata_create_instruction?` and paired with the
        # ATA-create-payer-slot carve-out in
        # `reject_fee_payer_in_instruction_accounts!`. Matches the Go and Lua
        # ports; tightening to spine parity is a protocol-wide decision that
        # must land in the Rust spine first, tracked at
        # `notes/lighthouse-allowlist-tracking.md`.
        instructions.drop(3).each_with_index do |instruction, index|
          program = instruction_program(instruction, account_keys)
          allowed_programs = if index == 2
            [base58_decode(MEMO_PROGRAM)]
          else
            [base58_decode(LIGHTHOUSE_PROGRAM), base58_decode(MEMO_PROGRAM)]
          end
          if index < 2 && program == base58_decode(ASSOCIATED_TOKEN_PROGRAM) &&
              valid_destination_ata_create_instruction?(instruction, account_keys, requirement, transfer)
            destination_create_ata = true
            next
          end
          next if allowed_programs.include?(program)

          raise invalid_reason_by_index.fetch(index, "invalid_exact_svm_payload_unknown_optional_instruction")
        end

        expected_memo = string_extra(requirement, "memo", required: false)
        return transfer.merge(destination_create_ata: destination_create_ata) if expected_memo.nil?

        memo_program = base58_decode(MEMO_PROGRAM)
        memo_instructions = instructions.drop(3).select do |instruction|
          instruction_program(instruction, account_keys) == memo_program
        end
        raise "invalid_exact_svm_payload_memo_count" unless memo_instructions.length == 1
        actual_memo_bytes = memo_instructions[0].fetch(:data).b
        raise "invalid_exact_svm_payload_memo_mismatch" unless actual_memo_bytes.dup.force_encoding("UTF-8").valid_encoding?
        # Compare in ASCII-8BIT (binary) to avoid silent encoding mismatch
        # between transaction bytes (binary) and JSON-decoded memo (UTF-8).
        raise "invalid_exact_svm_payload_memo_mismatch" unless actual_memo_bytes == expected_memo.b

        transfer.merge(destination_create_ata: destination_create_ata)
      end

      def verify_compute_limit_instruction!(instruction, account_keys)
        program = instruction_program(instruction, account_keys)
        data = instruction.fetch(:data)
        return if program == base58_decode(COMPUTE_BUDGET_PROGRAM) && data.bytesize == 5 && data.getbyte(0) == 2

        raise "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"
      end

      # Sweep every instruction's account list and reject any whose accounts
      # name a facilitator-managed signer (the fee payer). This closes the
      # ATA-drain vector where a malicious client appends an extra instruction
      # (TransferChecked, SystemProgram::Transfer, or any program) that
      # references the fee-payer pubkey as a signer or source. Mirrors the
      # Rust spine's `authority` check on the canonical transfer
      # (`rust/crates/x402/src/protocol/schemes/exact/verify.rs:382`) but
      # extends it to every instruction so optional or auxiliary instructions
      # cannot quietly drain managed-signer balances after the facilitator
      # co-signs.
      #
      # Carve-out: the legitimate `AssociatedTokenAccount::Create` /
      # `CreateIdempotent` instruction places the funding payer at account
      # index 0. When that payer is the fee payer (the only managed signer
      # the facilitator funds), it is the documented happy path used by
      # cross-spine clients to lazily provision the destination ATA. Allow
      # the fee payer in that exact slot; reject it anywhere else in the
      # ATA-create accounts vector and in every other instruction.
      #
      # INTENTIONAL_DIVERGENCE from spine: the Rust spine has no fee-payer-
      # in-instruction-accounts sweep at all and would reject this carve-out
      # as out-of-band hardening. The port keeps the sweep (the spine-aligned
      # `_transferring_funds` guard alone leaves the optional-slot DRAIN
      # vectors covered by `TestVerifyExactTransactionAttackRegressions` open)
      # and pairs it with the ATA-create payer-slot carve-out so the in-band
      # destination-ATA-create flow still succeeds. Matches the Go and Lua
      # ports; convergence with the spine is tracked at
      # `notes/lighthouse-allowlist-tracking.md`.
      def reject_fee_payer_in_instruction_accounts!(instructions, account_keys, managed_signers)
        ata_program = base58_decode(ASSOCIATED_TOKEN_PROGRAM)
        instructions.each do |instruction|
          accounts = instruction.fetch(:accounts)
          program = instruction_program(instruction, account_keys)
          carve_out_payer_slot =
            program == ata_program && ata_create_data?(instruction.fetch(:data))

          accounts.each_with_index do |index, position|
            next if carve_out_payer_slot && position.zero?

            if managed_signers.include?(account_key_for_index(index, account_keys))
              raise "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts"
            end
          end
        end
      end

      def ata_create_data?(data)
        # Associated Token Account program instruction discriminator:
        # - empty data           -> Create (legacy variant)
        # - single byte 0x00     -> Create
        # - single byte 0x01     -> CreateIdempotent
        # Any other shape is RecoverNested or a future variant; reject the
        # carve-out so we don't leak the fee-payer slot into unknown shapes.
        return true if data.bytesize.zero?
        return false unless data.bytesize == 1

        first = data.getbyte(0)
        first == 0 || first == 1
      end

      def verify_compute_price_instruction!(instruction, account_keys)
        program = instruction_program(instruction, account_keys)
        data = instruction.fetch(:data)
        unless program == base58_decode(COMPUTE_BUDGET_PROGRAM) && data.bytesize == 9 && data.getbyte(0) == 3
          raise "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"
        end

        micro_lamports = data.byteslice(1, 8).unpack1("Q<")
        if micro_lamports > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
          raise "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
        end
      end

      def verify_transfer_instruction!(instruction, account_keys, requirement, managed_signers)
        program = instruction_program(instruction, account_keys)
        allowed_programs = [base58_decode(string_extra(requirement, "tokenProgram")), base58_decode(TOKEN_2022_PROGRAM)]
        unless allowed_programs.include?(program)
          raise "invalid_exact_svm_payload_no_transfer_instruction"
        end

        data = instruction.fetch(:data)
        accounts = instruction.fetch(:accounts)
        unless accounts.length >= 4 && data.bytesize == 10 && data.getbyte(0) == 12
          raise "invalid_exact_svm_payload_no_transfer_instruction"
        end

        mint = account_key_for_index(accounts.fetch(1), account_keys)
        destination = account_key_for_index(accounts.fetch(2), account_keys)
        authority = account_key_for_index(accounts.fetch(3), account_keys)
        source = account_key_for_index(accounts.fetch(0), account_keys)

        if managed_signers.any? { |managed| managed == authority || managed == source }
          raise "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
        end

        if accounts.any? { |index| managed_signers.include?(account_key_for_index(index, account_keys)) }
          raise "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts"
        end

        expected_mint = base58_decode(requirement.fetch("asset"))
        raise "invalid_exact_svm_payload_mint_mismatch" unless mint == expected_mint

        expected_destination = associated_token_address(base58_decode(requirement.fetch("payTo")), program, expected_mint)
        raise "invalid_exact_svm_payload_recipient_mismatch" unless destination == expected_destination

        amount = data.byteslice(1, 8).unpack1("Q<")
        expected_amount = Integer(requirement.fetch("amount"), 10)
        raise "invalid_exact_svm_payload_amount_mismatch" unless amount == expected_amount

        {
          source: source,
          mint: mint,
          destination: destination,
          authority: authority,
          token_program: program
        }
      end

      def valid_destination_ata_create_instruction?(instruction, account_keys, requirement, transfer)
        data = instruction.fetch(:data)
        return false unless data.bytesize <= 1
        return false if data.bytesize == 1 && ![0, 1].include?(data.getbyte(0))

        accounts = instruction.fetch(:accounts)
        return false if accounts.length < 6

        associated_account = account_key_for_index(accounts.fetch(1), account_keys)
        wallet = account_key_for_index(accounts.fetch(2), account_keys)
        mint = account_key_for_index(accounts.fetch(3), account_keys)
        system_program = account_key_for_index(accounts.fetch(4), account_keys)
        token_program = account_key_for_index(accounts.fetch(5), account_keys)

        associated_account == transfer.fetch(:destination) &&
          wallet == base58_decode(requirement.fetch("payTo")) &&
          mint == transfer.fetch(:mint) &&
          system_program == base58_decode(SYSTEM_PROGRAM) &&
          token_program == transfer.fetch(:token_program)
      end

      def instruction_program(instruction, account_keys)
        account_key_for_index(instruction.fetch(:program_index), account_keys)
      end

      def account_key_for_index(index, account_keys)
        account_keys.fetch(index)
      rescue IndexError
        raise "invalid_exact_svm_payload_no_transfer_instruction"
      end

      def private_key_from_json(raw)
        bytes = JSON.parse(raw)
        unless bytes.is_a?(Array) && bytes.length == 64
          raise ArgumentError, "expected a 64-byte Solana secret key JSON array"
        end

        seed = bytes.first(32).pack("C*")
        Ed25519PrivateKey.new(seed)
      end

      # Derive the associated token account address as raw 32-byte pubkey.
      # Delegates to `PayCore::Solana::ATA.derive` and
      # decodes the resulting Base58 string back to the byte form x402's
      # transaction builder works in.
      def associated_token_address(wallet, token_program, mint)
        ata_base58 = ATA.derive(
          owner: wallet,
          mint: mint,
          token_program: token_program
        )
        base58_decode(ata_base58)
      end

      # Verify an Ed25519 signature against a message and public key.
      # Returns true if the signature is valid, false otherwise. Backed by
      # the `ed25519` runtime gem already pinned in `solana-pay-kit.gemspec`
      # rather than a pure-Ruby reimplementation.
      def verify_ed25519(public_key, message, signature)
        return false unless signature.is_a?(String) && signature.bytesize == 64
        return false unless public_key.is_a?(String) && public_key.bytesize == 32

        ::Ed25519::VerifyKey.new(public_key).verify(signature, message)
        true
      rescue ::Ed25519::VerifyError
        false
      end

      # Base58 helpers delegate to the shared core module.
      def base58_decode(value)
        Base58.decode(value)
      end

      def base58_encode(bytes)
        Base58.encode(bytes)
      end

      # Solana short_vec helpers delegate to the shared core module
      # (`PayCore::Solana::Transaction`), keeping a single canonical
      # implementation of compact-u16 across MPP and x402.
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
