# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "net/http"
require "securerandom"
require "uri"

module X402
  module Interop
    module Exact
      module_function

      BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
      MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
      LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
      ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
      SYSTEM_PROGRAM = "11111111111111111111111111111111"
      TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
      DEFAULT_COMPUTE_UNIT_LIMIT = 20_000
      DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1
      MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000
      MAX_MEMO_BYTES = 256
      ED25519_P = (2**255) - 19
      ED25519_D = (-121_665 * 121_666.pow(ED25519_P - 2, ED25519_P)) % ED25519_P
      ED25519_I = 2.pow((ED25519_P - 1) / 4, ED25519_P)
      ED25519_L = (2**252) + 277_423_177_773_723_535_358_519_377_908_836_484_93
      ED25519_BASE_X = 151_122_213_495_354_007_725_011_514_095_885_315_114_540_126_930_418_572_060_461_132_839_498_477_622_02
      ED25519_BASE_Y = 463_168_356_949_264_781_694_283_940_034_751_631_413_079_938_662_562_256_157_830_336_031_652_518_559_60
      PROGRAM_DERIVED_ADDRESS_MARKER = "ProgramDerivedAddress"

      class Ed25519PrivateKey
        def initialize(seed)
          @seed = seed
          @public_key = X402::Interop::Exact.public_key_from_seed(seed)
        end

        def raw_public_key
          @public_key
        end

        def sign(_digest, message)
          X402::Interop::Exact.sign_ed25519(@seed, @public_key, message)
        end
      end

      def build_exact_payment_signature_from_rpc(requirement:, client_secret_key:, rpc_url:, resource: nil)
        blockhash = string_extra(requirement, "recentBlockhash", required: false)
        blockhash = latest_blockhash(rpc_url) if blockhash.nil? || blockhash.empty?

        build_exact_payment_signature(
          requirement: requirement,
          client_secret_key: client_secret_key,
          recent_blockhash: blockhash,
          resource: resource
        )
      end

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
          payload: { transaction: Base64.strict_encode64(transaction) }
        }
        envelope[:resource] = resource if resource.is_a?(Hash)

        Base64.strict_encode64(JSON.generate(envelope))
      end

      def public_key_base58(client_secret_key)
        base58_encode(private_key_from_json(client_secret_key).raw_public_key)
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

      def latest_blockhash(rpc_url)
        uri = URI(rpc_url)
        request = Net::HTTP::Post.new(uri)
        request["content-type"] = "application/json"
        request.body = JSON.generate(jsonrpc: "2.0", id: 1, method: "getLatestBlockhash")
        response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") do |http|
          http.request(request)
        end
        raise "getLatestBlockhash HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        payload = JSON.parse(response.body)
        raise "getLatestBlockhash RPC error: #{payload["error"]}" if payload["error"]

        payload.fetch("result").fetch("value").fetch("blockhash")
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
          { program_index: program_index, accounts: accounts, data: data }
        end

        read_short_vec(message, offset) if offset < message.bytesize
        { account_keys: account_keys, instructions: instructions }
      end

      def verify_exact_instructions!(account_keys:, instructions:, requirement:, managed_signers:)
        unless (3..6).cover?(instructions.length)
          raise "invalid_exact_svm_payload_transaction_instructions_length"
        end

        verify_compute_limit_instruction!(instructions.fetch(0), account_keys)
        verify_compute_price_instruction!(instructions.fetch(1), account_keys)
        transfer = verify_transfer_instruction!(instructions.fetch(2), account_keys, requirement, managed_signers)
        verify_fee_payer_not_in_instruction_accounts!(instructions, account_keys, managed_signers)

        destination_create_ata = false
        invalid_reason_by_index = [
          "invalid_exact_svm_payload_unknown_fourth_instruction",
          "invalid_exact_svm_payload_unknown_fifth_instruction",
          "invalid_exact_svm_payload_unknown_sixth_instruction"
        ]
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

      def verify_fee_payer_not_in_instruction_accounts!(instructions, account_keys, managed_signers)
        instructions.each do |instruction|
          instruction.fetch(:accounts).each do |index|
            if managed_signers.include?(account_key_for_index(index, account_keys))
              raise "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts"
            end
          end
        end
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

      def associated_token_address(wallet, token_program, mint)
        program_id = base58_decode(ASSOCIATED_TOKEN_PROGRAM)
        find_program_address([wallet, token_program, mint], program_id)
      end

      def find_program_address(seeds, program_id)
        255.downto(0) do |bump|
          candidate = Digest::SHA256.digest(seeds.join + [bump].pack("C") + program_id + PROGRAM_DERIVED_ADDRESS_MARKER)
          return candidate unless ed25519_on_curve?(candidate)
        end

        raise "unable to find a viable program address"
      end

      def ed25519_on_curve?(bytes)
        return false unless bytes.bytesize == 32

        sign = bytes.bytes.last >> 7
        y_bytes = bytes.bytes
        y_bytes[-1] &= 0x7f
        y = y_bytes.reverse.reduce(0) { |acc, byte| (acc << 8) | byte }
        return false if y >= ED25519_P

        y2 = (y * y) % ED25519_P
        numerator = (y2 - 1) % ED25519_P
        denominator = ((ED25519_D * y2) + 1) % ED25519_P
        return false if denominator.zero?

        x2 = (numerator * mod_inverse(denominator, ED25519_P)) % ED25519_P
        x = mod_sqrt(x2, ED25519_P)
        return false if x.nil?

        x = ED25519_P - x if (x & 1) != sign
        ((x * x - x2) % ED25519_P).zero?
      end

      def public_key_from_seed(seed)
        encoded_prefix = Digest::SHA512.digest(seed)
        scalar = prune_scalar(encoded_prefix.byteslice(0, 32))
        encode_point(scalar_mult(scalar, [ED25519_BASE_X, ED25519_BASE_Y]))
      end

      def sign_ed25519(seed, public_key, message)
        expanded = Digest::SHA512.digest(seed)
        scalar = prune_scalar(expanded.byteslice(0, 32))
        prefix = expanded.byteslice(32, 32)
        r = bytes_to_int_le(Digest::SHA512.digest(prefix + message)) % ED25519_L
        encoded_r = encode_point(scalar_mult(r, [ED25519_BASE_X, ED25519_BASE_Y]))
        k = bytes_to_int_le(Digest::SHA512.digest(encoded_r + public_key + message)) % ED25519_L
        s = (r + (k * scalar)) % ED25519_L
        encoded_r + int_to_32_le(s)
      end

      # Verify an Ed25519 signature against a message and public key.
      # Returns true if the signature is valid, false otherwise.
      def verify_ed25519(public_key, message, signature)
        return false unless signature.is_a?(String) && signature.bytesize == 64
        return false unless public_key.is_a?(String) && public_key.bytesize == 32

        encoded_r = signature.byteslice(0, 32)
        s = bytes_to_int_le(signature.byteslice(32, 32))
        return false if s >= ED25519_L

        big_a = decode_point(public_key)
        return false if big_a.nil?
        big_r = decode_point(encoded_r)
        return false if big_r.nil?

        k = bytes_to_int_le(Digest::SHA512.digest(encoded_r + public_key + message)) % ED25519_L
        left = scalar_mult(s, [ED25519_BASE_X, ED25519_BASE_Y])
        right = point_add(big_r, scalar_mult(k, big_a))
        left == right
      end

      def decode_point(bytes)
        return nil unless bytes.bytesize == 32

        y_bytes = bytes.bytes
        sign = y_bytes[-1] >> 7
        y_bytes[-1] &= 0x7f
        y = y_bytes.reverse.reduce(0) { |acc, byte| (acc << 8) | byte }
        return nil if y >= ED25519_P

        y2 = (y * y) % ED25519_P
        numerator = (y2 - 1) % ED25519_P
        denominator = ((ED25519_D * y2) + 1) % ED25519_P
        return nil if denominator.zero?

        x2 = (numerator * mod_inverse(denominator, ED25519_P)) % ED25519_P
        x = mod_sqrt(x2, ED25519_P)
        return nil if x.nil?

        x = ED25519_P - x if (x & 1) != sign
        return nil unless ((x * x - x2) % ED25519_P).zero?

        [x, y]
      end

      def prune_scalar(bytes)
        scalar_bytes = bytes.bytes
        scalar_bytes[0] &= 248
        scalar_bytes[31] &= 63
        scalar_bytes[31] |= 64
        bytes_to_int_le(scalar_bytes.pack("C*"))
      end

      def scalar_mult(scalar, point)
        result = [0, 1]
        addend = point
        value = scalar
        while value.positive?
          result = point_add(result, addend) if value.odd?
          addend = point_add(addend, addend)
          value >>= 1
        end
        result
      end

      def point_add(first, second)
        x1, y1 = first
        x2, y2 = second
        common = (ED25519_D * x1 * x2 * y1 * y2) % ED25519_P
        x3 = ((x1 * y2 + x2 * y1) * mod_inverse((1 + common) % ED25519_P, ED25519_P)) % ED25519_P
        y3 = ((y1 * y2 + x1 * x2) * mod_inverse((1 - common) % ED25519_P, ED25519_P)) % ED25519_P
        [x3, y3]
      end

      def encode_point(point)
        x, y = point
        bytes = int_to_32_le(y).bytes
        bytes[31] |= 0x80 if x.odd?
        bytes.pack("C*")
      end

      def bytes_to_int_le(bytes)
        bytes.bytes.each_with_index.reduce(0) do |acc, (byte, index)|
          acc + (byte << (8 * index))
        end
      end

      def int_to_32_le(value)
        Array.new(32) { |index| (value >> (8 * index)) & 0xff }.pack("C*")
      end

      def mod_sqrt(value, modulus)
        return 0 if value.zero?

        x = mod_pow(value, (modulus + 3) / 8, modulus)
        x = (x * ED25519_I) % modulus unless ((x * x - value) % modulus).zero?
        return nil unless ((x * x - value) % modulus).zero?

        x
      end

      def base58_decode(value)
        number = 0
        value.each_char do |char|
          index = BASE58_ALPHABET.index(char)
          raise ArgumentError, "invalid base58 character #{char.inspect}" if index.nil?

          number = (number * 58) + index
        end

        bytes = []
        while number.positive?
          bytes.unshift(number & 0xff)
          number >>= 8
        end
        leading_zeroes = value.each_char.take_while { |char| char == "1" }.length
        ("\x00".b * leading_zeroes) + bytes.pack("C*")
      end

      def base58_encode(bytes)
        number = bytes.bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
        encoded = +""
        while number.positive?
          number, remainder = number.divmod(58)
          encoded.prepend(BASE58_ALPHABET[remainder])
        end
        leading_zeroes = bytes.bytes.take_while(&:zero?).length
        ("1" * leading_zeroes) + (encoded.empty? ? "" : encoded)
      end

      def short_vec(length)
        value = length
        output = "".b
        loop do
          byte = value & 0x7f
          value >>= 7
          byte |= 0x80 if value.positive?
          output << [byte].pack("C")
          break unless value.positive?
        end
        output
      end

      def read_short_vec(bytes, offset)
        shift = 0
        value = 0
        index = offset
        loop do
          raise ArgumentError, "short vec extends beyond input" if index >= bytes.bytesize

          byte = bytes.getbyte(index)
          value |= (byte & 0x7f) << shift
          index += 1
          break if (byte & 0x80).zero?

          shift += 7
          raise ArgumentError, "short vec is too long" if shift > 28
        end

        [value, index]
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

      def mod_inverse(value, modulus)
        mod_pow(value, modulus - 2, modulus)
      end

      def mod_pow(base, exponent, modulus)
        base.pow(exponent, modulus)
      end
    end
  end
end
