# frozen_string_literal: true

require "pay_core/error_codes"
require "pay_core/solana/base58"
require "pay_core/solana/mints"
require "pay_core/solana/ata"
require "pay_core/solana/transaction"

module PayKit::Protocols::Mpp
  module Protocol
    module Solana
      # Verifies Solana charge transactions before settlement.
      class Verifier
        MAX_COMPUTE_UNIT_LIMIT = 200_000
        MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000

        # Verify a credential payload against a charge challenge.
        def verify(credential, challenge, expected_request: nil)
          if credential.payload["transaction"].is_a?(String) && !credential.payload["transaction"].empty?
            request = expected_request || Intents::ChargeRequest.from_h(challenge.decode_request)
            return verify_transaction_payload(credential.payload["transaction"], request)
          end

          signature = credential.payload["signature"]
          return VerificationResult.failure("missing transaction or signature payload", code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID) unless signature.is_a?(String) && !signature.empty?

          # B34: reject push-mode (type=signature) credentials when the
          # challenge requires a server-side fee payer. A signature-only
          # credential references an already-landed transaction that the
          # client paid the fee for, defeating the server-funded charge.
          # Reject before any RPC call so a partially-validated push
          # credential never touches the network. Mirrors Rust spine and
          # PHP #100 / Python #106.
          request_for_b34 = expected_request || Intents::ChargeRequest.from_h(challenge.decode_request)
          details = request_for_b34.method_details || {}
          if details["feePayer"] == true
            return VerificationResult.failure(
              "Push-mode credentials are not allowed when the route uses a server-side fee payer",
              code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH
            )
          end

          validate_signature(signature)
          VerificationResult.success(reference: signature)
        rescue ArgumentError, Error => error
          code = error.respond_to?(:code) ? error.code : nil
          VerificationResult.failure(error.message, code: code)
        end

        # Verify a standard-base64 transaction payload against a request.
        def verify_transaction_payload(transaction_base64, request)
          transaction = ::PayCore::Solana::Transaction.from_base64(transaction_base64)
          verify_transaction(transaction, request)
          VerificationResult.success(reference: "")
        rescue ArgumentError, Error => error
          VerificationResult.failure(error.message)
        end

        # Fail unless `signature` is a Solana base58 signature.
        def validate_signature(signature)
          raise ArgumentError, "invalid signature length" unless signature.length.between?(87, 88)

          decoded = ::PayCore::Solana::Base58.decode(signature)
          raise ArgumentError, "invalid signature length" unless decoded.bytesize == 64
        end

        # Verify parsed transaction instructions and amounts.
        def verify_transaction(transaction, request)
          raise VerificationError, "v0 address lookup tables are not supported" unless transaction.message.address_table_lookups.empty?

          details = request.method_details || {}
          splits = Array(details["splits"])
          raise VerificationError, "too many splits" if splits.length > 8

          total = request.amount_i
          split_total = splits.sum { |split| amount_from(split, "split.amount") }
          primary = total - split_total
          raise VerificationError, "split amounts exceed total amount" if primary <= 0
          raise VerificationError, "recipient is required" if request.recipient.to_s.empty?

          fee_payer = expected_fee_payer(transaction, details)
          matched = {}
          if request.currency.casecmp("SOL").zero?
            raise VerificationError, "ataCreationRequired requires an SPL token charge" if splits.any? { |split| split["ataCreationRequired"] == true }

            match_sol_transfer(transaction, request.recipient, primary, fee_payer, matched)
            splits.each { |split| match_sol_transfer(transaction, split.fetch("recipient"), amount_from(split, "split.amount"), fee_payer, matched) }
            verify_memos(transaction, request, splits, matched)
            validate_allowlist(transaction, matched, expected_mint: nil, expected_token_program: nil, fee_payer: fee_payer, splits: splits)
          else
            network = details["network"] || "mainnet"
            mint = ::PayCore::Solana::Mints.resolve(request.currency, network)
            token_program = details["tokenProgram"] || ::PayCore::Solana::Mints.token_program_for(request.currency, network)
            if splits.any? { |split| split["ataCreationRequired"] == true } && mint != request.currency
              raise VerificationError, "ataCreationRequired requires currency to be an SPL token mint address"
            end
            match_spl_transfer(transaction, request.recipient, mint, token_program, primary, details["decimals"], fee_payer, matched)
            splits.each { |split| match_spl_transfer(transaction, split.fetch("recipient"), mint, token_program, amount_from(split, "split.amount"), details["decimals"], fee_payer, matched) }
            verify_memos(transaction, request, splits, matched)
            validate_allowlist(transaction, matched, expected_mint: mint, expected_token_program: token_program, fee_payer: fee_payer, splits: splits)
          end
        end

        private

        def expected_fee_payer(transaction, details)
          return nil unless details["feePayer"] == true

          key = details["feePayerKey"]
          raise VerificationError, "feePayer=true requires feePayerKey" if key.to_s.empty?
          raise VerificationError, "transaction fee payer mismatch" unless transaction.message.account_keys.first == key

          key
        end

        def amount_from(split, label)
          value = Integer(split.fetch("amount"), 10)
          # Split amounts are base-unit u64 on the Rust spine; reject
          # overflow here so it surfaces as an explicit invalid-amount error
          # rather than a downstream "No matching transfer" failure. Mirrors
          # `Intents::ChargeRequest::U64_MAX`.
          raise VerificationError, "#{label} exceeds the maximum u64 amount" if value > Intents::ChargeRequest::U64_MAX

          value
        rescue KeyError, ArgumentError
          raise VerificationError, "#{label} must be an integer string"
        end

        def match_sol_transfer(transaction, recipient, amount, fee_payer, matched)
          found = false
          transaction.message.instructions.each_with_index do |ix, index|
            next if matched[index]
            next unless program_id(transaction, ix) == ::PayCore::Solana::Mints::SYSTEM_PROGRAM
            next unless ix.data.bytesize >= 12
            next unless u32_le(ix.data.byteslice(0, 4)) == 2
            next unless u64_le(ix.data.byteslice(4, 8)) == amount

            source = account_key(transaction, ix.accounts[0], "source")
            destination = account_key(transaction, ix.accounts[1], "destination")
            next unless destination == recipient
            raise VerificationError, "fee payer cannot fund the SOL payment transfer" if fee_payer && source == fee_payer

            matched[index] = true
            found = true
            break
          end
          return if found

          raise VerificationError, "No matching SOL transfer of #{amount} lamports to #{recipient}"
        end

        def match_spl_transfer(transaction, recipient, mint, token_program, amount, decimals, fee_payer, matched)
          found = false
          transaction.message.instructions.each_with_index do |ix, index|
            next if matched[index]

            instruction_program = program_id(transaction, ix)
            next unless [::PayCore::Solana::Mints::TOKEN_PROGRAM, ::PayCore::Solana::Mints::TOKEN_2022_PROGRAM].include?(instruction_program)
            next unless instruction_program == token_program
            next unless ix.data.bytesize >= 10 && ix.data.getbyte(0) == 12
            next unless u64_le(ix.data.byteslice(1, 8)) == amount
            next if !decimals.nil? && ix.data.getbyte(9) != Integer(decimals)
            next unless account_key(transaction, ix.accounts[1], "mint") == mint

            source_ata = account_key(transaction, ix.accounts[0], "source")
            destination_ata = account_key(transaction, ix.accounts[2], "destination")
            authority = account_key(transaction, ix.accounts[3], "authority")
            if fee_payer
              raise VerificationError, "fee payer cannot authorize the SPL payment transfer" if authority == fee_payer
              fee_payer_ata = ::PayCore::Solana::ATA.derive(owner: fee_payer, mint: mint, token_program: token_program)
              raise VerificationError, "fee payer token account cannot fund the SPL payment transfer" if source_ata == fee_payer_ata
            end
            expected_ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: token_program)
            next unless destination_ata == expected_ata

            matched[index] = true
            found = true
            break
          end
          return if found

          raise VerificationError, "No matching SPL transferChecked of #{amount} to #{recipient}"
        end

        def verify_memos(transaction, request, splits, matched)
          memos = []
          memos << ["externalId", request.external_id] if request.external_id
          splits.each { |split| memos << ["split", split["memo"]] if split["memo"] }
          memos.each do |label, memo|
            raise VerificationError, "memo cannot exceed 566 bytes" if memo.bytesize > 566

            found = transaction.message.instructions.each_with_index.any? do |ix, index|
              next false if matched[index]
              next false unless program_id(transaction, ix) == ::PayCore::Solana::Mints::MEMO_PROGRAM
              next false unless ix.data.b == memo.b

              matched[index] = true
              true
            end
            raise VerificationError, "No memo instruction found for #{label} memo \"#{memo}\"" unless found
          end
        end

        def validate_allowlist(transaction, matched, expected_mint:, expected_token_program:, fee_payer:, splits:)
          created_owners = {}
          required_owners = splits.select { |split| split["ataCreationRequired"] == true }.map { |split| split.fetch("recipient") }
          allowed_owners = fee_payer ? required_owners : splits.map { |split| split.fetch("recipient") }
          expected_ata_payer = fee_payer || transaction.message.account_keys.first

          transaction.message.instructions.each_with_index do |ix, index|
            program = program_id(transaction, ix)
            if program == ::PayCore::Solana::Mints::COMPUTE_BUDGET_PROGRAM
              validate_compute_budget(ix)
            elsif [::PayCore::Solana::Mints::MEMO_PROGRAM, ::PayCore::Solana::Mints::SYSTEM_PROGRAM, ::PayCore::Solana::Mints::TOKEN_PROGRAM, ::PayCore::Solana::Mints::TOKEN_2022_PROGRAM].include?(program)
              raise VerificationError, "Unexpected program instruction in payment transaction: #{program}" unless matched[index]
            elsif program == ::PayCore::Solana::Mints::ASSOCIATED_TOKEN_PROGRAM
              owner = validate_ata_create(transaction, ix, expected_mint, allowed_owners, expected_token_program, expected_ata_payer)
              created_owners[owner] = true
            else
              raise VerificationError, "Unexpected program instruction in payment transaction: #{program}"
            end
          end
          required_owners.each do |owner|
            raise VerificationError, "Missing required ATA creation instruction for split recipient #{owner}" unless created_owners[owner]
          end
        end

        def validate_ata_create(transaction, ix, expected_mint, allowed_owners, expected_token_program, expected_payer)
          raise VerificationError, "ATA creation is not allowed for native SOL payments" if expected_mint.nil?
          raise VerificationError, "Only idempotent ATA creation is allowed" unless ix.data == "\x01".b
          raise VerificationError, "Unexpected ATA creation account layout" unless ix.accounts.length == 6

          payer = account_key(transaction, ix.accounts[0], "ATA payer")
          ata = account_key(transaction, ix.accounts[1], "ATA address")
          owner = account_key(transaction, ix.accounts[2], "ATA owner")
          mint = account_key(transaction, ix.accounts[3], "ATA mint")
          system_program = account_key(transaction, ix.accounts[4], "ATA system program")
          token_program = account_key(transaction, ix.accounts[5], "ATA token program")
          raise VerificationError, "ATA payer must match the transaction fee payer" unless payer == expected_payer
          raise VerificationError, "ATA creation mint does not match the charge currency" unless mint == expected_mint
          raise VerificationError, "ATA creation owner is not authorized by the challenge" unless allowed_owners.include?(owner)
          raise VerificationError, "ATA creation must reference the System Program" unless system_program == ::PayCore::Solana::Mints::SYSTEM_PROGRAM
          raise VerificationError, "ATA creation uses an unsupported token program" unless [::PayCore::Solana::Mints::TOKEN_PROGRAM, ::PayCore::Solana::Mints::TOKEN_2022_PROGRAM].include?(token_program)
          raise VerificationError, "ATA creation token program does not match methodDetails.tokenProgram" if expected_token_program && token_program != expected_token_program

          expected_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: token_program)
          raise VerificationError, "ATA creation address does not match owner/mint/token program" unless ata == expected_ata

          owner
        end

        def validate_compute_budget(ix)
          raise VerificationError, "Compute budget instruction must not have accounts" unless ix.accounts.empty?

          case ix.data.getbyte(0)
          when 2
            raise VerificationError, "Unsupported compute budget instruction" unless ix.data.bytesize == 5
            units = u32_le(ix.data.byteslice(1, 4))
            raise VerificationError, "Compute unit limit #{units} exceeds maximum #{MAX_COMPUTE_UNIT_LIMIT}" if units > MAX_COMPUTE_UNIT_LIMIT
          when 3
            raise VerificationError, "Unsupported compute budget instruction" unless ix.data.bytesize == 9
            price = u64_le(ix.data.byteslice(1, 8))
            raise VerificationError, "Compute unit price #{price} exceeds maximum #{MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS}" if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
          else
            raise VerificationError, "Unsupported compute budget instruction"
          end
        end

        def program_id(transaction, ix)
          account_key(transaction, ix.program_id_index, "program_id")
        end

        def account_key(transaction, index, label)
          transaction.message.account_keys.fetch(index)
        rescue IndexError, TypeError
          raise VerificationError, "Invalid #{label} index"
        end

        def u32_le(bytes)
          bytes.unpack1("L<")
        end

        def u64_le(bytes)
          bytes.unpack1("Q<")
        end
      end
    end
  end
end
