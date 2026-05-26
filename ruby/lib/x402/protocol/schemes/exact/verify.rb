# frozen_string_literal: true

require_relative "types"

module X402
  module Protocol
    module Schemes
      module Exact
        # The 11-rule x402 SVM-exact verifier. Mirrors the Rust spine
        # `rust/crates/x402/src/protocol/schemes/exact/verify.rs` and
        # raises canonical reject tokens (e.g.
        # `invalid_exact_svm_payload_amount_mismatch`) that the
        # cross-language interop harness substring-matches against.
        #
        # Rules (mirrors spine verify.rs):
        #   1. Instruction count 3..=6                          (verify.rs:230-235)
        #   2. ix[0] = ComputeBudget SetComputeUnitLimit        (verify.rs:240-248)
        #   3. ix[1] = ComputeBudget SetComputeUnitPrice <= MAX (verify.rs:250-264)
        #   4. ix[2] = SPL TransferChecked                      (verify.rs:380-410)
        #   5. Authority guard (no fee-payer in transfer auth)  (verify.rs:382)
        #   6. Mint match                                       (verify.rs:395-400)
        #   7. Destination ATA match (re-derive)                (verify.rs:402-405)
        #   8. Amount match                                     (verify.rs:407-410)
        #   9. ix[3..6] in allowlist                            (verify.rs:266-300)
        #  10. Memo binding (exactly one if extra.memo set)     (verify.rs:283-300)
        #  11. Token program strict bind to extra.tokenProgram  (verify.rs:380-395)
        module Verifier
          module_function

          # Top-level entry. Decode the transaction bytes, then run all
          # structural rules. Returns a verified-transfer descriptor on
          # success; raises a canonical reject string on any rule fail.
          def verify(transaction, requirement, managed_signers:)
            parsed = Exact.parse_versioned_transaction(transaction)
            verify_instructions!(
              account_keys: parsed.fetch(:account_keys),
              instructions: parsed.fetch(:instructions),
              requirement: requirement,
              managed_signers: managed_signers
            )
          end

          # Verify all non-managed client signatures on a versioned
          # transaction. Mirrors the spine ordering at
          # `rust/crates/x402/src/bin/interop_server.rs:316-324`: the
          # envelope is validated BEFORE the facilitator co-signs,
          # otherwise a partially-signed envelope leaks back to a
          # malformed-envelope attacker.
          def verify_client_signatures!(transaction, managed_signers)
            bytes = transaction.b
            signature_count, signatures_offset = Exact.read_short_vec(bytes, 0)
            message_offset = signatures_offset + (signature_count * 64)
            raise "invalid_exact_svm_payload_signature" if message_offset >= bytes.bytesize

            message = bytes.byteslice(message_offset, bytes.bytesize - message_offset)
            raise "invalid_exact_svm_payload_signature" unless message.getbyte(0) == 0x80

            required_signatures = message.getbyte(1)
            raise "invalid_exact_svm_payload_signature" if required_signatures > signature_count
            account_count, account_offset = Exact.read_short_vec(message, 4)
            raise "invalid_exact_svm_payload_signature" if required_signatures > account_count

            zero_signature = "\x00".b * 64
            required_signatures.times do |index|
              signer_key_start = account_offset + (index * 32)
              raise "invalid_exact_svm_payload_signature" if signer_key_start + 32 > message.bytesize

              signer_key = message.byteslice(signer_key_start, 32)
              next if managed_signers.include?(signer_key)

              signature = bytes.byteslice(signatures_offset + (index * 64), 64)
              raise "invalid_exact_svm_payload_signature" if signature == zero_signature
              raise "invalid_exact_svm_payload_signature" unless Exact.verify_ed25519(signer_key, message, signature)
            end
          end

          # ---- Structural rule sweep ------------------------------------
          def verify_instructions!(account_keys:, instructions:, requirement:, managed_signers:)
            # Rule 1: instruction count 3..=6 (spine verify.rs:230-235).
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
            # (`rust/crates/x402/src/protocol/schemes/exact/verify.rs:266`) and
            # the TS spine (`typescript/packages/x402/src/facilitator/exact/scheme.ts:300`)
            # permit only Memo + Lighthouse in slots 3-5. This port additionally
            # allows `AssociatedTokenAccount::Create` / `CreateIdempotent` in slots
            # 3-4 so a buyer can fund their own destination ATA in-band; the shape
            # of that exception is structurally validated by
            # `valid_destination_ata_create_instruction?` and paired with the
            # ATA-create-payer-slot carve-out in
            # `reject_fee_payer_in_instruction_accounts!`. Matches the Go and Lua
            # ports.
            instructions.drop(3).each_with_index do |instruction, index|
              program = instruction_program(instruction, account_keys)
              allowed_programs = if index == 2
                [Exact.base58_decode(Exact::MEMO_PROGRAM)]
              else
                [Exact.base58_decode(Exact::LIGHTHOUSE_PROGRAM), Exact.base58_decode(Exact::MEMO_PROGRAM)]
              end
              if index < 2 && program == Exact.base58_decode(Exact::ASSOCIATED_TOKEN_PROGRAM) &&
                  valid_destination_ata_create_instruction?(instruction, account_keys, requirement, transfer)
                destination_create_ata = true
                next
              end
              next if allowed_programs.include?(program)

              raise invalid_reason_by_index.fetch(index, "invalid_exact_svm_payload_unknown_optional_instruction")
            end

            # Rule 10: memo binding (spine verify.rs:283-300).
            expected_memo = Exact.string_extra(requirement, "memo", required: false)
            return transfer.merge(destination_create_ata: destination_create_ata) if expected_memo.nil?

            memo_program = Exact.base58_decode(Exact::MEMO_PROGRAM)
            memo_instructions = instructions.drop(3).select do |instruction|
              instruction_program(instruction, account_keys) == memo_program
            end
            raise "invalid_exact_svm_payload_memo_count" unless memo_instructions.length == 1
            actual_memo_bytes = memo_instructions[0].fetch(:data).b
            raise "invalid_exact_svm_payload_memo_mismatch" unless actual_memo_bytes.dup.force_encoding("UTF-8").valid_encoding?
            raise "invalid_exact_svm_payload_memo_mismatch" unless actual_memo_bytes == expected_memo.b

            transfer.merge(destination_create_ata: destination_create_ata)
          end

          # Rule 2: ComputeBudget SetComputeUnitLimit (spine verify.rs:240-248).
          def verify_compute_limit_instruction!(instruction, account_keys)
            program = instruction_program(instruction, account_keys)
            data = instruction.fetch(:data)
            return if program == Exact.base58_decode(Exact::COMPUTE_BUDGET_PROGRAM) && data.bytesize == 5 && data.getbyte(0) == 2

            raise "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"
          end

          # Rule 3: ComputeBudget SetComputeUnitPrice <= MAX (spine verify.rs:250-264).
          def verify_compute_price_instruction!(instruction, account_keys)
            program = instruction_program(instruction, account_keys)
            data = instruction.fetch(:data)
            unless program == Exact.base58_decode(Exact::COMPUTE_BUDGET_PROGRAM) && data.bytesize == 9 && data.getbyte(0) == 3
              raise "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"
            end

            micro_lamports = data.byteslice(1, 8).unpack1("Q<")
            if micro_lamports > Exact::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS
              raise "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"
            end
          end

          # Rules 4, 6, 7, 8, 11: TransferChecked shape + binding
          # (spine verify.rs:380-410).
          def verify_transfer_instruction!(instruction, account_keys, requirement, managed_signers)
            program = instruction_program(instruction, account_keys)
            allowed_programs = [Exact.base58_decode(Exact.string_extra(requirement, "tokenProgram")), Exact.base58_decode(Exact::TOKEN_2022_PROGRAM)]
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

            # Rule 5: authority guard (spine verify.rs:382).
            if managed_signers.any? { |managed| managed == authority || managed == source }
              raise "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
            end

            if accounts.any? { |index| managed_signers.include?(account_key_for_index(index, account_keys)) }
              raise "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts"
            end

            expected_mint = Exact.base58_decode(requirement.fetch("asset"))
            raise "invalid_exact_svm_payload_mint_mismatch" unless mint == expected_mint

            expected_destination = Exact.associated_token_address(Exact.base58_decode(requirement.fetch("payTo")), program, expected_mint)
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

          # Fee-payer-in-instruction-accounts sweep. Closes the ATA-drain
          # vector where an extra instruction (TransferChecked, SystemProgram
          # Transfer, etc.) names the fee payer as a signer or source.
          # INTENTIONAL_DIVERGENCE from spine: the Rust spine has no such
          # sweep. The Ruby port mirrors the Go and Lua port carve-out
          # for ATA-create's funding-payer slot 0.
          def reject_fee_payer_in_instruction_accounts!(instructions, account_keys, managed_signers)
            ata_program = Exact.base58_decode(Exact::ASSOCIATED_TOKEN_PROGRAM)
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
            # ATA program instruction discriminator:
            #   empty data       -> Create (legacy variant)
            #   single byte 0x00 -> Create
            #   single byte 0x01 -> CreateIdempotent
            return true if data.bytesize.zero?
            return false unless data.bytesize == 1

            first = data.getbyte(0)
            first == 0 || first == 1
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
              wallet == Exact.base58_decode(requirement.fetch("payTo")) &&
              mint == transfer.fetch(:mint) &&
              system_program == Exact.base58_decode(Exact::SYSTEM_PROGRAM) &&
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
        end
      end
    end
  end
end
