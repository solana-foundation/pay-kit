# frozen_string_literal: true

require "pay_core/solana/ata"
require "pay_core/solana/payment_channels"
require "pay_core/solana/transaction"

require_relative "types"

module PayKit::Protocols::X402
  module Protocol
    module Schemes
      module Upto
        # Stateless verification for the x402 `upto` payment-channel profile:
        # the off-chain payload checks (issue #175 §3 Phase 3) and the
        # structural validation of the client-built `open` transaction the
        # facilitator broadcasts in pull mode. Mirrors the Go reference
        # `VerifyUptoPayload` + `validateUptoOpenInstruction` (upto.go:149-199,
        # 660-747).
        module Verifier
          module_function

          PaymentChannels = ::PayCore::Solana::PaymentChannels
          ATA = ::PayCore::Solana::ATA
          Transaction = ::PayCore::Solana::Transaction

          # Open-instruction account layout the on-chain program expects, by
          # index (idl/payment-channels.json `open`). Indices 6/7 (payer/channel
          # token accounts) are derived, so they are validated separately.
          OPEN_PAYER = 0
          OPEN_RENT_PAYER = 1
          OPEN_PAYEE = 2
          OPEN_MINT = 3
          OPEN_AUTHORIZED_SIGNER = 4
          OPEN_CHANNEL = 5
          OPEN_PAYER_TOKEN = 6
          OPEN_CHANNEL_TOKEN = 7
          OPEN_TOKEN_PROGRAM = 8
          OPEN_SYSTEM_PROGRAM = 9
          OPEN_RENT = 10
          OPEN_ASSOCIATED_TOKEN_PROGRAM = 11
          OPEN_EVENT_AUTHORITY = 12
          OPEN_SELF_PROGRAM = 13

          # Verify the off-chain payload against the route-pinned requirement
          # (issue #175 §3 Phase 3 steps 1, 5; §5 Phase 2). Raises a stable
          # reject message on any failure; mirrors VerifyUptoPayload.
          def verify_payload!(payload, requirement, operator, now)
            profile = payload["profile"]
            unless profile == PROFILE_PAYMENT_CHANNEL
              raise reject("invalid payload type: #{profile}")
            end
            advertised = Array(requirement.dig("extra", "profiles")).include?(profile)
            raise reject("profile #{profile} not advertised by the server") unless advertised

            max = Upto.parse_base_units(requirement["amount"], "amount")
            signed_max = Upto.parse_base_units(payload["maxAmount"], "maxAmount")
            raise reject("amount mismatch: expected #{max}, got #{signed_max}") unless signed_max == max

            deposit = Upto.parse_base_units(payload["deposit"], "deposit")
            raise reject("channel deposit #{deposit} must equal the authorized maximum #{max}") unless deposit == max

            valid_after = Integer(payload["validAfter"] || 0)
            expires_at = Integer(payload["expiresAt"])
            raise reject("authorization not yet active (validAfter #{valid_after} > now #{now})") if now < valid_after
            raise reject("authorization expired (expiresAt #{expires_at} < now #{now})") if now > expires_at

            unless payload["authorizedSigner"] == operator
              raise reject("voucher authorized_signer must be the operator for the payment-channel profile")
            end

            {max: max, expires_at: expires_at, valid_after: valid_after}
          end

          # Enforce actual <= signed ceiling at settlement (issue #175 §4 Phase 4
          # step 2). Raises the scheme reject token on violation.
          def assert_within_ceiling!(actual, max)
            raise reject(ERROR_SETTLEMENT_EXCEEDS_AMOUNT) if actual > max
          end

          # Structurally validate the client-built `open` transaction before the
          # facilitator broadcasts it (pull mode): exactly one channel-open
          # instruction targeting the advertised channel program, with all 14
          # accounts in the exact program order. Mirrors
          # validateUptoOpenInstruction (upto.go:660-747).
          def validate_open_instruction!(transaction, program_id:, operator:, payer:, payee:, mint:, token_program:, channel_id:)
            keys = transaction.message.account_keys
            instructions = transaction.message.instructions
            unless instructions.length == 1
              raise reject("open transaction must contain exactly one instruction, found #{instructions.length}")
            end

            instruction = instructions.first
            program = key_at(keys, instruction.program_id_index)
            raise reject("open transaction targets an unexpected program") unless program == program_id
            if instruction.data.empty? || instruction.data.getbyte(0) != 1
              raise reject("open transaction is not a channel-open instruction")
            end

            payer_token = ATA.derive(owner: payer, mint: mint, token_program: token_program)
            channel_token = ATA.derive(owner: channel_id, mint: mint, token_program: token_program)
            event_authority = PaymentChannels.find_event_authority_pda(program_id: program_id)

            expect(instruction, keys, OPEN_PAYER, payer, "payer")
            expect(instruction, keys, OPEN_RENT_PAYER, operator, "rent_payer")
            expect(instruction, keys, OPEN_PAYEE, payee, "payee")
            expect(instruction, keys, OPEN_MINT, mint, "mint")
            expect(instruction, keys, OPEN_AUTHORIZED_SIGNER, operator, "authorized_signer")
            expect(instruction, keys, OPEN_CHANNEL, channel_id, "channel")
            expect(instruction, keys, OPEN_PAYER_TOKEN, payer_token, "payer_token_account")
            expect(instruction, keys, OPEN_CHANNEL_TOKEN, channel_token, "channel_token_account")
            expect(instruction, keys, OPEN_TOKEN_PROGRAM, token_program, "token_program")
            expect(instruction, keys, OPEN_SYSTEM_PROGRAM, PaymentChannels::SYSTEM_PROGRAM, "system_program")
            expect(instruction, keys, OPEN_RENT, PaymentChannels::RENT_SYSVAR, "rent_sysvar")
            expect(instruction, keys, OPEN_ASSOCIATED_TOKEN_PROGRAM, PaymentChannels::ASSOCIATED_TOKEN_PROGRAM, "associated_token_program")
            expect(instruction, keys, OPEN_EVENT_AUTHORITY, event_authority, "event_authority")
            expect(instruction, keys, OPEN_SELF_PROGRAM, program_id, "self_program")
          end

          # Verify the operator is the fee payer (account index 0) on the open
          # transaction, so a single operator signature covers the fee
          # (upto.go:477, 749-751).
          def fee_payer?(transaction, operator)
            keys = transaction.message.account_keys
            !keys.empty? && keys.first == operator
          end

          def expect(instruction, keys, position, want, label)
            got = account_at(instruction, keys, position)
            raise reject("open transaction #{label} mismatch: expected #{want}, got #{got || "<none>"}") unless got == want
          end

          def account_at(instruction, keys, position)
            return nil if position >= instruction.accounts.length

            key_at(keys, instruction.accounts[position])
          end

          def key_at(keys, index)
            return nil if index.nil? || index >= keys.length

            keys[index]
          end

          def reject(message)
            ::PayKit::Protocols::X402::Error::PaymentInvalid.new(message)
          end
        end
      end
    end
  end
end
