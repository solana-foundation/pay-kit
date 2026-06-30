# frozen_string_literal: true

require "ed25519"

require "pay_core/solana/ata"
require "pay_core/solana/base58"
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
          def validate_open_instruction!(transaction, program_id:, operator:, payer:, payee:, mint:, token_program:, channel_id:, max:)
            keys = transaction.message.account_keys
            instructions = transaction.message.instructions
            # Reject v0 transactions that pull accounts from address lookup
            # tables. This validator and the fee-payer co-sign resolve every
            # account via the static key list; a non-empty ALT lookup could
            # smuggle in accounts the position checks below cannot see, and the
            # operator would blindly co-sign. Mirrors the Rust spine.
            unless Array(transaction.message.address_table_lookups).empty?
              raise reject("open transaction must not use address lookup tables")
            end
            unless instructions.length == 1
              raise reject("open transaction must contain exactly one instruction, found #{instructions.length}")
            end

            instruction = instructions.first
            program = key_at(keys, instruction.program_id_index)
            raise reject("open transaction targets an unexpected program") unless program == program_id
            if instruction.data.empty? || instruction.data.getbyte(0) != 1
              raise reject("open transaction is not a channel-open instruction")
            end

            # The wire signature array must cover every required signer. A client
            # can pin payer/rent_payer to signer slots yet serialize fewer
            # signatures than the header requires; the operator fills slot 0 and
            # broadcasts a transaction the runtime rejects for missing
            # signatures, after the fee is spent. Pin the array length first.
            required_signers = transaction.message.header[:required_signatures]
            unless transaction.signatures.length == required_signers
              raise reject("open transaction has #{transaction.signatures.length} signatures, expected #{required_signers}")
            end

            payer_token = ATA.derive(owner: payer, mint: mint, token_program: token_program)
            channel_token = ATA.derive(owner: channel_id, mint: mint, token_program: token_program)
            event_authority = PaymentChannels.find_event_authority_pda(program_id: program_id)

            expect(instruction, keys, OPEN_PAYER, payer, "payer")
            expect(instruction, keys, OPEN_RENT_PAYER, operator, "rent_payer")
            expect(instruction, keys, OPEN_PAYEE, payee, "payee")
            # The on-chain `open` requires payer + rent_payer to be signers
            # (idl/payment-channels.json `open`, accounts 0/1). Matching only the
            # pubkeys is not enough: a client can point those instruction slots at
            # a non-signer account index, so the operator signs and pays the fee
            # for a transaction the program then rejects. Pin both to signer
            # positions in the message header before broadcast.
            require_signer!(transaction, instruction, OPEN_PAYER, "payer")
            require_signer!(transaction, instruction, OPEN_RENT_PAYER, "rent_payer")
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

            validate_open_args!(instruction.data, max: max, payer: payer, payee: payee, mint: mint,
              operator: operator, channel_id: channel_id, program_id: program_id)

            # Final check, once positions and signer slots are confirmed: every
            # required signer other than the operator (whose slot the facilitator
            # fills before broadcast) must already carry a valid signature over
            # the message. A client can otherwise serialize a zeroed payer
            # signature; the operator co-signs slot 0 and broadcasts, and the
            # runtime rejects the open after the operator has paid the fee.
            verify_cosigner_signatures!(transaction, operator, transaction.message.header[:required_signatures])
          end

          # Validate the OpenArgs the client signed before the operator spends a
          # fee broadcasting them. The account list passing does not bind the
          # args: a client could match every account yet sign a bad salt,
          # deposit, or distribution, forcing the operator to broadcast a
          # channel that verify_open then rejects on-chain (operator fee grief).
          # OpenArgs Borsh: salt(u64) deposit(u64) gracePeriod(u32) recipients(vec).
          def validate_open_args!(data, max:, payer:, payee:, mint:, operator:, channel_id:, program_id:)
            raise reject("open instruction data is too short for OpenArgs") if data.bytesize < 25

            salt = PaymentChannels.read_u64_le(data, 1)
            deposit = PaymentChannels.read_u64_le(data, 9)
            grace_period = PaymentChannels.read_u32_le(data, 17)
            recipients_count = PaymentChannels.read_u32_le(data, 21)
            unless deposit == max
              raise reject("open deposit #{deposit} must equal the authorized maximum #{max}")
            end
            unless grace_period == PaymentChannels::DEFAULT_GRACE_PERIOD_SECONDS
              raise reject("open grace period #{grace_period} must equal the canonical #{PaymentChannels::DEFAULT_GRACE_PERIOD_SECONDS}")
            end
            unless recipients_count.zero?
              raise reject("x402 upto requires an empty-recipient open (got #{recipients_count} splits)")
            end
            derived = PaymentChannels.find_channel_pda(
              payer: payer, payee: payee, mint: mint, authorized_signer: operator, salt: salt, program_id: program_id
            )
            unless derived == channel_id
              raise reject("open salt does not derive the payload channelId")
            end
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

          # Assert the instruction account at `position` resolves to a signer
          # slot in the message header. The compiled message lays out all
          # required signers first, so an account key index below
          # `header.required_signatures` is a signer (Solana message layout).
          def require_signer!(transaction, instruction, position, label)
            key_index = instruction.accounts[position]
            required = transaction.message.header[:required_signatures]
            unless !key_index.nil? && key_index < required
              raise reject("open transaction #{label} must be a signer")
            end
          end

          # Verify the serialized signature bytes for every required signer slot
          # except the operator's own (filled at co-sign). Rejects a zeroed or
          # forged client signature before the operator spends a broadcast fee.
          def verify_cosigner_signatures!(transaction, operator, required_signers)
            message = transaction.message.raw
            keys = transaction.message.account_keys
            required_signers.times do |i|
              signer = keys[i]
              next if signer.nil? || signer == operator

              signature = transaction.signatures[i]
              unless valid_signature?(signer, signature, message)
                raise reject("open transaction signer #{signer} is missing a valid signature")
              end
            end
          end

          def valid_signature?(pubkey, signature, message)
            return false if signature.nil? || signature.bytesize != 64

            ::Ed25519::VerifyKey.new(::PayCore::Solana::Base58.decode(pubkey)).verify(signature, message)
          rescue
            false
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
