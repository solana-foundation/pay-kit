# frozen_string_literal: true

require_relative "base58"
require_relative "instruction"
require_relative "transaction"

module PayCore
  module Solana
    # Compiles a list of `Instruction`s into an unsigned legacy Solana
    # transaction. The x402 `upto` settle path (settle_and_finalize + ATA
    # creates + distribute) is built and broadcast by the facilitator, so Ruby
    # — which until now only parsed transactions — needs a message compiler.
    #
    # Legacy (not v0) to match the references: the Go settle tx uses
    # `solana.NewTransaction` (legacy) and the Rust client's `open` tx uses
    # `Message::new_with_blockhash` (legacy). The compiled key ordering only has
    # to be internally consistent (instructions index into the key table); it is
    # not byte-pinned across SDKs, so we follow the canonical compaction rule:
    # writable-signers, readonly-signers, writable-nonsigners, readonly-nonsigners,
    # fee payer first.
    module MessageBuilder
      module_function

      # Build an unsigned legacy `Transaction` paying `fee_payer` (base58) over
      # `recent_blockhash` (base58) executing `instructions`. The returned
      # transaction has zeroed signature slots; the caller fills them with
      # `Transaction#sign_with` for each required signer.
      def build_legacy(fee_payer:, recent_blockhash:, instructions:)
        roles = collect_roles(fee_payer, instructions)
        ordered = order_accounts(roles)
        index_of = ordered.each_with_index.to_h { |pubkey, index| [pubkey, index] }

        header = [
          roles.count { |_pubkey, role| role[:signer] },
          roles.count { |_pubkey, role| role[:signer] && !role[:writable] },
          roles.count { |_pubkey, role| !role[:signer] && !role[:writable] }
        ]

        message = header.pack("C3")
        message += Transaction.compact_u16(ordered.length)
        message += ordered.map { |pubkey| Base58.decode(pubkey) }.join
        message += Base58.decode(recent_blockhash)
        message += Transaction.compact_u16(instructions.length)
        instructions.each do |instruction|
          message += [index_of.fetch(instruction.program_id)].pack("C")
          message += Transaction.compact_u16(instruction.accounts.length)
          message += instruction.accounts.map { |meta| index_of.fetch(meta.pubkey) }.pack("C*")
          message += Transaction.compact_u16(instruction.data.bytesize)
          message += instruction.data
        end

        signature_count = header.first
        unsigned = Transaction.compact_u16(signature_count) + ("\x00".b * 64 * signature_count) + message
        Transaction.from_bytes(unsigned)
      end

      # Merge every account reference (and program id) into role flags,
      # preserving first-seen order. The fee payer is seeded first as a
      # writable signer so it compiles to account index 0.
      def collect_roles(fee_payer, instructions)
        roles = {}
        upsert(roles, fee_payer, signer: true, writable: true)
        instructions.each do |instruction|
          instruction.accounts.each do |meta|
            upsert(roles, meta.pubkey, signer: meta.signer, writable: meta.writable)
          end
          # A program id is a readonly, non-signer account; `upsert` keeps any
          # stronger role the same key already earned as a writable/signer.
          upsert(roles, instruction.program_id, signer: false, writable: false)
        end
        roles
      end

      def upsert(roles, pubkey, signer:, writable:)
        role = roles[pubkey] ||= {signer: false, writable: false}
        role[:signer] ||= signer
        role[:writable] ||= writable
      end

      def order_accounts(roles)
        buckets = {sw: [], sr: [], nw: [], nr: []}
        roles.each do |pubkey, role|
          bucket = if role[:signer]
            role[:writable] ? :sw : :sr
          else
            role[:writable] ? :nw : :nr
          end
          buckets[bucket] << pubkey
        end
        buckets[:sw] + buckets[:sr] + buckets[:nw] + buckets[:nr]
      end
    end
  end
end
