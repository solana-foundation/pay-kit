# frozen_string_literal: true

module PayCore
  module Solana
    # A single account reference inside a compiled instruction, carrying the
    # signer / writable roles the legacy message compiler folds into the
    # message header. `pubkey` is a base58 String; the builders in
    # `PaymentChannels` emit these and `MessageBuilder` consumes them.
    AccountMeta = Struct.new(:pubkey, :signer, :writable) do
      def self.signer_writable(pubkey)
        new(pubkey, true, true)
      end

      def self.signer_readonly(pubkey)
        new(pubkey, true, false)
      end

      def self.writable(pubkey)
        new(pubkey, false, true)
      end

      def self.readonly(pubkey)
        new(pubkey, false, false)
      end
    end

    # An un-compiled Solana instruction: the program it targets (base58
    # `program_id`), its ordered `accounts` (each an `AccountMeta`), and the
    # raw binary instruction `data`. `MessageBuilder` turns a list of these
    # into a signed legacy transaction. Mirrors the shape the Rust/Go SDKs
    # feed their message compilers (`solana::Instruction`).
    #
    # Distinct from `Transaction`'s `Instruction`, which is the already-compiled
    # form (program-id INDEX + account INDEXES) produced when parsing wire bytes.
    PreparedInstruction = Struct.new(:program_id, :accounts, :data)
  end
end
