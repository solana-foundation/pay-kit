# frozen_string_literal: true

require "base64"

require_relative "base58"
require_relative "public_key"

module PayCore
  module Solana
    # Parsed legacy or v0 Solana transaction. Owns the binary codec; mirrors
    # the Rust spine `rust/crates/core/src/solana/transaction.rs`.
    #
    # `sign_with` raises `PayCore::Solana::Transaction::SigningError` by
    # default. Higher layers (solana-mpp, solana-x402) may subclass this
    # class and override the private `signing_error_class` hook to plug in
    # their own protocol-specific error type while reusing the canonical
    # wire codec.
    class Transaction
      # Raised when `sign_with` is asked to sign with a keypair that is not
      # a required signer of the parsed transaction.
      class SigningError < StandardError; end

      attr_reader :signatures, :message, :message_offset, :version

      def initialize(signatures:, message:, message_offset:, version:)
        @signatures = signatures
        @message = message
        @message_offset = message_offset
        @version = version
      end

      # Decode a standard-base64 Solana transaction.
      def self.from_base64(value)
        raw = Base64.strict_decode64(value)
        from_bytes(raw)
      rescue ArgumentError => error
        raise ArgumentError, "invalid transaction payload: #{error.message}"
      end

      # Parse a Solana transaction from wire bytes.
      def self.from_bytes(raw)
        cursor = Cursor.new(raw)
        signature_count = cursor.compact_u16
        signatures = signature_count.times.map { cursor.bytes(64) }
        message_offset = cursor.offset
        message = Message.parse(cursor.remaining)
        new(signatures: signatures, message: message, message_offset: message_offset, version: message.version)
      end

      # Serialize this transaction back to wire bytes.
      def to_bytes
        [self.class.compact_u16(signatures.length), signatures.join, message.raw].join
      end

      # Serialize to standard-base64.
      def to_base64
        Base64.strict_encode64(to_bytes)
      end

      # Replace one signature by signer public key. Raises `SigningError`
      # when the keypair is not present in the required signer set.
      def sign_with(keypair)
        index = message.account_keys.index(keypair.public_key.to_s)
        raise signing_error_class, "fee payer not found in transaction accounts" if index.nil?
        raise signing_error_class, "fee payer is not a required signer" if index >= signatures.length

        signatures[index] = keypair.sign(message.raw)
      end

      # Return the primary signature as base58.
      def primary_signature
        Base58.encode(signatures.fetch(0))
      end

      def self.compact_u16(value)
        bytes = []
        loop do
          byte = value & 0x7f
          value >>= 7
          byte |= 0x80 if value.positive?
          bytes << byte
          break unless value.positive?
        end
        bytes.pack("C*")
      end

      # Encode an unsigned integer as Solana short_vec (compact-u16) bytes.
      # Alias of `compact_u16` exposed under the spine name so x402 byte
      # encoders can share one canonical implementation.
      def self.short_vec(value)
        compact_u16(value)
      end

      # Decode a Solana short_vec starting at `offset`, returning
      # `[value, next_offset]`. Mirrors the canonical spine helper exposed
      # by `rust/crates/core/src/solana/transaction.rs::read_short_vec`.
      def self.read_short_vec(bytes, offset)
        value = 0
        shift = 0
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

      private

      # Sub-classes (solana-mpp, solana-x402) override to plug in their own
      # protocol-specific error class while reusing this base implementation.
      def signing_error_class
        SigningError
      end
    end

    # Parsed Solana transaction message.
    class Message
      attr_reader :raw, :version, :header, :account_keys, :recent_blockhash, :instructions, :address_table_lookups

      def initialize(raw:, version:, header:, account_keys:, recent_blockhash:, instructions:, address_table_lookups:)
        @raw = raw
        @version = version
        @header = header
        @account_keys = account_keys
        @recent_blockhash = recent_blockhash
        @instructions = instructions
        @address_table_lookups = address_table_lookups
      end

      # Parse a legacy or v0 transaction message.
      def self.parse(raw)
        cursor = Cursor.new(raw)
        version = "legacy"
        first = cursor.peek
        if (first & 0x80) != 0
          version = first & 0x7f
          raise ArgumentError, "unsupported transaction version" unless version == 0

          cursor.byte
        end
        header = {
          required_signatures: cursor.byte,
          readonly_signed: cursor.byte,
          readonly_unsigned: cursor.byte
        }
        account_keys = cursor.compact_u16.times.map { PublicKey.new(cursor.bytes(32)).to_s }
        recent_blockhash = Base58.encode(cursor.bytes(32))
        instructions = cursor.compact_u16.times.map { Instruction.parse(cursor) }
        lookups = []
        lookups = cursor.compact_u16.times.map { AddressLookup.parse(cursor) } if version == 0
        new(
          raw: raw,
          version: version,
          header: header,
          account_keys: account_keys,
          recent_blockhash: recent_blockhash,
          instructions: instructions,
          address_table_lookups: lookups
        )
      end
    end

    # Parsed compiled Solana instruction.
    class Instruction
      attr_reader :program_id_index, :accounts, :data

      def initialize(program_id_index:, accounts:, data:)
        @program_id_index = program_id_index
        @accounts = accounts
        @data = data
      end

      # Parse a compiled instruction from a cursor.
      def self.parse(cursor)
        new(
          program_id_index: cursor.byte,
          accounts: cursor.compact_u16.times.map { cursor.byte },
          data: cursor.bytes(cursor.compact_u16)
        )
      end
    end

    # Parsed v0 address lookup table entry.
    class AddressLookup
      # Parse one address lookup table entry.
      def self.parse(cursor)
        cursor.bytes(32)
        writable = cursor.compact_u16.times.map { cursor.byte }
        readonly = cursor.compact_u16.times.map { cursor.byte }
        {writable: writable, readonly: readonly}
      end
    end

    # Cursor for Solana compact-u16 binary parsing.
    class Cursor
      attr_reader :offset

      def initialize(raw)
        @raw = raw
        @offset = 0
      end

      # Read one byte.
      def byte
        raise ArgumentError, "unexpected end of transaction" if offset >= @raw.bytesize

        value = @raw.getbyte(offset)
        @offset += 1
        value
      end

      # Peek at one byte.
      def peek
        raise ArgumentError, "unexpected end of transaction" if offset >= @raw.bytesize

        @raw.getbyte(offset)
      end

      # Read `count` bytes.
      def bytes(count)
        raise ArgumentError, "unexpected end of transaction" if offset + count > @raw.bytesize

        value = @raw.byteslice(offset, count)
        @offset += count
        value
      end

      # Read a Solana compact-u16 integer.
      def compact_u16
        value = 0
        shift = 0
        loop do
          byte = self.byte
          value |= (byte & 0x7f) << shift
          break if (byte & 0x80).zero?

          shift += 7
          raise ArgumentError, "compact-u16 is too long" if shift > 21
        end
        value
      end

      # Return all unread bytes.
      def remaining
        @raw.byteslice(offset, @raw.bytesize - offset)
      end
    end
  end
end
