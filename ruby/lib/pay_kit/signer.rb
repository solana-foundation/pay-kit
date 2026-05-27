# frozen_string_literal: true

require "json"

require "pay_core/solana/base58"

require_relative "errors"

module PayKit
  # Factory module for local Ed25519 signers. Every factory returns an
  # object that satisfies the PayKit signer duck-type contract:
  #
  #   #pubkey      → base58 String (44 chars)
  #   #sign(msg)   → 64-byte signature String
  #   #fee_payer?  → Boolean (true for in-process local signers)
  #   #demo?       → Boolean (only true for `Signer.demo`)
  #
  # Remote enclave signers (GCP KMS, AWS KMS, HashiCorp Vault) are
  # reserved under `PayKit::Kms` but are not part of this release; the
  # `Signer::InvalidKeyError` and the contract live here so callers can
  # treat both halves uniformly when the remote backends ship.
  module Signer
    # Raised when an input value cannot be parsed as a valid 64-byte
    # Solana keypair (wrong length, invalid encoding, missing bytes).
    class InvalidKeyError < ::PayKit::Error; end

    module_function

    # The package-shipped demo keypair. Returns the cached `Signer::Demo`
    # instance and emits a one-time `Logger.warn`. Boot-time mainnet
    # refusal is wired in `PayKit::Config#freeze!`.
    def demo
      Demo.instance
    end

    # 64-byte secret as a Ruby Array of integers (Solana CLI keypair
    # format minus the JSON wrapping).
    def bytes(array)
      Local.new(array)
    end

    # Solana CLI JSON-array format, e.g. `"[1,2,3,...,64]"`.
    def json(string)
      array = JSON.parse(string)
      raise InvalidKeyError, "Solana CLI keypair must be a JSON array" unless array.is_a?(Array)

      Local.new(array.map { |element| Integer(element) })
    rescue JSON::ParserError, TypeError => error
      raise InvalidKeyError, "malformed Solana CLI JSON-array keypair: #{error.message}"
    end

    # Phantom / Solflare base58 export form. Solana keypair bytes (64)
    # encoded as base58 produce ~87-88 characters.
    def base58(string)
      decoded = ::PayCore::Solana::Base58.decode(string)
      Local.new(decoded.bytes)
    rescue ArgumentError => error
      raise InvalidKeyError, "malformed base58 keypair: #{error.message}"
    end

    # 128-char hex string (64 bytes hex-encoded).
    def hex(string)
      unless string.is_a?(String) && string.match?(/\A[0-9a-fA-F]+\z/) && string.length.even?
        raise InvalidKeyError, "hex keypair must be an even-length string of hex digits"
      end

      Local.new([string].pack("H*").bytes)
    end

    # Read a Solana CLI JSON-array keypair file.
    def file(path)
      raw = File.read(path)
      json(raw)
    rescue Errno::ENOENT, Errno::EACCES => error
      raise InvalidKeyError, "keypair file unreadable: #{error.message}"
    end

    # Env-var loader. Returns `nil` when the variable is unset or empty
    # so that the caller's default keypair (typically `Signer.demo`)
    # survives the no-op assignment chain. Raises `InvalidKeyError` when
    # the variable holds a value that cannot be parsed in any of the
    # supported formats.
    def env(name)
      raw = ENV[name]
      return nil if raw.nil? || raw.empty?

      stripped = raw.strip
      if stripped.start_with?("[")
        json(stripped)
      elsif stripped.match?(/\A[0-9a-fA-F]{128}\z/)
        hex(stripped)
      else
        base58(stripped)
      end
    end

    # Generate a fresh ephemeral keypair. Test-only utility; production
    # callers should bind to a persistent key source (file/env/KMS).
    def generate
      require "ed25519"

      signing_key = ::Ed25519::SigningKey.generate
      Local.new(signing_key.to_bytes.bytes + signing_key.verify_key.to_bytes.bytes)
    end
  end
end

require_relative "signer/local"
require_relative "signer/demo"
