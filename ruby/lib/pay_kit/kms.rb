# frozen_string_literal: true

require_relative "errors"

module PayKit
  # Namespace reservation for remote enclave signers (GCP KMS, AWS KMS,
  # HashiCorp Vault, etc.). The shape is locked so consumers can build
  # against `PayKit::Kms.gcp(...)` today without having to rename when
  # the actual implementations ship in a follow-up release.
  #
  # Every factory currently raises `PayKit::NotImplementedError`. Loud
  # failure is on purpose: silent fallback would mask production
  # misconfiguration (a merchant intending to sign through a managed
  # KMS service should not get a local in-process signer instead).
  #
  # When implemented, KMS signers will satisfy the same duck-type
  # contract as `PayKit::Signer::Local` (`#pubkey`, `#sign(message)`,
  # `#fee_payer?`) and add async-on-network semantics with explicit
  # `pubkey:` configuration so boot does not probe the enclave.
  module Kms
    module_function

    def gcp(key_name:, pubkey:)
      raise ::PayKit::NotImplementedError,
        "PayKit::Kms.gcp(key_name: #{key_name.inspect}, pubkey: #{pubkey.inspect}) " \
        "is reserved for a follow-up release; use PayKit::Signer.file or PayKit::Signer.env in the meantime"
    end

    def aws(key_id:, region:, pubkey:)
      raise ::PayKit::NotImplementedError,
        "PayKit::Kms.aws(key_id: #{key_id.inspect}, region: #{region.inspect}, pubkey: #{pubkey.inspect}) " \
        "is reserved for a follow-up release; use PayKit::Signer.file or PayKit::Signer.env in the meantime"
    end

    def vault(addr:, path:, pubkey:)
      raise ::PayKit::NotImplementedError,
        "PayKit::Kms.vault(addr: #{addr.inspect}, path: #{path.inspect}, pubkey: #{pubkey.inspect}) " \
        "is reserved for a follow-up release; use PayKit::Signer.file or PayKit::Signer.env in the meantime"
    end
  end
end
