# frozen_string_literal: true

module PayCore
  # Canonical structured error codes (audit v2 L6 / P1 lock, mirrored across
  # Ruby, PHP, Lua, Rust, TypeScript, Go, Python).
  #
  # Every 402 response body emitted by the server SDK carries a `code` field
  # with one of these constants. The body also keeps the legacy `error` and
  # `message` fields so a polyglot client that pre-dates L6 still works.
  #
  # `canonical_code` maps an MPP/x402 error message or a legacy code to the
  # right L6 canonical code. Unknown failure classes fall back to
  # `payment_invalid` so a 402 response always carries a canonical code.
  module ErrorCodes
    # The credential's claimed charge does not match the route's expected
    # charge (amount, recipient, currency, method details).
    CODE_CHARGE_REQUEST_MISMATCH = "charge_request_mismatch"

    # The credential was issued for a different route than the one being
    # requested (different pinned fields: realm, intent, method).
    CODE_CHALLENGE_ROUTE_MISMATCH = "challenge_route_mismatch"

    # HMAC verification failed on the challenge id.
    CODE_CHALLENGE_VERIFICATION_FAILED = "challenge_verification_failed"

    # The challenge's `expires` is in the past.
    CODE_CHALLENGE_EXPIRED = "challenge_expired"

    # The credential payload is malformed or fails on-chain verification:
    # decode error, instruction allowlist violation, signature shape error.
    CODE_PAYMENT_INVALID = "payment_invalid"

    # The credential was signed against a different network than the one the
    # server is configured for.
    CODE_WRONG_NETWORK = "wrong_network"

    # The on-chain signature has already been used to settle a previous charge.
    CODE_SIGNATURE_CONSUMED = "signature_consumed"

    CANONICAL_CODES = [
      CODE_CHARGE_REQUEST_MISMATCH,
      CODE_CHALLENGE_ROUTE_MISMATCH,
      CODE_CHALLENGE_VERIFICATION_FAILED,
      CODE_CHALLENGE_EXPIRED,
      CODE_PAYMENT_INVALID,
      CODE_WRONG_NETWORK,
      CODE_SIGNATURE_CONSUMED
    ].freeze

    # Mapping from legacy or per-language internal codes to canonical codes.
    # Mirrors python/src/solana_mpp/_errors.py `_LEGACY_TO_CANONICAL`.
    LEGACY_TO_CANONICAL = {
      "challenge-expired" => CODE_CHALLENGE_EXPIRED,
      "challenge-mismatch" => CODE_CHALLENGE_VERIFICATION_FAILED,
      "signature-consumed" => CODE_SIGNATURE_CONSUMED,
      "wrong-network" => CODE_WRONG_NETWORK,
      "amount-mismatch" => CODE_CHARGE_REQUEST_MISMATCH,
      "recipient-mismatch" => CODE_CHARGE_REQUEST_MISMATCH,
      "splits-exceed-amount" => CODE_CHARGE_REQUEST_MISMATCH,
      "invalid-payload" => CODE_PAYMENT_INVALID,
      "invalid-payload-type" => CODE_PAYMENT_INVALID,
      "invalid-config" => CODE_PAYMENT_INVALID,
      "missing-signature" => CODE_PAYMENT_INVALID,
      "missing-transaction" => CODE_PAYMENT_INVALID,
      "transaction-failed" => CODE_PAYMENT_INVALID,
      "transaction-not-found" => CODE_PAYMENT_INVALID,
      "no-transfer" => CODE_PAYMENT_INVALID
    }.freeze

    # Substring patterns that classify an SDK error message into a canonical
    # code when no explicit code was set at raise time. Ordered; first match
    # wins. Mirrors harness/src/canonical-codes.ts and
    # rust/src/bin/harness_server.rs::classify_canonical_code.
    MESSAGE_PATTERNS = [
      [/already consumed/i, CODE_SIGNATURE_CONSUMED],
      # Solana RPC's own duplicate-signature reject text. Surfaces when
      # an idempotent-resubmit reaches the RPC's per-blockhash signature
      # uniqueness check before (or instead of) the local replay store -
      # the matrix's charge-idempotent-resubmit pins this.
      [/already been processed/i, CODE_SIGNATURE_CONSUMED],
      [/challenge verification failed/i, CODE_CHALLENGE_VERIFICATION_FAILED],
      [/challenge expired/i, CODE_CHALLENGE_EXPIRED],
      [/signed against localnet but the server expects/i, CODE_WRONG_NETWORK],
      [/network mismatch/i, CODE_WRONG_NETWORK],
      [/amount mismatch/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/currency mismatch/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/recipient mismatch/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/method details mismatch/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/split amounts exceed total/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/too many splits/i, CODE_CHARGE_REQUEST_MISMATCH],
      [/credential method does not match/i, CODE_CHALLENGE_ROUTE_MISMATCH],
      [/credential intent is not a charge/i, CODE_CHALLENGE_ROUTE_MISMATCH],
      [/credential realm does not match/i, CODE_CHALLENGE_ROUTE_MISMATCH],
      [/unexpected program instruction/i, CODE_CHARGE_REQUEST_MISMATCH]
    ].freeze

    # Return the canonical L6 code for a code or an error message.
    #
    # Resolution order:
    #   1. The string is already a canonical L6 code.
    #   2. The string is a legacy kebab-case code with a known mapping.
    #   3. The string matches a classified message pattern.
    #   4. Fallback: `payment_invalid`.
    def self.canonical_code(code_or_message)
      return CODE_PAYMENT_INVALID if code_or_message.nil? || code_or_message.empty?
      return code_or_message if CANONICAL_CODES.include?(code_or_message)
      mapped = LEGACY_TO_CANONICAL[code_or_message]
      return mapped if mapped

      MESSAGE_PATTERNS.each do |pattern, code|
        return code if code_or_message.match?(pattern)
      end
      CODE_PAYMENT_INVALID
    end
  end
end
