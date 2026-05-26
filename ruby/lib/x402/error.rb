# frozen_string_literal: true

module X402
  # Canonical x402 error hierarchy. Mirrors the Rust spine enum
  # `rust/crates/x402/src/error.rs:1-60` while keeping the Ruby
  # idiom of one class per variant so callers can `rescue` the
  # specific reject class they care about.
  #
  # The leaf classes embed their canonical reject token (the string
  # the cross-language interop harness greps for) so the wire body
  # remains stable across ports: raising `PaymentInvalid.new(reason)`
  # serializes that reason verbatim, never the Ruby class name.
  class Error < StandardError
    # --- Generic catch-all (spine Error::Other) --------------------------
    class Other < Error; end

    # --- Transport / RPC (spine Error::Rpc, Http) ------------------------
    class Rpc < Error; end
    class Http < Error; end

    # --- Settlement state (spine Error::TransactionNotFound, Failed) -----
    class TransactionNotFound < Error
      def initialize(msg = "Transaction not found or not yet confirmed")
        super
      end
    end

    class TransactionFailed < Error; end

    # --- Replay store (spine Error::SignatureConsumed) -------------------
    class SignatureConsumed < Error
      # Canonical reject token surfaced verbatim on the wire body.
      TOKEN = "signature_consumed"

      def initialize(msg = TOKEN)
        super
      end
    end

    # --- Simulation (spine Error::SimulationFailed) ----------------------
    class SimulationFailed < Error; end

    # --- Envelope shape (spine Error::MissingTransaction, MissingSignature,
    #     InvalidPayloadType, InvalidPaymentRequired, MissingPaymentHeader) -
    class MissingTransaction < Error; end
    class MissingSignature < Error; end
    class InvalidPayloadType < Error; end
    class InvalidPaymentRequired < Error; end
    class MissingPaymentHeader < Error; end

    # --- Verifier rejects (spine Error::NoTransferInstruction, AmountMismatch,
    #     RecipientMismatch, MintMismatch, AtaMismatch, WrongNetwork) ------
    #
    # Subclassed under PaymentInvalid so a single `rescue` covers the
    # whole verifier-reject family. Each subclass carries a fixed
    # canonical reject token in its message so the cross-language
    # interop harness can substring-match without seeing the Ruby
    # class name.
    class PaymentInvalid < Error; end
  end
end
