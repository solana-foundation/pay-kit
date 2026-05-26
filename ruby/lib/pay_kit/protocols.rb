# frozen_string_literal: true

require_relative "errors"

module PayKit
  # Namespace for protocol adapters. Each adapter exposes:
  #
  #   .from_config(config)          -> frozen adapter instance
  #   #accepts_entry(gate, request) -> Hash (one entry in 402 `accepts[]`)
  #   #challenge_headers(gate, req) -> Hash (protocol-specific 402 headers)
  #   #verify_and_settle(gate, req) -> Payment    (raises InvalidProof on failure)
  #   #detect?(request)             -> Boolean   (does this request carry our envelope?)
  #
  # Adapters are stateless aside from the frozen config. Replay state
  # lives inside the wrapped server (`X402::Server::Exact::SettlementCache`,
  # `Mpp::Server`'s store).
  module Protocols
    # Sentinel returned by `PayKit::Protocols::X402.exact` so gates can
    # express `accept: PayKit::Protocols::X402.exact` even though the
    # symbol-form `accept: :x402` still works. Frozen, comparable
    # against the `:x402` symbol via `#protocol`.
    ProtocolRef = Data.define(:protocol, :scheme) do
      def to_sym
        protocol
      end
    end
  end
end

require_relative "protocols/x402"
require_relative "protocols/mpp"
