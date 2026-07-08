# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"

module PayCore
  module Solana
    # Minimal JSON-RPC client for Solana clusters. Shared by solana-mpp
    # (charge path) and solana-x402 (latest blockhash + send/confirm). The
    # `RpcError` raised on non-2xx, network, or RPC error is intentionally
    # local; higher layers translate it into their own protocol error
    # without leaking transport concerns. Mirrors the Rust spine
    # `rust/crates/core/src/solana/rpc.rs`.
    class Rpc
      DEFAULT_OPEN_TIMEOUT_SECONDS = 5
      DEFAULT_READ_TIMEOUT_SECONDS = 10
      DEFAULT_WRITE_TIMEOUT_SECONDS = 10
      NETWORK_ERRORS = [
        EOFError,
        Errno::ECONNREFUSED,
        Errno::ECONNRESET,
        Errno::EPIPE,
        IOError,
        SocketError
      ].freeze

      # Raised on HTTP failure, transport error, or non-nil JSON-RPC error.
      class RpcError < StandardError; end

      def initialize(
        url,
        open_timeout: DEFAULT_OPEN_TIMEOUT_SECONDS,
        read_timeout: DEFAULT_READ_TIMEOUT_SECONDS,
        write_timeout: DEFAULT_WRITE_TIMEOUT_SECONDS
      )
        @uri = URI(url)
        @open_timeout = open_timeout
        @read_timeout = read_timeout
        @write_timeout = write_timeout
        @request_id = 0
        @request_id_mutex = Mutex.new
      end

      # Call a Solana JSON-RPC method.
      def call(method, params = [])
        response = perform_request(JSON.generate({jsonrpc: "2.0", id: next_request_id, method: method, params: params}))
        raise rpc_error_class, "#{method} HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        body = JSON.parse(response.body)
        raise rpc_error_class, "#{method}: #{body["error"]["message"]}" if body["error"]

        body["result"]
      rescue Timeout::Error => error
        raise rpc_error_class, "#{method}: Solana RPC request timed out (#{error.class})"
      rescue *NETWORK_ERRORS => error
        raise rpc_error_class, "#{method}: Solana RPC request failed (#{error.class})"
      end

      # Return the latest confirmed blockhash.
      def latest_blockhash
        call("getLatestBlockhash", [{"commitment" => "confirmed"}]).fetch("value").fetch("blockhash")
      end

      # Simulate a base64 transaction and fail on program errors.
      def simulate_transaction(transaction_base64)
        call("simulateTransaction", [
          transaction_base64,
          {
            "encoding" => "base64",
            "commitment" => "confirmed",
            "sigVerify" => false
          }
        ]).fetch("value")
      end

      # Submit a signed base64 transaction.
      def send_raw_transaction(transaction_base64)
        call("sendTransaction", [
          transaction_base64,
          {
            "encoding" => "base64",
            "skipPreflight" => false,
            "preflightCommitment" => "confirmed"
          }
        ])
      end

      # Return signature status array.
      def signature_statuses(signatures)
        call("getSignatureStatuses", [signatures]).fetch("value")
      end

      # Fetch the owning program of an account (the `owner` field of
      # getAccountInfo). Returns the owner program ID string, or nil when the
      # account does not exist. Used to resolve the token program of an
      # arbitrary SPL mint at boot (audit #28).
      def account_owner(pubkey)
        value = call("getAccountInfo", [
          pubkey,
          {"encoding" => "base64", "commitment" => "confirmed"}
        ]).fetch("value")
        return nil if value.nil?

        value["owner"]
      end

      # Fetch a confirmed transaction by signature using base64 encoding.
      def transaction_base64(signature)
        call("getTransaction", [
          signature,
          {
            "encoding" => "base64",
            "commitment" => "confirmed",
            "maxSupportedTransactionVersion" => 0
          }
        ])
      end

      private

      # Subclasses can swap the raised error class without overriding every
      # `raise` site. A protocol layer uses this hook to emit its own
      # protocol error while leaving the canonical `RpcError` available to
      # other consumers.
      def rpc_error_class
        RpcError
      end

      def next_request_id
        @request_id_mutex.synchronize do
          @request_id += 1
        end
      end

      def perform_request(body)
        request = Net::HTTP::Post.new(@uri.request_uri, "Content-Type" => "application/json")
        request.body = body

        http = Net::HTTP.new(@uri.hostname, @uri.port)
        http.use_ssl = @uri.scheme == "https"
        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout
        http.write_timeout = @write_timeout if http.respond_to?(:write_timeout=)

        http.start { |client| client.request(request) }
      end
    end
  end
end
