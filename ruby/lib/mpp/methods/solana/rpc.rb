# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "uri"

module Mpp
  module Methods
    module Solana
      # Minimal JSON-RPC client for the charge server path.
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
          body = JSON.parse(response.body)
          raise Error, "#{method}: #{body["error"]["message"]}" if body["error"]

          body["result"]
        rescue Timeout::Error => error
          raise Error, "#{method}: Solana RPC request timed out (#{error.class})"
        rescue *NETWORK_ERRORS => error
          raise Error, "#{method}: Solana RPC request failed (#{error.class})"
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
end
