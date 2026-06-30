# frozen_string_literal: true

require "json"
require "logger"
require "rack"

require_relative "protocols/x402/runtime"

module PayKit
  # Usage-based (x402 `upto`) billing surface: a `Charge` meter the protected
  # handler records consumption into, and a Rack middleware that runs the
  # canonical open-verify → serve → settle-after sequence around it.
  #
  # Two-layer zero policy, matching the Go/Python ports:
  #   * the engine (`Server::Upto`) HONORS a zero settlement at the protocol
  #     layer — it closes the channel and refunds the full deposit;
  #   * this middleware FAIL-CLOSES a zero charge at the app layer — it still
  #     settles 0 on-chain (closing the channel) but withholds the resource
  #     body and returns 402.
  # That is why the Ruby upto server runs `x402-upto-basic` but stays off the
  # live `x402-upto-zero-actual` scenario (which is pinned to the low-level
  # Rust server); the honors-zero engine path is proven by unit tests.
  module Usage
    # Rack env key the middleware exposes the request's `Charge` under.
    CHARGE_ENV_KEY = "pay_kit.usage.charge"

    # Meters consumption for a single upto authorization. `charge` accumulates
    # metered base units, clamped to `[0, max]` so a handler can never settle
    # above the signed ceiling. Mirrors the Go `Charge` test helper.
    class Charge
      attr_reader :max_base_units

      def initialize(max_base_units)
        @max_base_units = max_base_units
        @settled = 0
      end

      # Record the actual metered amount, replacing any prior value; clamped to
      # [0, max] so a handler can never settle above the ceiling. Last call wins,
      # mirroring the Go/Python/TS Charge.
      def charge(amount)
        @settled = amount.to_i.clamp(0, @max_base_units)
      end

      # The clamped amount to settle on-chain.
      def settled_base_units
        @settled
      end
    end

    module_function

    # Fail-closed finalize policy: a zero settled charge yields no resource.
    def deliver?(settled_base_units)
      settled_base_units.positive?
    end

    # Rack middleware that gates a single resource path behind an x402 `upto`
    # authorization. On the protected path it returns a 402 upto challenge when
    # no credential is present, otherwise it verifies + broadcasts the channel
    # open, runs the wrapped app (which meters into the request's `Charge`),
    # then settles the metered actual amount and either returns the buffered
    # response with settlement headers (nonzero) or fail-closes with a 402
    # (zero).
    class Middleware
      Constants = ::PayKit::Protocols::X402::Constants
      UptoTypes = ::PayKit::Protocols::X402::Protocol::Schemes::Upto

      def initialize(app, engine:, resource_path:, settlement_header: nil)
        @app = app
        @engine = engine
        @resource_path = resource_path
        @settlement_header = settlement_header
      end

      def call(env)
        request = ::Rack::Request.new(env)
        return @app.call(env) unless request.path == @resource_path

        header = payment_header(env)
        return challenge(env) if header.nil? || header.empty?

        # Phase 3 (before the resource): nothing was served and nothing
        # settled, so a 402 re-challenge is the correct response to a failure.
        begin
          open = @engine.verify_open(header)
        rescue => error
          return challenge(env, error: error.message)
        end

        charge = Charge.new(open.max_amount)
        env[CHARGE_ENV_KEY] = charge

        # The channel is now open and reserved. If the protected app raises
        # before settlement runs, settle a zero charge to close the channel and
        # refund the payer's full deposit — which also releases the in-flight
        # reservation — then re-raise so the app's error surfaces. Without this
        # the reservation would leak and the payer's deposit would stay locked.
        begin
          status, headers, body = @app.call(env)
        rescue => app_error
          release_after_app_failure(open)
          raise app_error
        end
        settled = charge.settled_base_units

        # Phase 4 (after the resource): settlement may broadcast on-chain, so a
        # failure here must NOT tell the client to pay again — that risks a
        # double charge if the settle transaction later lands. It is a server
        # error, and the buffered resource body is dropped (and closed).
        begin
          settlement = @engine.settle_actual(open, settled)
        rescue => error
          close_body(body)
          return settle_error(error)
        end

        # Fail-closed on a zero charge: the channel still settled 0 on-chain
        # (closed, full refund), but no resource body is delivered.
        unless Usage.deliver?(settled)
          close_body(body)
          return challenge(env)
        end

        [status, settlement_headers(headers, settlement), body]
      end

      private

      def payment_header(env)
        env["HTTP_" + Constants::PAYMENT_SIGNATURE_HEADER.upcase.tr("-", "_")] ||
          env["HTTP_X_PAYMENT"]
      end

      # Close a Rack body we are about to drop so streaming/file/BodyProxy
      # bodies do not leak their underlying resources.
      def close_body(body)
        body.close if body.respond_to?(:close)
      end

      # The protected app raised after the channel opened. Settle a zero charge
      # to close the channel and refund the payer; `settle_actual` releases the
      # in-flight reservation in its own ensure even when the settle broadcast
      # fails. If that compensating settlement fails the channel may still be
      # open on-chain with the payer's deposit locked, and `release!` only clears
      # the in-memory reservation — so log loudly with the channel id (operators
      # must reconcile/refund it manually) instead of swallowing the failure.
      def release_after_app_failure(open)
        @engine.settle_actual(open, 0)
      rescue => settle_error
        open.release! if open.respond_to?(:release!)
        log_orphaned_channel(open, settle_error)
      end

      # Loud, actionable warning when a compensating zero settlement fails and a
      # channel may be stranded on-chain. Uses the PayKit logger convention so it
      # lands alongside the rest of the application log.
      def log_orphaned_channel(open, error)
        channel_id = open.respond_to?(:channel_id) ? open.channel_id : "unknown"
        logger.warn(
          "x402 upto: compensating zero settlement failed for channel #{channel_id}; " \
          "the channel may remain open on-chain with the payer deposit locked and needs manual reconciliation " \
          "(#{error.class}: #{error.message})"
        )
      end

      def logger
        ::PayKit.logger || (@default_logger ||= ::Logger.new($stderr).tap do |log|
          log.formatter = proc { |_severity, _datetime, _progname, msg| "[PayKit] WARN: #{msg}\n" }
        end)
      end

      # A post-resource settlement failure: report a server error, never a 402,
      # so the client is not told to retry a payment that may already be
      # settling on-chain.
      def settle_error(error)
        [
          502,
          {"content-type" => "application/json"},
          [JSON.generate({"error" => "settlement_failed", "message" => error.message})]
        ]
      end

      def settlement_headers(headers, settlement)
        result = headers.dup
        result[Constants::PAYMENT_RESPONSE_HEADER] = UptoTypes.encode_settlement_response(settlement)
        result[@settlement_header] = settlement["transaction"] if @settlement_header && !@settlement_header.empty?
        result
      end

      def challenge(env, error: nil)
        body = {"error" => "payment_required"}
        body["invalidReason"] = error unless error.nil?
        [
          402,
          {
            Constants::PAYMENT_REQUIRED_HEADER => @engine.payment_required(resource: @resource_path),
            "content-type" => "application/json"
          },
          [JSON.generate(body)]
        ]
      end
    end
  end
end
