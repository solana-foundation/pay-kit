# frozen_string_literal: true

require "bigdecimal"

require_relative "../errors"
require_relative "../challenge"
require_relative "../../mpp"

module PayKit
  module Protocols
    # MPP adapter. Wraps `::Mpp::Server::Charge` for charge intent.
    # The class-level `.charge` callable returns a frozen `ProtocolRef`
    # so gates can opt in explicitly: `accept: PayKit::Protocols::MPP.charge`.
    class MPP
      CHARGE_REF = ProtocolRef.new(protocol: :mpp, scheme: :charge).freeze
      def self.charge = CHARGE_REF

      # `server_for` is a `->(gate) { Mpp::Server::Charge }` callback
      # supplied by the dispatcher. The dispatcher owns a per-recipient
      # MPP method cache so different gates (different `gate.pay_to`)
      # route to different servers without rebuilding `Mpp.create` per
      # request. The legacy fixed-server form (`server: ...`) is kept
      # for tests that fake the server.
      def initialize(server_for: nil, server: nil)
        raise ArgumentError, "MPP adapter needs server_for: or server:" if server_for.nil? && server.nil?

        @server_for = server_for
        @fixed_server = server
        freeze
      end

      def detect?(request)
        header_value(request, "Authorization")&.start_with?("Payment ")
      end

      # MPP doesn't expose a single `accepts_entry` Hash like x402,
      # because the WWW-Authenticate header IS the challenge. We
      # surface a minimal entry for the 402 body so the client can
      # see both protocols listed; the real challenge ships in headers.
      def accepts_entry(gate, _request)
        amount_units = to_smallest_units(gate.total)
        {
          protocol: "mpp",
          scheme: "charge",
          amount: amount_units,
          currency: gate.amount.primary_coin.to_s,
          payTo: gate.pay_to,
          splits: splits_for(gate, amount_units)
        }
      end

      def challenge_headers(gate, request)
        result = perform(gate, request, authorization: nil)
        return {} unless result.is_a?(::Mpp::Challenge)

        result.headers
      end

      def verify_and_settle(gate, request)
        authorization = header_value(request, "Authorization")
        result = perform(gate, request, authorization: authorization)

        case result
        when ::Mpp::Settlement
          Payment.new(
            protocol: :mpp,
            scheme: :charge,
            transaction: result.signature,
            settlement_headers: result.headers || {},
            raw: authorization
          )
        when ::Mpp::Challenge
          spec_code = result.body.is_a?(Hash) ? result.body["code"] : nil
          raise InvalidProof.new(:payment_required, result.reason || "payment required", spec_code: spec_code)
        else
          raise InvalidProof.new(:payment_invalid, "unexpected MPP response: #{result.class}")
        end
      end

      private

      def perform(gate, _request, authorization:)
        amount_units = to_smallest_units(gate.total)
        server_for(gate).charge(
          authorization,
          amount: amount_units,
          description: gate.description,
          external_id: gate.external_id,
          splits: splits_for(gate, amount_units)
        )
      rescue ::Mpp::Error => e
        raise InvalidProof.new(:payment_invalid, e.message)
      end

      def server_for(gate)
        return @fixed_server if @fixed_server
        @server_for.call(gate)
      end

      # Build the MPP `splits[]` field for the on-chain charge intent.
      # The MPP verifier treats splits as the FEE-ONLY list and computes
      # `primary = request.amount - sum(splits.amount)`, then matches a
      # transfer of `primary` to `request.recipient` (the gate's
      # `pay_to`). Including the primary recipient inside `splits[]`
      # would double-count the principal and fail verification with
      # "split amounts exceed total amount". See
      # `lib/mpp/protocol/solana/verifier.rb` lines 75-87.
      def splits_for(gate, _total_units)
        return nil unless gate.fees?

        gate.fees.map do |fee|
          {"recipient" => fee.recipient, "amount" => to_smallest_units(fee.price).to_s}
        end
      end

      # Convert a Price (decimal string like "0.10") into the SPL
      # smallest-units integer assuming 6-decimal USDC/USDT/EURC.
      # MPP currently uses fixed 6 decimals for stablecoin charges
      # (mirrors `Mpp::Protocol::Solana` defaults).
      def to_smallest_units(price)
        whole, _, fraction = price.amount.partition(".")
        fraction = fraction.ljust(6, "0")[0, 6]
        (Integer(whole, 10) * 1_000_000) + Integer(fraction.empty? ? "0" : fraction, 10)
      end

      def header_value(request, name)
        rack_key = "HTTP_" + name.upcase.tr("-", "_")
        request.env[rack_key] || request.env[name]
      end
    end
  end
end
