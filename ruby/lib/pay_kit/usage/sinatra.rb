# frozen_string_literal: true

require "sinatra/base"

require_relative "../usage"

module PayKit
  module Usage
    # Sinatra integration for the x402 `upto` usage gate. Register the
    # extension and call `require_usage` to mount the settle-after middleware,
    # then read the per-request `Charge` with the `usage_charge` helper:
    #
    #   class App < Sinatra::Base
    #     register PayKit::Usage::Sinatra
    #     require_usage engine: engine, resource_path: "/usage",
    #       settlement_header: "x-payment-settlement-signature"
    #
    #     get "/usage" do
    #       usage_charge.charge(metered_base_units)
    #       json(ok: true)
    #     end
    #   end
    #
    # The middleware verifies + broadcasts the channel open before the route
    # runs, then settles the metered amount after it returns.
    module Sinatra
      # Mount the upto usage middleware in front of the app's routes.
      def require_usage(engine:, resource_path:, settlement_header: nil)
        use ::PayKit::Usage::Middleware,
          engine: engine,
          resource_path: resource_path,
          settlement_header: settlement_header
      end

      # Per-request helpers available inside routes.
      module Helpers
        # The `Charge` meter for the in-flight upto authorization, or nil when
        # the current route is not gated by `require_usage`.
        def usage_charge
          request.env[::PayKit::Usage::CHARGE_ENV_KEY]
        end
      end

      def self.registered(app)
        app.helpers(Helpers)
      end
    end
  end
end
