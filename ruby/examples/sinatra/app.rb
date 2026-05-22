# frozen_string_literal: true

require "json"
require "sinatra/base"
require_relative "mpp"

# Sinatra app with one MPP-protected endpoint.
#
#   GET /health  -> free, returns {"ok": true}
#   GET /paid    -> gated by Mpp::Server::RackMiddleware (handles 402,
#                   verifies the Payment credential, settles on-chain, and
#                   emits the receipt header — all in the middleware layer).
class RubyMppSinatraExample < Sinatra::Base
  set :bind,            SinatraExample::Config.host
  set :port,            SinatraExample::Config.port
  set :show_exceptions, false

  use Mpp::Server::RackMiddleware,
      handler: SinatraExample::Charge.handler,
      request: ->(_env) { SinatraExample::Charge.charge_request },
      path:    "/paid"

  get "/health" do
    content_type :json
    JSON.generate(ok: true)
  end

  run! if app_file == $PROGRAM_NAME
end
