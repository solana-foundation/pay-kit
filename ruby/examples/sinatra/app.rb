# frozen_string_literal: true

require "json"
require "sinatra/base"
require_relative "server"
require_relative "../../lib/mpp/sinatra"

# Sinatra app with one MPP-protected endpoint.
#
#   GET /health  -> free, returns {"ok": true}
#   GET /paid    -> gated by mpp_charge!. The helper inspects the
#                   Authorization: Payment header, halts with a 402 if no
#                   valid credential was supplied, and otherwise injects the
#                   receipt + signature headers so the route can render any
#                   body it likes.
class RubyMppSinatraExample < Sinatra::Base
  helpers Mpp::Sinatra::Helpers

  set :bind, SinatraExample::Config.host
  set :port, SinatraExample::Config.port
  set :show_exceptions, false
  set :mpp_server, SinatraExample.server

  get "/health" do
    content_type :json
    JSON.generate(ok: true)
  end

  get "/paid" do
    mpp_charge!(amount: SinatraExample::Config.amount, description: "Paid endpoint")
    content_type :json
    JSON.generate(ok: true, message: "thanks for paying!")
  end

  run! if app_file == $PROGRAM_NAME
end
