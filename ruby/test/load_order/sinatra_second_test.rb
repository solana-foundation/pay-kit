# frozen_string_literal: true

# Standalone load-order test B: solana_pay_kit loaded BEFORE Sinatra.
# Verifies the TracePoint-driven late-binding path fires once Sinatra
# arrives later.

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "minitest/autorun"

class SinatraSecondLoadOrderTest < Minitest::Test
  def test_sinatra_helpers_and_middleware_register_when_sinatra_loaded_second
    require "solana_pay_kit"
    refute ::PayKit::SinatraAutoRegister.registered?,
      "AutoRegister must wait for Sinatra to load before firing"

    require "sinatra/base"
    assert ::PayKit::SinatraAutoRegister.registered?,
      "AutoRegister should fire via TracePoint when Sinatra::Base appears later"

    app = Class.new(::Sinatra::Base)
    assert_includes app.instance_method(:require_payment!).owner.ancestors.map(&:name),
      "PayKit::Sinatra"

    middleware_classes = ::Sinatra::Base.middleware.map { |entry| entry[0] }
    assert_includes middleware_classes, ::PayKit::Rack::PaymentRequired
  end
end
