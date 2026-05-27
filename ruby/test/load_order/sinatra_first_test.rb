# frozen_string_literal: true

# Standalone load-order test A: Sinatra loaded BEFORE solana_pay_kit.
# Runs as its own Ruby process so it can verify the require ordering
# from a clean Ruby state - the main test suite already has the gem
# fully loaded.
#
# Spawned by test/load_order/run.rb; not picked up by the normal
# test/run.rb glob.

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))

require "minitest/autorun"

class SinatraFirstLoadOrderTest < Minitest::Test
  def test_sinatra_helpers_and_middleware_register_when_sinatra_loaded_first
    require "sinatra/base"
    require "solana_pay_kit"

    assert ::PayKit::SinatraAutoRegister.registered?,
      "SinatraAutoRegister should fire immediately when Sinatra is already loaded"

    app = Class.new(::Sinatra::Base)
    assert_includes app.instance_method(:require_payment!).owner.ancestors.map(&:name),
      "PayKit::Sinatra",
      "Sinatra::Base subclasses must inherit the PayKit::Sinatra helpers"

    middleware_classes = ::Sinatra::Base.middleware.map { |entry| entry[0] }
    assert_includes middleware_classes, ::PayKit::Rack::PaymentRequired,
      "Sinatra::Base middleware list must include PayKit::Rack::PaymentRequired"
  end
end
