# frozen_string_literal: true

require_relative "test_helper"
require "rack/mock"

class ExampleTest < Minitest::Test
  include RubyMppTestHelpers

  def test_sinatra_example_loads_and_exposes_health_route
    with_env(
      "PAY_KIT_PAY_TO" => pubkey(2),
      "PAY_KIT_MPP_SECRET" => "test-secret"
    ) do
      require_relative "../examples/sinatra/app"

      response = Rack::MockRequest.new(SinatraExample).get("/health")

      assert_equal 200, response.status
      assert_equal({"ok" => true}, JSON.parse(response.body))
    end
  end

  private

  def with_env(values)
    previous = values.to_h { |key, _value| [key, ENV[key]] }
    values.each { |key, value| ENV[key] = value }
    yield
  ensure
    previous.each do |key, value|
      value.nil? ? ENV.delete(key) : ENV[key] = value
    end
  end
end
