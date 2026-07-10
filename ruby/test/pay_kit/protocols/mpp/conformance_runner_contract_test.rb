# frozen_string_literal: true

require_relative "../../../test_helper"

require "json"
require "open3"
require "rbconfig"

class ConformanceRunnerContractTest < Minitest::Test
  CONFORMANCE_RUNNER = File.expand_path("../../../../exe/conformance", __dir__)

  def test_result_identifies_the_ruby_implementation
    result = run_vector(JSON.generate({
      "id" => "ruby-runner-identity",
      "intent" => "charge",
      "mode" => "canonical-bytes",
      "input" => {"value" => {"a" => 1}}
    }))

    assert_equal "ruby", result.fetch("language")
    assert_equal "accept", result.fetch("outcome")
  end

  def test_lone_surrogate_is_a_structured_reject
    raw = '{"id":"ruby-lone-surrogate","intent":"charge","mode":"canonical-bytes",' \
      '"input":{"value":{"bad":"\ud800"}},"expect":{"outcome":"reject"}}'

    result = run_vector(raw)

    assert_equal "ruby", result.fetch("language")
    assert_equal "reject", result.fetch("outcome")
    assert_match(/surrogate/i, result.fetch("error"))
  end

  private

  def run_vector(raw)
    output, error, status = Open3.capture3(
      RbConfig.ruby,
      CONFORMANCE_RUNNER,
      stdin_data: raw
    )
    assert status.success?, error
    JSON.parse(output)
  end
end
