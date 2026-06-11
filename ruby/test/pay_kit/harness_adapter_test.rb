# frozen_string_literal: true

require_relative "test_helper"
require "open3"
require "socket"
require "net/http"
require "timeout"

# Drives `harness/ruby-server/server.rb` as a subprocess to prove the
# dual-protocol adapter boots correctly under both env namespaces.
# Full settlement (RPC + chain) is exercised by the cross-language
# harness matrix in CI; this test pins the adapter's boot contract and
# the 402 challenge shape so a regression in the harness adapter is
# caught at the gem-test level.
class PayKitHarnessAdapterTest < Minitest::Test
  ADAPTER = File.expand_path("../../../harness/ruby-server/server.rb", __dir__)

  COMMON_ENV = {
    "PAY_TO" => "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj",
    "MINT" => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
  }

  def test_x402_mode_ready_payload_and_health
    with_adapter(x402_env) do |port|
      assert_equal "ok", Net::HTTP.get(URI("http://127.0.0.1:#{port}/health")).then { |b| JSON.parse(b)["ok"] ? "ok" : "no" }

      # Unpaid /paid returns 402 with PAYMENT-REQUIRED header (x402 v2).
      response = Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/paid"))
      assert_equal "402", response.code
      assert response["payment-required"], "PAYMENT-REQUIRED header missing"

      body = JSON.parse(response.body)
      assert_equal "payment_required", body["error"]
      assert_equal "/paid", body["resource"]
      entry = body["accepts"].first
      assert_equal "exact", entry["scheme"]
      assert_equal "x402", entry["protocol"]
      assert_equal COMMON_ENV["MINT"], entry["asset"]
    end
  end

  def test_mpp_mode_ready_payload_and_health
    with_adapter(mpp_env) do |port|
      assert_equal true, JSON.parse(Net::HTTP.get(URI("http://127.0.0.1:#{port}/health")))["ok"]
    end
  end

  def test_dual_env_set_is_rejected
    env = mpp_env.merge(x402_env)
    _, stderr, status = Open3.capture3(env, "ruby", "-I", lib_path, ADAPTER)
    refute status.success?
    assert_match(/set exactly one/i, stderr)
  end

  def test_no_env_set_is_rejected
    _, stderr, status = Open3.capture3({}, "ruby", "-I", lib_path, ADAPTER)
    refute status.success?
    assert_match(/set exactly one/i, stderr)
  end

  private

  def x402_env
    {
      "X402_HARNESS_RPC_URL" => "http://127.0.0.1:8899",
      "X402_HARNESS_PAY_TO" => COMMON_ENV["PAY_TO"],
      "X402_HARNESS_MINT" => COMMON_ENV["MINT"],
      "X402_HARNESS_FACILITATOR_SECRET_KEY" => JSON.generate((0..63).to_a)
    }
  end

  def mpp_env
    {
      "MPP_HARNESS_RPC_URL" => "http://127.0.0.1:8899",
      "MPP_HARNESS_PAY_TO" => COMMON_ENV["PAY_TO"],
      "MPP_HARNESS_MINT" => COMMON_ENV["MINT"],
      "MPP_HARNESS_AMOUNT" => "100000"
    }
  end

  def lib_path
    File.expand_path("../../lib", __dir__)
  end

  def with_adapter(env)
    stdin, stdout, stderr, wait = Open3.popen3(env, "ruby", "-I", lib_path, ADAPTER)
    stdin.close

    ready_line = Timeout.timeout(8) { stdout.gets }
    assert ready_line, "adapter did not emit ready line"
    ready = JSON.parse(ready_line)
    assert_equal "ready", ready["type"]
    assert_equal "ruby", ready["implementation"]
    port = ready["port"]
    assert_kind_of Integer, port

    yield port
  ensure
    begin
      Process.kill("TERM", wait.pid) if wait&.alive?
    rescue Errno::ESRCH
      nil
    end
    wait&.value
    stdout&.close
    stderr&.close
  end
end
