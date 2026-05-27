# frozen_string_literal: true

require_relative "test_helper"
require "open3"

# Driver that spawns the two standalone load-order suites in fresh
# Ruby processes. Both orderings must produce a registered Sinatra
# helper + middleware — see DESIGN.md: "a single require is enough".
class PayKitLoadOrderTest < Minitest::Test
  LOAD_ORDER_DIR = File.expand_path("../load_order", __dir__)

  def test_sinatra_loaded_first_then_solana_pay_kit
    run_subprocess_test!("sinatra_first_test.rb")
  end

  def test_solana_pay_kit_loaded_first_then_sinatra
    run_subprocess_test!("sinatra_second_test.rb")
  end

  private

  def run_subprocess_test!(filename)
    path = File.join(LOAD_ORDER_DIR, filename)
    cmd = ["bundle", "exec", "ruby", path]
    stdout, stderr, status = Open3.capture3(*cmd, chdir: File.expand_path("../..", __dir__))

    unless status.success?
      flunk("load-order subprocess failed: #{filename}\n" \
            "stdout:\n#{stdout}\nstderr:\n#{stderr}")
    end

    refute_match(/failures, [^0]/, stdout, "subprocess reported failures: #{stdout}")
    refute_match(/errors, [^0]/, stdout, "subprocess reported errors: #{stdout}")
  end
end
