# frozen_string_literal: true

# Load all _test.rb files except the load-order suite, which runs in
# fresh subprocesses (it depends on Ruby's require state being clean).
# The load-order tests are driven from test/pay_kit/load_order_test.rb.
Dir[File.join(__dir__, "**/*_test.rb")].sort.each do |path|
  next if path.include?("/load_order/")

  require path
end
