# frozen_string_literal: true

# Canonical entry point for the `solana-pay-kit` gem. Matches the gem
# name (`gem install solana-pay-kit`, `require "solana_pay_kit"`).
#
# Loads the protocol layers and the high-level `PayKit` umbrella.
# Framework shims (`PayKit::Sinatra`, `PayKit::Controller`) are
# opt-in via their own requires - this file does NOT auto-detect
# Sinatra or Rails.
require_relative "pay_kit"
