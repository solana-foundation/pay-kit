# frozen_string_literal: true

require "base64"

require_relative "../test_helper"

class RpcGetAccountInfoTest < Minitest::Test
  def setup
    @rpc = ::PayCore::Solana::Rpc.new("http://localhost:8899")
  end

  def test_decodes_base64_account_data
    raw = "\x01\x02\x03\x04".b
    value = {"value" => {"data" => [Base64.strict_encode64(raw), "base64"], "owner" => "Owner111", "lamports" => 4_242}}

    @rpc.stub(:call, value) do
      info = @rpc.get_account_info("Acct111")
      assert_equal raw, info[:data]
      assert_equal "Owner111", info[:owner]
      assert_equal 4_242, info[:lamports]
    end
  end

  def test_returns_nil_when_account_missing
    @rpc.stub(:call, {"value" => nil}) do
      assert_nil @rpc.get_account_info("Acct111")
    end
  end

  def test_handles_empty_data
    @rpc.stub(:call, {"value" => {"data" => ["", "base64"], "owner" => "Owner111"}}) do
      info = @rpc.get_account_info("Acct111")
      assert_equal "".b, info[:data]
    end
  end

  def test_handles_missing_data_key
    @rpc.stub(:call, {"value" => {"owner" => "Owner111"}}) do
      assert_equal "".b, @rpc.get_account_info("Acct111")[:data]
    end
  end

  def test_handles_string_data
    raw = "\x09\x08".b
    @rpc.stub(:call, {"value" => {"data" => Base64.strict_encode64(raw), "owner" => "Owner111"}}) do
      assert_equal raw, @rpc.get_account_info("Acct111")[:data]
    end
  end
end
