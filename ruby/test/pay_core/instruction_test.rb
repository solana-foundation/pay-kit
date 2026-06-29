# frozen_string_literal: true

require_relative "../test_helper"

class InstructionTest < Minitest::Test
  AM = ::PayCore::Solana::AccountMeta
  PI = ::PayCore::Solana::PreparedInstruction

  def test_account_meta_factories
    assert_equal [true, true], role(AM.signer_writable("k"))
    assert_equal [true, false], role(AM.signer_readonly("k"))
    assert_equal [false, true], role(AM.writable("k"))
    assert_equal [false, false], role(AM.readonly("k"))
  end

  def test_account_meta_carries_pubkey
    meta = AM.writable("SomeKey")
    assert_equal "SomeKey", meta.pubkey
  end

  def test_prepared_instruction_fields
    accounts = [AM.writable("a")]
    ix = PI.new("program", accounts, "data".b)

    assert_equal "program", ix.program_id
    assert_equal accounts, ix.accounts
    assert_equal "data".b, ix.data
  end

  private

  def role(meta)
    [meta.signer, meta.writable]
  end
end
