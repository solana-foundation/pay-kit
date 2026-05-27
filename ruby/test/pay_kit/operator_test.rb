# frozen_string_literal: true

require_relative "test_helper"

class PayKitOperatorTest < Minitest::Test
  # 64-byte non-demo keypair for tests that need a non-default signer.
  RAW_BYTES = (1..64).to_a.freeze
  RAW_PUBKEY = PayCore::Solana::Account.new(RAW_BYTES.dup).public_key.to_s
  EXPLICIT_RECIPIENT = "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP"

  # --- defaults --------------------------------------------------------

  def test_default_operator_uses_demo_signer_and_fee_payer_true
    op = PayKit::Operator.new
    assert_equal PayKit::Signer::Demo::PUBKEY, op.signer.pubkey
    assert op.signer.demo?
    assert op.fee_payer?
    assert_nil op.recipient
  end

  def test_effective_recipient_defaults_to_signer_pubkey
    op = PayKit::Operator.new
    assert_equal PayKit::Signer::Demo::PUBKEY, op.effective_recipient
  end

  def test_effective_recipient_uses_explicit_recipient_when_set
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT)
    assert_equal EXPLICIT_RECIPIENT, op.effective_recipient
  end

  def test_explicit_signer_replaces_demo
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    op = PayKit::Operator.new(signer: signer)
    assert_equal RAW_PUBKEY, op.signer.pubkey
    refute op.signer.demo?
    assert_equal RAW_PUBKEY, op.effective_recipient
  end

  def test_explicit_fee_payer_false_is_honored
    op = PayKit::Operator.new(fee_payer: false)
    refute op.fee_payer?
    assert_equal false, op.fee_payer
  end

  # --- construction forms ---------------------------------------------

  def test_block_form_sets_each_field
    op = PayKit::Operator.new do |o|
      o.recipient = EXPLICIT_RECIPIENT
      o.signer = PayKit::Signer.bytes(RAW_BYTES.dup)
      o.fee_payer = false
    end
    assert_equal EXPLICIT_RECIPIENT, op.recipient
    assert_equal RAW_PUBKEY, op.signer.pubkey
    refute op.fee_payer?
  end

  def test_kwargs_and_block_compose
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT) do |o|
      o.fee_payer = false
    end
    assert_equal EXPLICIT_RECIPIENT, op.recipient
    refute op.fee_payer?
  end

  # --- nil-as-no-op setters -------------------------------------------

  def test_recipient_setter_ignores_nil
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT)
    op.recipient = nil
    assert_equal EXPLICIT_RECIPIENT, op.recipient
  end

  def test_signer_setter_ignores_nil
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    op = PayKit::Operator.new(signer: signer)
    op.signer = nil
    assert_equal RAW_PUBKEY, op.signer.pubkey
  end

  def test_fee_payer_setter_ignores_nil
    op = PayKit::Operator.new(fee_payer: false)
    op.fee_payer = nil
    refute op.fee_payer?
  end

  def test_env_driven_no_op_pattern
    # Simulates the canonical env-driven configure block. Unset env vars
    # resolve to nil and must leave the defaults untouched.
    op = PayKit::Operator.new do |o|
      o.recipient = ENV["PAY_KIT_OPERATOR_TEST_NEVER_SET"]
      o.signer = PayKit::Signer.env("PAY_KIT_OPERATOR_TEST_NEVER_SET")
    end
    assert_equal PayKit::Signer::Demo::PUBKEY, op.signer.pubkey
    assert_equal PayKit::Signer::Demo::PUBKEY, op.effective_recipient
  end

  # --- reset! ----------------------------------------------------------

  def test_reset_recipient_clears_to_nil
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT)
    op.reset!(:recipient)
    assert_nil op.recipient
    assert_equal PayKit::Signer::Demo::PUBKEY, op.effective_recipient
  end

  def test_reset_signer_restores_demo
    op = PayKit::Operator.new(signer: PayKit::Signer.bytes(RAW_BYTES.dup))
    op.reset!(:signer)
    assert_equal PayKit::Signer::Demo::PUBKEY, op.signer.pubkey
    assert op.signer.demo?
  end

  def test_reset_fee_payer_returns_to_true
    op = PayKit::Operator.new(fee_payer: false)
    op.reset!(:fee_payer)
    assert op.fee_payer?
  end

  def test_reset_unknown_field_raises_argument_error
    op = PayKit::Operator.new
    assert_raises(ArgumentError) { op.reset!(:not_a_field) }
  end

  def test_reset_returns_self_for_chaining
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT, fee_payer: false)
    op.reset!(:recipient).reset!(:fee_payer)
    assert_nil op.recipient
    assert op.fee_payer?
  end

  # --- validation ------------------------------------------------------

  def test_recipient_setter_rejects_non_string
    op = PayKit::Operator.new
    assert_raises(PayKit::ConfigurationError) { op.recipient = 123 }
    assert_raises(PayKit::ConfigurationError) { op.recipient = :a_symbol }
    assert_raises(PayKit::ConfigurationError) { op.recipient = ["array"] }
  end

  def test_signer_setter_rejects_non_signer_like
    op = PayKit::Operator.new
    assert_raises(PayKit::ConfigurationError) { op.signer = "not a signer" }
    assert_raises(PayKit::ConfigurationError) { op.signer = Object.new }
    assert_raises(PayKit::ConfigurationError) { op.signer = 42 }
  end

  def test_signer_setter_accepts_duck_typed_object
    fake_signer = Object.new
    def fake_signer.pubkey
      "fake-pubkey"
    end

    def fake_signer.sign(_msg)
      "x" * 64
    end

    def fake_signer.fee_payer?
      true
    end

    op = PayKit::Operator.new
    op.signer = fake_signer
    assert_equal "fake-pubkey", op.signer.pubkey
  end

  def test_fee_payer_setter_rejects_truthy_coercions
    op = PayKit::Operator.new
    assert_raises(PayKit::ConfigurationError) { op.fee_payer = "yes" }
    assert_raises(PayKit::ConfigurationError) { op.fee_payer = 1 }
    assert_raises(PayKit::ConfigurationError) { op.fee_payer = 0 }
    assert_raises(PayKit::ConfigurationError) { op.fee_payer = "true" }
  end

  def test_fee_payer_setter_accepts_only_strict_booleans
    op = PayKit::Operator.new
    op.fee_payer = false
    refute op.fee_payer?
    op.fee_payer = true
    assert op.fee_payer?
  end

  # --- equality + hashing ---------------------------------------------

  def test_two_operators_with_same_resolved_fields_are_equal
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    a = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT, signer: signer, fee_payer: true)
    b = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT, signer: signer, fee_payer: true)
    assert_equal a, b
    assert_equal a.hash, b.hash
  end

  def test_operator_with_default_recipient_equals_explicit_at_signer_pubkey
    # When `recipient` is nil, `effective_recipient == signer.pubkey`,
    # so an Operator with nil recipient is equal to one whose recipient
    # was set to the same pubkey.
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    implicit = PayKit::Operator.new(signer: signer)
    explicit = PayKit::Operator.new(signer: signer, recipient: RAW_PUBKEY)
    assert_equal implicit, explicit
  end

  def test_operators_with_different_fee_payer_are_not_equal
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    a = PayKit::Operator.new(signer: signer, fee_payer: true)
    b = PayKit::Operator.new(signer: signer, fee_payer: false)
    refute_equal a, b
  end

  # --- to_h ------------------------------------------------------------

  def test_to_h_summary
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    op = PayKit::Operator.new(recipient: EXPLICIT_RECIPIENT, signer: signer, fee_payer: true)
    h = op.to_h
    assert_equal EXPLICIT_RECIPIENT, h[:recipient]
    assert_equal RAW_PUBKEY, h[:signer_pubkey]
    assert_equal "PayKit::Signer::Local", h[:signer_class]
    assert_equal true, h[:fee_payer]
  end
end
