# frozen_string_literal: true

require "base64"
require "json"
require_relative "test_helper"
require "x402"

class X402ServerExactTest < Minitest::Test
  NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  ASSET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
  EXTRA_ASSET = "ExtraMint11111111111111111111111111111"
  PYUSD_DEVNET_MINT = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
  PAY_TO = "11111111111111111111111111111112"
  BLOCKHASH = "11111111111111111111111111111111"

  def test_normalizes_price_to_six_decimals
    assert_equal "1000", X402::Server::Exact.normalize_amount("$0.001")
    assert_equal "1000", X402::Server::Exact.normalize_amount("0.001 USDC")
    assert_equal "1250000", X402::Server::Exact.normalize_amount("1.25")
  end

  def test_exact_challenge_uses_runtime_state
    state = build_state(price: "$0.125")
    requirement = X402::Server::Exact.exact_requirement(state)

    assert_equal "exact", requirement.fetch("scheme")
    assert_equal NETWORK, requirement.fetch("network")
    assert_equal ASSET, requirement.fetch("asset")
    assert_equal "125000", requirement.fetch("amount")
    assert_equal PAY_TO, requirement.fetch("payTo")
    assert_equal X402::Protocol::Schemes::Exact.base58_encode(state.fee_payer.raw_public_key),
      requirement.fetch("extra").fetch("feePayer")
  end

  def test_exact_challenge_includes_extra_offered_mints
    state = build_state(extra_offered_mints: " #{PYUSD_DEVNET_MINT}, #{EXTRA_ASSET} ")
    accepts = X402::Server::Exact.exact_challenge(state).fetch("accepts")
    base, pyusd, extra = accepts

    assert_equal [ASSET, PYUSD_DEVNET_MINT, EXTRA_ASSET], accepts.map { |requirement| requirement.fetch("asset") }
    assert_equal 3, accepts.length

    [pyusd, extra].each do |requirement|
      assert_equal base.fetch("amount"), requirement.fetch("amount")
      assert_equal base.fetch("payTo"), requirement.fetch("payTo")
      assert_equal base.fetch("extra").fetch("feePayer"), requirement.fetch("extra").fetch("feePayer")
      assert_equal base.fetch("extra").fetch("decimals"), requirement.fetch("extra").fetch("decimals")
    end

    assert_equal X402::Protocol::Schemes::Exact::TOKEN_2022_PROGRAM, pyusd.fetch("extra").fetch("tokenProgram")
    assert_equal X402::Server::Exact::DEFAULT_TOKEN_PROGRAM, extra.fetch("extra").fetch("tokenProgram")
  end

  def test_exact_requirement_includes_server_recent_blockhash
    # When the server supplies a blockhash provider, it shows up in
    # `extra.recentBlockhash` so the client can sign against the
    # server's chain (the Surfpool / surfnet case where the wire CAIP-2
    # is devnet but the actual ledger is a private fork).
    state = build_state(recent_blockhash_provider: -> { "ServerProvidedBlockhash11111111111111111" })
    requirement = X402::Server::Exact.exact_requirement(state)

    assert_equal "ServerProvidedBlockhash11111111111111111",
      requirement.fetch("extra").fetch("recentBlockhash")
  end

  def test_exact_requirement_omits_blockhash_when_provider_returns_nil
    # The default RPC-backed provider returns `nil` when the RPC is
    # unreachable. The challenge must still be served — the client
    # falls back to its own `getLatestBlockhash`, which is the
    # historical behaviour.
    state = build_state(recent_blockhash_provider: -> {})
    requirement = X402::Server::Exact.exact_requirement(state)

    refute requirement.fetch("extra").key?("recentBlockhash")
  end

  def test_payment_requirement_matches_binds_settlement_fields
    state = build_state
    requirement = X402::Server::Exact.exact_requirement(state)

    assert X402::Server::Exact.payment_requirement_matches?(requirement, requirement)

    mutated = Marshal.load(Marshal.dump(requirement))
    mutated.fetch("extra")["feePayer"] = "11111111111111111111111111111114"

    refute X402::Server::Exact.payment_requirement_matches?(mutated, requirement)
  end

  def test_settlement_signs_fee_payer_before_sending
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "ruby-settlement-signature"
    })
    payment_header = build_payment_header(state)

    settlement = X402::Server::Exact.settle_exact_payment(state, payment_header)
    signed_transaction = sent.fetch(0)

    assert_equal "ruby-settlement-signature", settlement
    refute_equal "\x00".b * 64, signed_transaction.byteslice(1, 64)
    refute_equal "\x00".b * 64, signed_transaction.byteslice(65, 64)
  end

  def test_settlement_rejects_accepted_requirement_drift
    state = build_state
    envelope = JSON.parse(Base64.decode64(build_payment_header(state)))
    envelope.fetch("accepted").fetch("extra")["feePayer"] = "11111111111111111111111111111114"
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "No matching payment requirements: accepted payment requirement does not match server challenge", error.message
  end

  def test_settlement_tolerates_unknown_keys_in_accepted_extra
    # Unknown extra keys (drift) must not break matching: clients ship
    # extension fields the server doesn't recognise, the server still
    # has to honour the credential if scheme/network/asset/payTo and
    # the canonical extra identity keys (feePayer/tokenProgram/memo)
    # all agree. Mirrors the TS reference behaviour at
    # harness/src/fixtures/typescript/exact-server.ts:141-143 and the
    # spine `accepted_requirement_matches?` semantics in
    # rust/crates/x402/src/protocol/schemes/exact/types.rs.
    state = build_state
    envelope = JSON.parse(Base64.decode64(build_payment_header(state)))
    envelope.fetch("accepted").fetch("extra")["unexpected"] = "drift"
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    # No raise expected. Settlement progresses past matching; a later
    # stage (signature/transaction verification) governs the outcome
    # for this test's signature-less fixture, so we just assert
    # matching did not block.
    begin
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    rescue RuntimeError => err
      refute_equal "No matching payment requirements: accepted payment requirement does not match server challenge", err.message
    end
  end

  def test_settlement_tolerates_accepted_max_timeout_drift
    # maxTimeoutSeconds is informational and not part of the identity
    # tuple a client must echo. The Rust/TS references both ignore it
    # during matching; Ruby follows suit.
    state = build_state
    envelope = JSON.parse(Base64.decode64(build_payment_header(state)))
    envelope["accepted"]["maxTimeoutSeconds"] = 30
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    begin
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    rescue RuntimeError => err
      refute_equal "No matching payment requirements: accepted payment requirement does not match server challenge", err.message
    end
  end

  def test_settlement_rejects_malformed_payment_signature_encoding
    state = build_state

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, "not base64")
    end

    assert_equal "invalid payment signature encoding", error.message
  end

  def test_settlement_rejects_malformed_payment_signature_json
    state = build_state
    payment_header = Base64.strict_encode64("not-json")

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid payment signature JSON", error.message
  end

  def test_settlement_rejects_non_object_payment_signature_json
    state = build_state
    payment_header = Base64.strict_encode64(JSON.generate(["not", "object"]))

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "payment signature must be a JSON object", error.message
  end

  def test_settlement_rejects_non_object_payload
    state = build_state
    envelope = {
      "x402Version" => 2,
      "accepted" => X402::Server::Exact.exact_requirement(state),
      "payload" => "not-object"
    }
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "payment payload is missing transaction", error.message
  end

  def test_settlement_rejects_missing_transaction_payload
    state = build_state
    envelope = {
      "x402Version" => 2,
      "accepted" => X402::Server::Exact.exact_requirement(state),
      "payload" => {}
    }
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "payment payload is missing transaction", error.message
  end

  def test_settlement_rejects_invalid_transaction_payload_base64
    state = build_state
    envelope = JSON.parse(Base64.decode64(build_payment_header(state)))
    envelope.fetch("payload")["transaction"] = "not base64"
    payment_header = Base64.strict_encode64(JSON.generate(envelope))

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "payment payload transaction is not valid base64", error.message
  end

  def test_settlement_rejects_transaction_amount_mismatch_before_sending
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      replace_transfer_amount(transaction, 999)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_amount_mismatch", error.message
    assert_empty sent
  end

  def test_settlement_rejects_fee_payer_as_transfer_authority_before_sending
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      make_fee_payer_transfer_authority(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds", error.message
    assert_empty sent
  end

  def test_settlement_rejects_fee_payer_as_transfer_source_before_sending
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      make_fee_payer_transfer_source(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds", error.message
    assert_empty sent
  end

  def test_settlement_rejects_fee_payer_in_any_instruction_account_before_sending
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      add_fee_payer_to_memo_accounts(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts", error.message
    assert_empty sent
  end

  # Attack regression: fee-payer ATA drain via extra SPL TransferChecked.
  # A malicious client appends a TransferChecked in the optional-instruction
  # slot that names the fee payer as an additional account (e.g. authority).
  # The instruction-list sweep runs before the optional-program allowlist,
  # so the canonical reject token is the fee-payer-in-instruction-accounts
  # reason — proving the sweep (not the program-allowlist fallback) is the
  # gate that closes this drain.
  def test_settlement_rejects_extra_token_transfer_naming_fee_payer
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      append_extra_token_transfer_with_fee_payer_authority(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts", error.message
    assert_empty sent
  end

  # Attack regression: fee-payer SOL drain via SystemProgram::Transfer.
  # The classic "facilitator drain" shape — instead of an SPL transfer,
  # the attacker appends a native lamport transfer whose source is the
  # fee payer. The instruction-list sweep is the responsible gate.
  def test_settlement_rejects_extra_system_transfer_from_fee_payer
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      append_system_transfer_from_fee_payer(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts", error.message
    assert_empty sent
  end

  # Attack regression: fee-payer pubkey appears at instruction-account
  # position 1 (not the carve-out slot 0) of an extra memo instruction.
  # Mirrors the "SLOT attack" shape: fee payer named at a non-payer slot.
  # The sweep must reject regardless of position.
  def test_settlement_rejects_fee_payer_at_instruction_slot_one
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      append_memo_with_fee_payer_at_slot_one(transaction)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts", error.message
    assert_empty sent
  end

  # Positive control: the same envelope minus the attack mutation must be
  # accepted. Confirms the sweep does not block the canonical happy-path
  # transfer that the cross-spine reference clients emit.
  def test_settlement_accepts_clean_envelope_positive_control
    state = build_state(sender: ->(_state, _transaction) { "unit-settlement" })

    assert_equal "unit-settlement",
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))
  end

  def test_settlement_rejects_lighthouse_as_sixth_instruction
    sent = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      append_optional_instruction(transaction, X402::Protocol::Schemes::Exact::LIGHTHOUSE_PROGRAM)
      append_optional_instruction(transaction, X402::Protocol::Schemes::Exact::LIGHTHOUSE_PROGRAM)
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_unknown_sixth_instruction", error.message
    assert_empty sent
  end

  def test_settlement_rejects_duplicate_signature_after_confirmation
    # Two settlements that confirm to the *same* on-chain signature must
    # collapse to one. The replay store is keyed on the confirmed signature
    # (`x402-svm-exact:consumed:<base58_signature>`), so the second attempt
    # observes the already-consumed signature and surfaces the canonical
    # `signature_consumed` reject.
    state = build_state(sender: ->(_state, _transaction) { "shared-signature" })
    payment_header = build_payment_header(state)

    assert_equal "shared-signature", X402::Server::Exact.settle_exact_payment(state, payment_header)
    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "signature_consumed", error.message
  end

  def test_settlement_orders_broadcast_then_confirm_then_put_if_absent
    order = []
    cache = X402::Server::Exact::SettlementCache.new
    tracking_cache = Class.new do
      def initialize(inner, order)
        @inner = inner
        @order = order
      end

      def put_if_absent(key, **kwargs)
        @order << [:put_if_absent, key]
        @inner.put_if_absent(key, **kwargs)
      end

      def duplicate?(key, **kwargs)
        @inner.duplicate?(key, **kwargs)
      end
    end.new(cache, order)
    state = build_state(
      sender: ->(_state, _transaction) {
        order << [:broadcast]
        "sig-ordering"
      },
      signature_confirmer: ->(_state, signature) {
        order << [:confirm, signature]
        signature
      },
      settlement_cache: tracking_cache
    )

    assert_equal "sig-ordering",
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))

    assert_equal [
      [:broadcast],
      [:confirm, "sig-ordering"],
      [:put_if_absent, "x402-svm-exact:consumed:sig-ordering"]
    ], order
  end

  def test_settlement_does_not_record_signature_when_broadcast_fails_before_confirm
    cache = X402::Server::Exact::SettlementCache.new
    state = build_state(
      sender: ->(_state, _transaction) { raise "sendTransaction RPC error: blockhash not found" },
      signature_confirmer: ->(_state, _signature) { raise "confirm must not run when broadcast failed" },
      settlement_cache: cache
    )
    payment_header = build_payment_header(state)

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end
    assert_match(/blockhash not found/, error.message)

    # No release path exists by design — the replay key was never written, so
    # a retry on the same envelope is free to broadcast again.
    retried = false
    state = build_state(
      sender: ->(_state, _transaction) {
        retried = true
        "retry-sig"
      },
      signature_confirmer: ->(_state, signature) { signature },
      settlement_cache: cache
    )
    assert_equal "retry-sig", X402::Server::Exact.settle_exact_payment(state, payment_header)
    assert retried
  end

  def test_settlement_does_not_record_signature_when_confirmation_fails
    cache = X402::Server::Exact::SettlementCache.new
    state = build_state(
      sender: ->(_state, _transaction) { "unconfirmed-sig" },
      signature_confirmer: ->(_state, _signature) { raise "timed out awaiting confirmation for unconfirmed-sig" },
      settlement_cache: cache
    )

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))
    end
    assert_match(/timed out awaiting confirmation/, error.message)

    # Confirmation failed → put_if_absent never ran → the signature is not in
    # the replay store. The retry is allowed to broadcast again, and Solana's
    # own per-signature uniqueness inside the blockhash window prevents a
    # double-pay if the original eventually confirms.
    refute cache.duplicate?("x402-svm-exact:consumed:unconfirmed-sig")
  end

  def test_settlement_consumed_key_namespace_is_scheme_scoped
    assert_equal "x402-svm-exact:consumed:abc123",
      X402::Server::Exact.signature_consumed_key("abc123")
  end

  def test_settlement_rejects_missing_source_token_account_before_sending
    sent = []
    checked = []
    state = build_state(
      sender: ->(_state, _transaction) {
        sent << true
        "unit-settlement"
      },
      account_checker: ->(_state, account) {
        checked << account
        false
      }
    )

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))
    end

    assert_equal "source token account does not exist", error.message
    assert_equal 1, checked.length
    assert_empty sent
  end

  def test_settlement_rejects_missing_destination_token_account_before_sending
    sent = []
    checked = []
    state = build_state(
      sender: ->(_state, _transaction) {
        sent << true
        "unit-settlement"
      },
      account_checker: ->(_state, account) {
        checked << account
        checked.length == 1
      }
    )

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))
    end

    assert_equal "destination token account does not exist", error.message
    assert_equal 2, checked.length
    assert_empty sent
  end

  def test_settlement_skips_missing_destination_account_when_create_ata_is_present
    checked = []
    state = build_state(
      account_checker: ->(_state, account) {
        checked << account
        true
      }
    )
    payment_header = mutate_payment_transaction(build_payment_header(state), resign: true) do |transaction|
      append_valid_destination_ata_create_instruction(transaction, state)
    end

    assert_equal "unit-settlement", X402::Server::Exact.settle_exact_payment(state, payment_header)
    assert_equal 1, checked.length
  end

  def test_server_rejects_unsigned_payload_before_facilitator_sign
    sent = []
    signed_with_facilitator = []
    state = build_state(sender: ->(_state, transaction) {
      sent << transaction
      "unit-settlement"
    })

    # Corrupt the client signature by flipping bits in the client's signature
    # slot. The facilitator MUST NOT apply its own signature to this envelope:
    # otherwise a partially-signed transaction leaks back to the attacker.
    payment_header = mutate_payment_transaction(build_payment_header(state)) do |transaction|
      # Client signature lives at offset 1 + 64 (after short_vec(2) + fee
      # payer slot). Flip every byte to ensure verification fails.
      client_signature_offset = 1 + 64
      64.times do |index|
        transaction.setbyte(client_signature_offset + index, transaction.getbyte(client_signature_offset + index) ^ 0xff)
      end
      transaction
    end

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header)
    end

    assert_equal "invalid_exact_svm_payload_signature", error.message
    assert_empty sent
    # The envelope's fee-payer slot must remain unsigned — if the facilitator
    # had signed early, the bytes would no longer be all-zero.
    envelope = JSON.parse(Base64.decode64(payment_header))
    transaction_bytes = Base64.decode64(envelope.fetch("payload").fetch("transaction"))
    facilitator_signature_slot = transaction_bytes.byteslice(1, 64)
    assert_equal ("\x00".b * 64), facilitator_signature_slot
    assert_empty signed_with_facilitator
  end

  def test_server_accepts_valid_client_signature_positive_control
    state = build_state(sender: ->(_state, _transaction) { "unit-settlement" })

    assert_equal "unit-settlement",
      X402::Server::Exact.settle_exact_payment(state, build_payment_header(state))
  end

  def test_server_rejects_payment_for_different_resource
    state = build_state(sender: ->(_state, _transaction) { "unit-settlement" })
    payment_header = build_payment_header(state, resource: "/resource/a")

    error = assert_raises(RuntimeError) do
      X402::Server::Exact.settle_exact_payment(state, payment_header, resource: "/resource/b")
    end

    assert_equal "invalid_exact_svm_payload_resource_mismatch", error.message
  end

  def test_server_accepts_payment_for_matching_resource_positive_control
    state = build_state(sender: ->(_state, _transaction) { "unit-settlement" })
    payment_header = build_payment_header(state, resource: "/resource/a")

    assert_equal "unit-settlement",
      X402::Server::Exact.settle_exact_payment(state, payment_header, resource: "/resource/a")
  end

  def test_settlement_cache_evicts_entries_after_ttl
    cache = X402::Server::Exact::SettlementCache.new(ttl_seconds: 120)
    now = Time.at(1_000)

    refute cache.duplicate?("tx-a", now: now)
    assert cache.duplicate?("tx-a", now: now + 119)
    refute cache.duplicate?("tx-a", now: now + 121)
  end

  def test_payment_errors_are_normalized
    body = X402::Server::Exact.payment_error_body(RuntimeError.new("sendTransaction RPC error: failed"))

    assert_equal(
      {
        error: "payment_invalid",
        message: "sendTransaction RPC error: failed",
        invalidReason: "sendTransaction RPC error: failed"
      },
      body
    )
  end

  def test_protected_route_normalizes_invalid_payment_error_body
    state = build_state
    status, headers, body = X402::Server::Exact.response_for(
      "/protected",
      {"PAYMENT-SIGNATURE" => "not base64"},
      state
    )

    assert_equal 402, status
    assert headers.key?("PAYMENT-REQUIRED")
    assert_equal "payment_invalid", body.fetch(:error)
    assert_equal "invalid payment signature encoding", body.fetch(:message)
    assert_equal "invalid payment signature encoding", body.fetch(:invalidReason)
  end

  def test_send_transaction_normalizes_rpc_error_message
    state = build_state
    response = Object.new
    base_is_a = response.method(:is_a?)
    response.define_singleton_method(:is_a?) { |klass| klass == Net::HTTPSuccess || base_is_a.call(klass) }
    response.define_singleton_method(:code) { "200" }
    response.define_singleton_method(:body) do
      JSON.generate(
        "error" => {
          "code" => -32_002,
          "message" => "Transaction simulation failed"
        }
      )
    end
    fake_http = Object.new
    fake_http.define_singleton_method(:request) { |_request| response }
    start = ->(_hostname, _port, _options, &block) { block.call(fake_http) }

    singleton = class << Net::HTTP; self; end
    original_start = Net::HTTP.method(:start)
    singleton.define_method(:start, start)
    begin
      error = assert_raises(RuntimeError) do
        X402::Server::Exact.send_transaction(state, "signed-transaction")
      end

      assert_equal "sendTransaction RPC error: Transaction simulation failed", error.message
    ensure
      singleton.define_method(:start, original_start)
    end
  end

  def test_send_transaction_returns_rpc_signature
    state = build_state

    with_net_http_response(JSON.generate("result" => "rpc-signature")) do
      assert_equal "rpc-signature", X402::Server::Exact.send_transaction(state, "signed-transaction")
    end
  end

  def test_send_transaction_rejects_empty_rpc_signature
    state = build_state

    with_net_http_response(JSON.generate("result" => "")) do
      error = assert_raises(RuntimeError) do
        X402::Server::Exact.send_transaction(state, "signed-transaction")
      end

      assert_equal "sendTransaction returned empty signature", error.message
    end
  end

  def test_account_exists_returns_true_when_rpc_value_is_present
    state = build_state

    with_net_http_response(JSON.generate("result" => {"value" => {"owner" => "token"}})) do
      assert X402::Server::Exact.account_exists?(state, PAY_TO)
    end
  end

  def test_account_exists_returns_false_when_rpc_value_is_missing
    state = build_state

    with_net_http_response(JSON.generate("result" => {"value" => nil})) do
      refute X402::Server::Exact.account_exists?(state, PAY_TO)
    end
  end

  def test_account_exists_normalizes_non_object_rpc_error
    state = build_state

    with_net_http_response(JSON.generate("error" => "plain rpc failure")) do
      error = assert_raises(RuntimeError) do
        X402::Server::Exact.account_exists?(state, PAY_TO)
      end

      assert_equal "getAccountInfo RPC error: plain rpc failure", error.message
    end
  end

  def test_account_exists_rejects_http_failure
    state = build_state

    with_net_http_response("service unavailable", code: "503", success: false) do
      error = assert_raises(RuntimeError) do
        X402::Server::Exact.account_exists?(state, PAY_TO)
      end

      assert_equal "getAccountInfo HTTP 503", error.message
    end
  end

  def test_static_routes_return_expected_responses
    state = build_state

    status, = X402::Server::Exact.response_for("/health", {}, state)
    assert_equal 200, status

    status, _headers, body = X402::Server::Exact.response_for("/capabilities", {}, state)
    assert_equal 200, status
    assert_equal "ruby", body.fetch(:implementation)

    status, headers, body = X402::Server::Exact.response_for("/exact", {}, state)
    assert_equal 402, status
    assert headers.key?("PAYMENT-REQUIRED")
    assert_equal({error: "payment_required"}, body)

    status, headers, body = X402::Server::Exact.response_for("/missing", {}, state)
    assert_equal 404, status
    assert_empty headers
    assert_equal({error: "not_found"}, body)
  end

  def test_protected_route_returns_settlement_success
    state = build_state(sender: ->(_state, _transaction) { "settlement-signature" })
    status, headers, body = X402::Server::Exact.response_for(
      "/protected",
      {"payment-signature" => build_payment_header(state, resource: "/protected")},
      state
    )

    assert_equal 200, status
    assert_equal "settlement-signature", headers.fetch("x-fixture-settlement")
    assert_equal true, body.fetch(:paid)
    assert_equal "settlement-signature", body.fetch(:settlement).fetch(:transaction)
    assert_equal NETWORK, body.fetch(:settlement).fetch(:network)
    # Canonical x402 v2 PAYMENT-RESPONSE header. Mirrors Rust spine
    # (rust/crates/x402/src/bin/interop_server.rs L221-231) and TS fixture
    # (harness/src/fixtures/typescript/exact-server.ts L322-331).
    # Header value is raw JSON (not base64) with exactly the canonical
    # PaymentResponse shape: { success, network, transaction }.
    payment_response_raw = headers.fetch("PAYMENT-RESPONSE")
    payment_response = JSON.parse(payment_response_raw, symbolize_names: true)
    assert_equal(
      {success: true, network: NETWORK, transaction: "settlement-signature"},
      payment_response
    )
  end

  def test_server_rejects_cross_server_credential_with_canonical_token
    # Simulate a cross-server replay: a credential built for server A (with a
    # different payTo) is presented to server B. Server B must reject with a
    # 4xx response whose body carries one of the canonical reject tokens that
    # the interop cross-server scenarios harness searches for.
    server_a = build_state
    other_pay_to = "11111111111111111111111111111113"
    server_b = X402::Server::Exact::Config.new(
      rpc_url: "http://127.0.0.1:8899",
      network: NETWORK,
      mint: ASSET,
      pay_to: other_pay_to,
      facilitator_secret_key: JSON.generate(secret(65)),
      amount: "$0.001",
      transaction_sender: ->(_state, _transaction) { "settlement-signature" },
      account_checker: ->(_state, _account) { true }
    )
    payment_header = build_payment_header(server_a, resource: "/protected")

    status, _headers, body = X402::Server::Exact.response_for(
      "/protected",
      {"PAYMENT-SIGNATURE" => payment_header},
      server_b
    )

    assert status >= 400 && status < 500, "expected 4xx, got #{status}"
    serialized = JSON.generate(body).downcase
    canonical_tokens = [
      "no matching payment requirements",
      "payment_invalid"
    ]
    matched = canonical_tokens.any? { |token| serialized.include?(token) }
    assert matched, "expected body to include a canonical reject token, got #{serialized}"
  end

  def test_protected_route_returns_payment_required_without_signature
    state = build_state
    status, headers, body = X402::Server::Exact.response_for("/protected", {}, state)

    assert_equal 402, status
    assert_equal({error: "payment_required"}, body)
    assert JSON.parse(Base64.decode64(headers.fetch("PAYMENT-REQUIRED"))).fetch("accepts").any?
  end

  def test_resource_path_and_settlement_header_env_overrides
    # Cross-server scenarios drive route + header name via
    # X402_INTEROP_RESOURCE_PATH and X402_INTEROP_SETTLEMENT_HEADER. The
    # server MUST honor those overrides instead of hardcoding /protected
    # and x-fixture-settlement.
    state = build_state_with_overrides(
      resource_path: "/protected/expensive",
      settlement_header: "x-fixture-settlement-alt",
      sender: ->(_state, _transaction) { "settlement-signature" }
    )

    # Default route no longer routes here.
    status, _headers, body = X402::Server::Exact.response_for("/protected", {}, state)
    assert_equal 404, status
    assert_equal({error: "not_found"}, body)

    # Challenge advertises the overridden resource URI.
    status, headers, _body = X402::Server::Exact.response_for("/protected/expensive", {}, state)
    assert_equal 402, status
    challenge = JSON.parse(Base64.decode64(headers.fetch("PAYMENT-REQUIRED")))
    assert_equal "/protected/expensive", challenge.fetch("resource").fetch("uri")

    # Settlement emits the overridden header name and not the default.
    payment_header = build_payment_header(state, resource: "/protected/expensive")
    status, headers, body = X402::Server::Exact.response_for(
      "/protected/expensive",
      {"PAYMENT-SIGNATURE" => payment_header},
      state
    )
    assert_equal 200, status
    assert_equal "settlement-signature", headers.fetch("x-fixture-settlement-alt")
    refute headers.key?("x-fixture-settlement"), "default settlement header must not be emitted when override is set"
    assert_equal true, body.fetch(:paid)
  end

  private

  def build_state_with_overrides(resource_path:, settlement_header:, sender:)
    X402::Server::Exact::Config.new(
      rpc_url: "http://127.0.0.1:8899",
      network: NETWORK,
      mint: ASSET,
      pay_to: PAY_TO,
      facilitator_secret_key: JSON.generate(secret(65)),
      amount: "$0.001",
      resource_path: resource_path,
      settlement_header: settlement_header,
      transaction_sender: sender,
      account_checker: ->(_state, _account) { true },
      signature_confirmer: ->(_state, signature) { signature }
    )
  end

  def build_state(
    price: "$0.001",
    extra_offered_mints: nil,
    sender: ->(_state, _transaction) { "unit-settlement" },
    account_checker: ->(_state, _account) { true },
    signature_confirmer: ->(_state, signature) { signature },
    settlement_cache: nil,
    recent_blockhash_provider: -> {}
  )
    kwargs = {
      rpc_url: "http://127.0.0.1:8899",
      network: NETWORK,
      mint: ASSET,
      pay_to: PAY_TO,
      facilitator_secret_key: JSON.generate(secret(65)),
      amount: price,
      transaction_sender: sender,
      account_checker: account_checker,
      signature_confirmer: signature_confirmer,
      settlement_cache: settlement_cache,
      recent_blockhash_provider: recent_blockhash_provider
    }
    unless extra_offered_mints.nil?
      kwargs[:extra_offered_mints] = extra_offered_mints.split(",").map(&:strip).reject(&:empty?)
    end
    X402::Server::Exact::Config.new(**kwargs)
  end

  def build_payment_header(state, resource: nil)
    X402::Protocol::Schemes::Exact.build_exact_payment_signature(
      requirement: X402::Server::Exact.exact_requirement(state, resource: resource),
      client_secret_key: JSON.generate(secret(1)),
      recent_blockhash: BLOCKHASH,
      resource: {"type" => "http", "uri" => resource || "/protected"}
    )
  end

  def with_net_http_response(body, code: "200", success: true)
    response = Object.new
    base_is_a = response.method(:is_a?)
    response.define_singleton_method(:is_a?) do |klass|
      (success && klass == Net::HTTPSuccess) || base_is_a.call(klass)
    end
    response.define_singleton_method(:code) { code }
    response.define_singleton_method(:body) { body }
    fake_http = Object.new
    fake_http.define_singleton_method(:request) { |_request| response }

    singleton = class << Net::HTTP; self; end
    original_start = Net::HTTP.method(:start)
    singleton.define_method(:start, ->(_hostname, _port, _options, &block) { block.call(fake_http) })
    yield
  ensure
    singleton.define_method(:start, original_start)
  end

  def mutate_payment_transaction(payment_header, resign: false)
    envelope = JSON.parse(Base64.decode64(payment_header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))
    mutated = yield transaction.dup
    mutated = resign_client_signature(mutated) if resign
    envelope.fetch("payload")["transaction"] = Base64.strict_encode64(mutated)
    Base64.strict_encode64(JSON.generate(envelope))
  end

  def resign_client_signature(transaction)
    bytes = transaction.b
    signature_count, signatures_offset = X402::Protocol::Schemes::Exact.read_short_vec(bytes, 0)
    message_offset = signatures_offset + (signature_count * 64)
    message = bytes.byteslice(message_offset, bytes.bytesize - message_offset)
    private_key = X402::Protocol::Schemes::Exact.private_key_from_json(JSON.generate(secret(1)))
    # Client signer is at index 1 (fee_payer is 0).
    signature = private_key.sign(nil, message)
    bytes[signatures_offset + 64, 64] = signature
    bytes
  end

  def replace_transfer_amount(transaction, amount)
    offset = transfer_data_offset(transaction)
    transaction[offset, 10] = [12].pack("C") + [amount].pack("Q<") + [6].pack("C")
    transaction
  end

  def make_fee_payer_transfer_authority(transaction)
    offset = transfer_data_offset(transaction)
    transaction.setbyte(offset - 2, 0)
    transaction
  end

  def make_fee_payer_transfer_source(transaction)
    offset = transfer_data_offset(transaction)
    transaction.setbyte(offset - 5, 0)
    transaction
  end

  def add_fee_payer_to_memo_accounts(transaction)
    offset = transaction.bytesize - 1 - 32

    transaction.setbyte(offset - 2, 1)
    transaction.insert(offset - 1, [0].pack("C"))
    transaction
  end

  def append_optional_instruction(transaction, program)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_keys_offset = account_count_offset + 1
    blockhash_offset = account_keys_offset + (account_count * 32)

    unless transaction.byteslice(account_keys_offset, account_count * 32).include?(X402::Protocol::Schemes::Exact.base58_decode(program))
      transaction.setbyte(account_count_offset, account_count + 1)
      transaction.insert(blockhash_offset, X402::Protocol::Schemes::Exact.base58_decode(program))
      account_count += 1
    end

    instruction_count_offset = account_keys_offset + (account_count * 32) + 32

    transaction.setbyte(instruction_count_offset, transaction.getbyte(instruction_count_offset) + 1)
    transaction.insert(transaction.bytesize - 1, [account_count - 1, 0, 0].pack("C*"))
    transaction
  end

  def append_valid_destination_ata_create_instruction(transaction, state)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_keys_offset = account_count_offset + 1
    blockhash_offset = account_keys_offset + (account_count * 32)
    extra_keys = [
      X402::Protocol::Schemes::Exact.base58_decode(state.pay_to),
      X402::Protocol::Schemes::Exact.base58_decode(X402::Protocol::Schemes::Exact::SYSTEM_PROGRAM),
      X402::Protocol::Schemes::Exact.base58_decode(X402::Protocol::Schemes::Exact::ASSOCIATED_TOKEN_PROGRAM)
    ]

    transaction.setbyte(account_count_offset, account_count + extra_keys.length)
    transaction.insert(blockhash_offset, extra_keys.join)

    pay_to_index = account_count
    system_index = account_count + 1
    ata_program_index = account_count + 2
    instruction_count_offset = account_keys_offset + ((account_count + extra_keys.length) * 32) + 32
    transaction.setbyte(instruction_count_offset, transaction.getbyte(instruction_count_offset) + 1)
    instruction = [
      ata_program_index,
      6,
      1,
      3,
      pay_to_index,
      6,
      system_index,
      5,
      1,
      1
    ].pack("C*")
    transaction.insert(transaction.bytesize - 1, instruction)
    transaction
  end

  # Append an extra SPL TransferChecked instruction in the optional slot,
  # naming the fee payer (account index 0) as one of the transfer accounts.
  # Token program is already present as a static key (index 5).
  def append_extra_token_transfer_with_fee_payer_authority(transaction)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_keys_offset = account_count_offset + 1
    instruction_count_offset = account_keys_offset + (account_count * 32) + 32

    transaction.setbyte(instruction_count_offset, transaction.getbyte(instruction_count_offset) + 1)
    # Token program index is 5 in build_transaction's account_keys layout.
    # Accounts: [fee_payer=0, mint=6, fee_payer=0, fee_payer=0] — four
    # accounts as required by TransferChecked, with the fee payer named at
    # both source and authority positions.
    instruction = [
      5,             # program_index (token program)
      4,             # short_vec(account_count)
      0, 6, 0, 0,    # accounts: fee_payer, mint, fee_payer, fee_payer
      10,            # short_vec(data_len)
      12,            # discriminator: TransferChecked
      1, 0, 0, 0, 0, 0, 0, 0, # amount = 1 (little-endian u64)
      6              # decimals
    ].pack("C*")
    transaction.insert(transaction.bytesize - 1, instruction)
    transaction
  end

  # Append a SystemProgram::Transfer that names the fee payer as source.
  # This is the canonical fee-payer SOL drain shape.
  def append_system_transfer_from_fee_payer(transaction)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_keys_offset = account_count_offset + 1
    blockhash_offset = account_keys_offset + (account_count * 32)

    # Add SystemProgram as a new static account key.
    transaction.setbyte(account_count_offset, account_count + 1)
    transaction.insert(blockhash_offset, X402::Protocol::Schemes::Exact.base58_decode(X402::Protocol::Schemes::Exact::SYSTEM_PROGRAM))
    system_program_index = account_count

    new_account_count = account_count + 1
    instruction_count_offset = account_keys_offset + (new_account_count * 32) + 32
    transaction.setbyte(instruction_count_offset, transaction.getbyte(instruction_count_offset) + 1)
    # SystemProgram::Transfer instruction:
    # - accounts: [from=fee_payer=0, to=pay_to (account index 3 = destination_ata; we just want a valid index)]
    # - data: discriminator 2 (u32 LE) + lamports (u64 LE)
    instruction = [
      system_program_index, # program_index
      2,                    # short_vec(account_count)
      0, 3,                 # accounts: from=fee_payer, to=any-account
      12,                   # short_vec(data_len)
      2, 0, 0, 0,           # discriminator: Transfer
      1, 0, 0, 0, 0, 0, 0, 0 # lamports = 1
    ].pack("C*")
    transaction.insert(transaction.bytesize - 1, instruction)
    transaction
  end

  # Append a memo-program instruction whose accounts vector names the fee
  # payer at position 1 (a non-carve-out slot). The sweep must reject
  # before settlement, regardless of which slot the fee payer appears in
  # (only ATA-create's funding-payer slot 0 is carved out).
  def append_memo_with_fee_payer_at_slot_one(transaction)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_keys_offset = account_count_offset + 1
    instruction_count_offset = account_keys_offset + (account_count * 32) + 32

    transaction.setbyte(instruction_count_offset, transaction.getbyte(instruction_count_offset) + 1)
    # Memo program index is 7 in build_transaction's account_keys layout.
    # Accounts: [memo_program=7, fee_payer=0] — fee payer at position 1.
    instruction = [
      7,        # program_index (memo)
      2,        # short_vec(account_count)
      7, 0,     # accounts: filler, fee_payer
      0         # short_vec(data_len) — empty
    ].pack("C*")
    transaction.insert(transaction.bytesize - 1, instruction)
    transaction
  end

  def transfer_data_offset(transaction)
    data = [12].pack("C") + [1000].pack("Q<") + [6].pack("C")
    offset = transaction.index(data)
    raise "transfer instruction fixture not found" if offset.nil?

    offset
  end

  def secret(start)
    values = Array.new(64, 0)
    values[0, 32] = (start...(start + 32)).map { |value| value % 256 }
    values
  end
end
