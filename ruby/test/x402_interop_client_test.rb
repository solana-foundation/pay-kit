# frozen_string_literal: true

require "base64"
require "json"
require_relative "test_helper"
require "x402/client"
require "x402/exact"

class InteropClientTest < Minitest::Test
  NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  ASSET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

  def test_selects_requirement_from_payment_required_header
    requirement = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }
    encoded = Base64.strict_encode64(JSON.generate("x402Version" => 2, "accepts" => [requirement]))

    selected = X402::Interop::Client.select_svm_requirement(
      headers: {"PAYMENT-REQUIRED" => encoded},
      body: "",
      network: NETWORK
    )

    assert_equal requirement, selected
  end

  def test_selects_challenge_resource_from_payment_required_header
    requirement = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }
    resource = {"url" => "/protected", "description" => "test"}
    encoded = Base64.strict_encode64(
      JSON.generate("x402Version" => 2, "resource" => resource, "accepts" => [requirement])
    )

    selected, selected_resource = X402::Interop::Client.select_svm_challenge(
      headers: {"PAYMENT-REQUIRED" => encoded},
      body: "",
      network: NETWORK
    )

    assert_equal requirement, selected
    assert_equal resource, selected_resource
  end

  def test_selects_requirement_from_json_body
    evm = {
      "scheme" => "exact",
      "network" => "eip155:8453",
      "asset" => "0x0000000000000000000000000000000000000000",
      "amount" => "1000"
    }
    solana = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }

    selected = X402::Interop::Client.select_svm_requirement(
      headers: {},
      body: JSON.generate("accepts" => [evm, solana]),
      network: NETWORK
    )

    assert_equal solana, selected
  end

  def test_selects_requirement_with_ts_fixture_max_amount_required_field
    # The TypeScript reference fixture
    # (harness/src/fixtures/typescript/exact-server.ts) emits offers
    # using `maxAmountRequired` rather than the canonical Rust-spine
    # `amount` field. Rust accepts either at types.rs:337-339; Ruby
    # must too for cross-spine interop.
    requirement = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "maxAmountRequired" => "1000"
    }
    encoded = Base64.strict_encode64(JSON.generate("x402Version" => 2, "accepts" => [requirement]))

    selected = X402::Interop::Client.select_svm_requirement(
      headers: {"PAYMENT-REQUIRED" => encoded},
      body: "",
      network: NETWORK
    )

    assert_equal requirement, selected
  end

  def test_selects_challenge_resource_when_envelope_carries_string_url
    # Rust spine carries `resource` as a typed ResourceInfo object, but
    # the TS fixture emits it as a bare URL string. The Ruby client
    # normalises the string form into `{ "url" => <string> }` so
    # downstream consumers always see a hash.
    requirement = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }
    encoded = Base64.strict_encode64(
      JSON.generate("x402Version" => 2, "resource" => "/protected", "accepts" => [requirement])
    )

    selected, selected_resource = X402::Interop::Client.select_svm_challenge(
      headers: {"PAYMENT-REQUIRED" => encoded},
      body: "",
      network: NETWORK
    )

    assert_equal requirement, selected
    assert_equal({"url" => "/protected"}, selected_resource)
  end

  def test_ignores_malformed_payment_required_header_and_body
    selected = X402::Interop::Client.select_svm_requirement(
      headers: {"PAYMENT-REQUIRED" => "not-json"},
      body: "not-json",
      network: NETWORK
    )

    assert_nil selected
  end

  def test_selects_preferred_currency
    usdc = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }
    pyusd = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
      "amount" => "1000"
    }

    selected = X402::Interop::Client.select_svm_requirement(
      headers: {},
      body: JSON.generate("accepts" => [usdc, pyusd]),
      network: NETWORK,
      preferred_currencies: ["PYUSD", "USDC"]
    )

    assert_equal pyusd, selected
  end

  def test_falls_back_to_first_matching_currency_when_preferences_are_unavailable
    usdc = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000"
    }
    pyusd = {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
      "amount" => "1000"
    }

    selected = X402::Interop::Client.select_svm_requirement(
      headers: {},
      body: JSON.generate("accepts" => [usdc, pyusd]),
      network: NETWORK,
      preferred_currencies: ["CASH"]
    )

    assert_equal usdc, selected
  end

  def test_ignores_unsupported_scheme
    selected = X402::Interop::Client.select_svm_requirement(
      headers: {},
      body: JSON.generate(
        "accepts" => [
          {
            "scheme" => "unsupported",
            "network" => NETWORK,
            "asset" => ASSET,
            "amount" => "1000"
          }
        ]
      ),
      network: NETWORK
    )

    assert_nil selected
  end

  def test_builds_exact_payment_signature_envelope
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    client_address = X402::Interop::Exact.public_key_base58(JSON.generate(secret))
    requirement = exact_requirement
    resource = {"url" => "/protected"}

    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash"),
      resource: resource
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))

    assert_equal 2, envelope.fetch("x402Version")
    assert_equal 60, envelope.fetch("accepted").fetch("maxTimeoutSeconds")
    assert_equal resource, envelope.fetch("resource")
    assert_equal 2, transaction.bytes.first
    assert_equal "\x00".b * 64, transaction.byteslice(1, 64)
    refute_equal "\x00".b * 64, transaction.byteslice(65, 64)
    assert_includes transaction, X402::Interop::Exact.base58_decode(client_address)
  end

  def test_build_exact_payment_signature_requires_fee_payer
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra").delete("feePayer")

    error = assert_raises(ArgumentError) do
      X402::Interop::Exact.build_exact_payment_signature(
        requirement: requirement,
        client_secret_key: JSON.generate(secret),
        recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
      )
    end

    assert_equal "payment requirement has invalid extra.feePayer", error.message
  end

  def test_build_exact_payment_signature_normalizes_missing_required_extra_errors
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a

    {
      "feePayer" => "payment requirement has invalid extra.feePayer",
      "decimals" => "payment requirement has invalid extra.decimals",
      "tokenProgram" => "payment requirement has invalid extra.tokenProgram"
    }.each do |key, message|
      requirement = exact_requirement
      requirement.fetch("extra").delete(key)

      error = assert_raises(ArgumentError) do
        X402::Interop::Exact.build_exact_payment_signature(
          requirement: requirement,
          client_secret_key: JSON.generate(secret),
          recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
        )
      end

      assert_equal message, error.message
    end
  end

  def test_build_exact_payment_signature_uses_unique_default_memo_for_duplicate_safety
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra").delete("memo")

    first = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    second = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )

    first_tx = JSON.parse(Base64.decode64(first)).fetch("payload").fetch("transaction")
    second_tx = JSON.parse(Base64.decode64(second)).fetch("payload").fetch("transaction")

    refute_equal first_tx, second_tx
  end

  def test_build_exact_payment_signature_accepts_memo_at_reference_limit
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra")["memo"] = "x" * X402::Interop::Exact::MAX_MEMO_BYTES

    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))

    assert_includes transaction, "x" * X402::Interop::Exact::MAX_MEMO_BYTES
  end

  def test_build_exact_payment_signature_rejects_memo_above_reference_limit
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra")["memo"] = "x" * (X402::Interop::Exact::MAX_MEMO_BYTES + 1)

    error = assert_raises(ArgumentError) do
      X402::Interop::Exact.build_exact_payment_signature(
        requirement: requirement,
        client_secret_key: JSON.generate(secret),
        recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
      )
    end

    assert_equal "extra.memo exceeds maximum 256 bytes", error.message
  end

  def test_build_exact_payment_signature_from_rpc_uses_embedded_recent_blockhash
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement

    header = X402::Interop::Exact.build_exact_payment_signature_from_rpc(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      rpc_url: "http://127.0.0.1:8899"
    )
    envelope = JSON.parse(Base64.decode64(header))

    assert_equal requirement, envelope.fetch("accepted")
  end

  def test_build_exact_payment_signature_from_rpc_fetches_missing_recent_blockhash
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra").delete("recentBlockhash")

    with_net_http_response(
      JSON.generate("result" => {"value" => {"blockhash" => "11111111111111111111111111111111"}})
    ) do
      header = X402::Interop::Exact.build_exact_payment_signature_from_rpc(
        requirement: requirement,
        client_secret_key: JSON.generate(secret),
        rpc_url: "http://127.0.0.1:8899"
      )
      envelope = JSON.parse(Base64.decode64(header))

      assert_equal requirement, envelope.fetch("accepted")
    end
  end

  def test_latest_blockhash_rejects_http_failure
    # After shared-core consolidation x402 delegates `latest_blockhash` to
    # `Mpp::Methods::Solana::Rpc`, which raises the canonical `Mpp::Error`
    # subclass of `StandardError` carrying a stable
    # `getLatestBlockhash HTTP <code>` message on non-2xx responses.
    with_net_http_response("service unavailable", code: "503", success: false) do
      error = assert_raises(Mpp::Error) do
        X402::Interop::Exact.latest_blockhash("http://127.0.0.1:8899")
      end

      assert_equal "getLatestBlockhash HTTP 503", error.message
    end
  end

  def test_verify_exact_transaction_accepts_expected_memo
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))

    transfer = X402::Interop::Exact.verify_exact_transaction!(
      transaction: transaction,
      requirement: requirement,
      managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
    )

    assert_equal false, transfer.fetch(:destination_create_ata)
  end

  def test_verify_exact_transaction_accepts_multibyte_utf8_memo
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    # Mix of accented Latin, CJK, and an emoji — exercises ASCII-8BIT vs UTF-8 string
    # equality. Without binary-equal comparison this would silently fail with
    # invalid_exact_svm_payload_memo_mismatch even though the bytes match.
    requirement.fetch("extra")["memo"] = "naïve-日本語-\u{1F680}"
    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))

    transfer = X402::Interop::Exact.verify_exact_transaction!(
      transaction: transaction,
      requirement: requirement,
      managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
    )

    assert_equal false, transfer.fetch(:destination_create_ata)
  end

  def test_verify_exact_transaction_round_trips_max_memo_length
    # Regression for short_vec length-prefix encoding at memo = MAX_MEMO_BYTES.
    # The compact length for 256 is [0x80, 0x02]; an incorrect UTF-8 codepoint
    # encoding would produce 3 bytes and the verifier would fail to parse the
    # transaction message.
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra")["memo"] = "x" * X402::Interop::Exact::MAX_MEMO_BYTES

    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))

    transfer = X402::Interop::Exact.verify_exact_transaction!(
      transaction: transaction,
      requirement: requirement,
      managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
    )

    assert_equal false, transfer.fetch(:destination_create_ata)
  end

  def test_verify_exact_transaction_rejects_invalid_utf8_memo_bytes
    # Pin the contract: memo bytes inside the transaction must be valid UTF-8,
    # otherwise verification raises invalid_exact_svm_payload_memo_mismatch.
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    requirement.fetch("extra")["memo"] = "ok"

    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    transaction = Base64.decode64(envelope.fetch("payload").fetch("transaction"))
    # Corrupt one memo byte to an invalid UTF-8 lone continuation (0x80).
    memo_offset = transaction.index("ok".b)
    refute_nil memo_offset
    transaction.setbyte(memo_offset, 0x80)

    error = assert_raises(RuntimeError) do
      X402::Interop::Exact.verify_exact_transaction!(
        transaction: transaction,
        requirement: requirement,
        managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
      )
    end
    assert_equal "invalid_exact_svm_payload_memo_mismatch", error.message
  end

  def test_short_vec_encodes_multibyte_lengths_as_binary_bytes
    # Reference Solana short_vec for lengths >= 128 must emit raw bytes
    # 0x80..0xFF, not UTF-8 codepoints. Regression guard for byte.chr usage.
    encoded = X402::Interop::Exact.short_vec(256)
    assert_equal Encoding::ASCII_8BIT, encoded.encoding
    assert_equal [0x80, 0x02], encoded.bytes
    assert_equal 2, encoded.bytesize

    encoded_127 = X402::Interop::Exact.short_vec(127)
    assert_equal [0x7f], encoded_127.bytes

    encoded_128 = X402::Interop::Exact.short_vec(128)
    assert_equal [0x80, 0x01], encoded_128.bytes
  end

  def test_verify_exact_transaction_rejects_short_instruction_list
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    transaction = exact_transaction(requirement, secret)
    count_offset = instruction_count_offset(transaction)
    transaction.setbyte(count_offset, 2)

    error = assert_raises(RuntimeError) do
      X402::Interop::Exact.verify_exact_transaction!(
        transaction: transaction,
        requirement: requirement,
        managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
      )
    end

    assert_equal "invalid_exact_svm_payload_transaction_instructions_length", error.message
  end

  def test_verify_exact_transaction_rejects_bad_compute_limit_instruction
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    transaction = exact_transaction(requirement, secret)
    compute_limit_data_offset = transaction.index([2, X402::Interop::Exact::DEFAULT_COMPUTE_UNIT_LIMIT].pack("CV"))
    transaction.setbyte(compute_limit_data_offset, 9)

    error = assert_raises(RuntimeError) do
      X402::Interop::Exact.verify_exact_transaction!(
        transaction: transaction,
        requirement: requirement,
        managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
      )
    end

    assert_equal "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction", error.message
  end

  def test_verify_exact_transaction_rejects_excessive_compute_price
    secret = Array.new(64, 0)
    secret[0, 32] = (1..32).to_a
    requirement = exact_requirement
    transaction = exact_transaction(requirement, secret)
    compute_price_data_offset = transaction.index(
      [3, X402::Interop::Exact::DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS].pack("CQ<")
    )
    transaction[compute_price_data_offset, 9] = [
      3,
      X402::Interop::Exact::MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1
    ].pack("CQ<")

    error = assert_raises(RuntimeError) do
      X402::Interop::Exact.verify_exact_transaction!(
        transaction: transaction,
        requirement: requirement,
        managed_signers: [X402::Interop::Exact.base58_decode(requirement.fetch("extra").fetch("feePayer"))]
      )
    end

    assert_equal "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high", error.message
  end

  def test_private_key_from_json_rejects_non_secret_key_array
    error = assert_raises(ArgumentError) do
      X402::Interop::Exact.public_key_base58(JSON.generate([1, 2, 3]))
    end

    assert_equal "expected a 64-byte Solana secret key JSON array", error.message
  end

  def test_read_short_vec_rejects_overlong_encoding
    error = assert_raises(ArgumentError) do
      X402::Interop::Exact.read_short_vec("\x80\x80\x80\x80\x80".b, 0)
    end

    assert_equal "short vec is too long", error.message
  end

  private

  def exact_transaction(requirement, secret)
    header = X402::Interop::Exact.build_exact_payment_signature(
      requirement: requirement,
      client_secret_key: JSON.generate(secret),
      recent_blockhash: requirement.fetch("extra").fetch("recentBlockhash")
    )
    envelope = JSON.parse(Base64.decode64(header))
    Base64.decode64(envelope.fetch("payload").fetch("transaction"))
  end

  def instruction_count_offset(transaction)
    message_offset = 1 + (2 * 64)
    account_count_offset = message_offset + 4
    account_count = transaction.getbyte(account_count_offset)
    account_count_offset + 1 + (account_count * 32) + 32
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

    # x402 entry points hit Net::HTTP via two distinct shapes: the legacy
    # x402 procedural client used `Net::HTTP.start(host, port, opts)` (class
    # method) and the post-shared-core path delegates to
    # `Mpp::Methods::Solana::Rpc#perform_request`, which builds a
    # `Net::HTTP` instance and calls `http.start { client.request(req) }`.
    # Stub both shapes so a single test helper covers either implementation.
    singleton = class << Net::HTTP; self; end
    original_start = Net::HTTP.method(:start)
    singleton.define_method(:start, ->(_hostname, _port, *_args, &block) { block.call(fake_http) })

    instance_singleton = Net::HTTP
    original_instance_start = instance_singleton.instance_method(:start)
    instance_singleton.define_method(:start) { |&block| block.call(fake_http) }

    yield
  ensure
    singleton.define_method(:start, original_start) if original_start
    instance_singleton.define_method(:start, original_instance_start) if original_instance_start
  end

  def exact_requirement
    {
      "scheme" => "exact",
      "network" => NETWORK,
      "asset" => ASSET,
      "amount" => "1000",
      "payTo" => "11111111111111111111111111111112",
      "maxTimeoutSeconds" => 60,
      "extra" => {
        "feePayer" => "11111111111111111111111111111113",
        "decimals" => 6,
        "tokenProgram" => "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "recentBlockhash" => "11111111111111111111111111111111",
        "memo" => "unit-test"
      }
    }
  end
end
