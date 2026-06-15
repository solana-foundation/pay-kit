# frozen_string_literal: true

require_relative "../../../test_helper"

class FakeRpc
  attr_reader :sent_transactions, :simulated_transactions

  def initialize(signature: "3mJr7AoUXx2Wqd", transaction_response: nil, statuses: nil, simulation_error: nil)
    @signature = signature
    @transaction_response = transaction_response
    @statuses = statuses || [{"err" => nil, "confirmationStatus" => "confirmed"}]
    @simulation_error = simulation_error
    @sent_transactions = []
    @simulated_transactions = []
  end

  def simulate_transaction(transaction_base64)
    @simulated_transactions << transaction_base64
    {"err" => @simulation_error}
  end

  def send_raw_transaction(transaction_base64)
    @sent_transactions << transaction_base64
    @signature
  end

  def signature_statuses(_signatures)
    @statuses
  end

  def transaction_base64(_signature)
    @transaction_response
  end
end

class SequenceRpc < FakeRpc
  def initialize(responses:)
    super()
    @responses = responses
  end

  def transaction_base64(_signature)
    @responses.shift
  end
end

class ChargeServerTest < Minitest::Test
  include RubyMppTestHelpers

  def setup
    @server = PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "api")
  end

  def test_creates_and_verifies_expected_credential
    request = charge_request(external_id: "order-1")
    challenge = @server.create_challenge(request)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(
      challenge: challenge.to_echo,
      payload: {"signature" => valid_signature}
    )
    verifier = PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new

    result = @server.verify_authorization_header(
      credential.to_authorization_header,
      verifier: verifier,
      expected_request: request
    )

    assert result.ok?
    assert_equal valid_signature, result.reference
  end

  def test_blockhash_provider_injects_recent_blockhash_without_mutating_request
    request = charge_request
    server = PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(
      secret_key: "secret",
      realm: "api",
      blockhash_provider: -> { "recent-blockhash" }
    )

    challenge = server.create_challenge(request)
    decoded = challenge.decode_request

    assert_equal "recent-blockhash", decoded.fetch("methodDetails").fetch("recentBlockhash")
    refute request.method_details.key?("recentBlockhash")
  end

  def test_rejects_method_details_replay_with_same_amount_currency_and_recipient
    cheap = charge_request
    expensive = charge_request(method_details: {"network" => "localnet", "decimals" => 6, "splits" => [{"recipient" => pubkey(3), "amount" => "250"}]})
    challenge = @server.create_challenge(cheap)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    result = @server.verify_authorization_header(
      credential.to_authorization_header,
      verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new,
      expected_request: expensive
    )

    refute result.ok?
    assert_match(/Method details mismatch/, result.reason)
  end

  def test_rejects_cross_route_amount_replay
    cheap = charge_request(amount: "500")
    expensive = charge_request(amount: "1000")
    challenge = @server.create_challenge(cheap)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    result = @server.verify_authorization_header(
      credential.to_authorization_header,
      verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new,
      expected_request: expensive
    )

    refute result.ok?
    assert_match(/Amount mismatch/, result.reason)
  end

  def test_rejects_expired_challenge
    request = charge_request
    challenge = @server.create_challenge(request, expires: "2020-01-01T00:00:00Z")
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    result = @server.verify_authorization_header(
      credential.to_authorization_header,
      verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new,
      expected_request: request
    )

    refute result.ok?
    assert_equal "challenge expired", result.reason
  end

  def test_rejects_wrong_secret_and_wrong_realm
    request = charge_request
    issuer = PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "other", realm: "api")
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: issuer.create_challenge(request).to_echo, payload: {"signature" => valid_signature})

    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)
    refute result.ok?
    assert_match(/challenge verification failed/, result.reason)

    issuer = PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "other")
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: issuer.create_challenge(request).to_echo, payload: {"signature" => valid_signature})
    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)
    refute result.ok?
    assert_match(/does not match this server|challenge verification failed/, result.reason)
  end

  def test_rejects_wrong_method_with_valid_hmac
    request = charge_request
    challenge = PayKit::Protocols::Mpp::Protocol::Core::Challenge.with_secret(
      secret_key: "secret",
      realm: "api",
      method: "stripe",
      intent: "charge",
      request: request.to_h
    )
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)

    refute result.ok?
    assert_match(/method/, result.reason)
  end

  def test_rejects_wrong_intent_currency_and_recipient_with_valid_hmac
    request = charge_request
    challenge = PayKit::Protocols::Mpp::Protocol::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "session", request: request.to_h)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})
    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)
    refute result.ok?
    assert_match(/intent/, result.reason)

    challenge = @server.create_challenge(charge_request(currency: "USDC"))
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})
    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)
    refute result.ok?
    assert_match(/Currency mismatch/, result.reason)

    challenge = @server.create_challenge(charge_request(recipient: pubkey(3)))
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})
    result = @server.verify_authorization_header(credential.to_authorization_header, verifier: PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new, expected_request: request)
    refute result.ok?
    assert_match(/Recipient mismatch/, result.reason)
  end

  private

  def valid_signature
    ::PayCore::Solana::Base58.encode(("a" * 64).b)
  end
end

class TransactionVerifierTest < Minitest::Test
  include RubyMppTestHelpers

  def setup
    @verifier = PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new
  end

  def test_verifies_sol_transfer_and_memo
    payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::MEMO_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
      instructions: [
        compiled_instruction(4, [], [3].pack("C") + u64(1)),
        compiled_instruction(4, [], [2].pack("C") + u32(200_000)),
        compiled_instruction(2, [0, 1], u32(2) + u64(1000)),
        compiled_instruction(3, [], "order-1")
      ]
    )
    request = charge_request(external_id: "order-1")

    result = @verifier.verify_transaction_payload(tx, request)

    assert result.ok?, result.reason
  end

  def test_verifies_non_ascii_external_id_memo_bytes
    payer = pubkey(1)
    recipient = pubkey(2)
    memo = "order-é"
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::MEMO_PROGRAM],
      instructions: [
        compiled_instruction(2, [0, 1], u32(2) + u64(1000)),
        compiled_instruction(3, [], memo.b)
      ]
    )
    request = charge_request(external_id: memo)

    result = @verifier.verify_transaction_payload(tx, request)

    assert result.ok?, result.reason
  end

  def test_rejects_unexpected_program
    payer = pubkey(1)
    recipient = pubkey(2)
    unexpected = pubkey(7)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, unexpected],
      instructions: [
        compiled_instruction(2, [0, 1], u32(2) + u64(1000)),
        compiled_instruction(3, [], "")
      ]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request)

    refute result.ok?
    assert_match(/Unexpected program/, result.reason)
  end

  def test_rejects_fee_payer_funding_sol_transfer
    fee_payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [fee_payer, recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )
    request = charge_request(method_details: {"feePayer" => true, "feePayerKey" => fee_payer})

    result = @verifier.verify_transaction_payload(tx, request)

    refute result.ok?
    assert_match(/fee payer cannot fund/, result.reason)
  end

  def test_rejects_compute_budget_above_limit
    payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
      instructions: [
        compiled_instruction(3, [], [2].pack("C") + u32(200_001)),
        compiled_instruction(2, [0, 1], u32(2) + u64(1000))
      ]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request)

    refute result.ok?
    assert_match(/Compute unit limit/, result.reason)
  end

  def test_rejects_signature_wrong_length
    assert_raises(ArgumentError) { @verifier.validate_signature("abc") }
  end

  def test_verifier_rejects_missing_payload_and_invalid_base64
    challenge = PayKit::Protocols::Mpp::Protocol::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "charge", request: charge_request.to_h)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {})

    result = @verifier.verify(credential, challenge)
    refute result.ok?
    assert_match(/missing transaction or signature/, result.reason)

    result = @verifier.verify_transaction_payload("not base64", charge_request)
    refute result.ok?
    assert_match(/invalid transaction payload/, result.reason)
  end

  def test_verifies_pull_transaction_against_expected_route_request
    payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )
    challenge = PayKit::Protocols::Mpp::Protocol::Core::Challenge.with_secret(secret_key: "secret", realm: "api", method: "solana", intent: "charge", request: charge_request.to_h)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"transaction" => tx})
    expected = charge_request(method_details: {"network" => "localnet", "decimals" => 6, "splits" => [{"recipient" => pubkey(3), "amount" => "250"}]})

    result = @verifier.verify(credential, challenge, expected_request: expected)

    refute result.ok?
    assert_match(/No matching SOL transfer/, result.reason)
  end

  def test_rejects_split_amount_boundaries
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )
    too_many = 9.times.map { |index| {"recipient" => pubkey(index + 10), "amount" => "1"} }
    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"splits" => too_many}))
    refute result.ok?
    assert_match(/too many splits/, result.reason)

    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"splits" => [{"recipient" => pubkey(3), "amount" => "1000"}]}))
    refute result.ok?
    assert_match(/split amounts exceed/, result.reason)
  end

  # Rust spine parity (rust/crates/mpp/src/protocol/intents/charge.rs:53-58):
  # split amounts are base-unit u64. A split amount above u64::MAX must
  # surface as an explicit invalid-amount error rather than a downstream
  # "No matching transfer" failure.
  def test_rejects_split_amount_above_u64_max
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )
    overflow_split = [{"recipient" => pubkey(3), "amount" => (2**64).to_s}]
    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"splits" => overflow_split}))
    refute result.ok?
    assert_match(/exceeds the maximum u64 amount/, result.reason)
  end

  def test_rejects_fee_payer_missing_key_and_mismatch
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"feePayer" => true}))
    refute result.ok?
    assert_match(/feePayer=true requires/, result.reason)

    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"feePayer" => true, "feePayerKey" => pubkey(3)}))
    refute result.ok?
    assert_match(/fee payer mismatch/, result.reason)
  end

  def test_verifies_spl_transfer_checked
    owner = pubkey(1)
    recipient = pubkey(2)
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    source_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    dest_ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    tx = tx_base64(
      account_keys: [owner, source_ata, mint, dest_ata, PROGRAMS::TOKEN_PROGRAM],
      instructions: [compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(1000) + [6].pack("C"))]
    )
    request = charge_request(currency: mint, recipient: recipient, method_details: {"network" => "localnet", "decimals" => 6, "tokenProgram" => PROGRAMS::TOKEN_PROGRAM})

    result = @verifier.verify_transaction_payload(tx, request)

    assert result.ok?, result.reason
  end

  def test_verifies_spl_split_with_idempotent_ata_creation
    owner = pubkey(1)
    recipient = pubkey(2)
    split_owner = pubkey(3)
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    source_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    dest_ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    split_ata = ::PayCore::Solana::ATA.derive(owner: split_owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    tx = tx_base64(
      account_keys: [owner, source_ata, mint, dest_ata, PROGRAMS::TOKEN_PROGRAM, PROGRAMS::ASSOCIATED_TOKEN_PROGRAM, split_owner, split_ata, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [
        compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(750) + [6].pack("C")),
        compiled_instruction(5, [0, 7, 6, 2, 8, 4], "\x01".b),
        compiled_instruction(4, [1, 2, 7, 0], [12].pack("C") + u64(250) + [6].pack("C"))
      ]
    )
    request = charge_request(
      amount: "1000",
      currency: mint,
      recipient: recipient,
      method_details: {
        "network" => "localnet",
        "decimals" => 6,
        "tokenProgram" => PROGRAMS::TOKEN_PROGRAM,
        "splits" => [{"recipient" => split_owner, "amount" => "250", "ataCreationRequired" => true}]
      }
    )

    result = @verifier.verify_transaction_payload(tx, request)

    assert result.ok?, result.reason
  end

  def test_rejects_missing_required_ata_creation_for_split
    owner = pubkey(1)
    recipient = pubkey(2)
    split_owner = pubkey(3)
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    source_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    dest_ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    split_ata = ::PayCore::Solana::ATA.derive(owner: split_owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    tx = tx_base64(
      account_keys: [owner, source_ata, mint, dest_ata, PROGRAMS::TOKEN_PROGRAM, split_ata],
      instructions: [
        compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(750) + [6].pack("C")),
        compiled_instruction(4, [1, 2, 5, 0], [12].pack("C") + u64(250) + [6].pack("C"))
      ]
    )
    request = charge_request(
      amount: "1000",
      currency: mint,
      recipient: recipient,
      method_details: {
        "network" => "localnet",
        "decimals" => 6,
        "tokenProgram" => PROGRAMS::TOKEN_PROGRAM,
        "splits" => [{"recipient" => split_owner, "amount" => "250", "ataCreationRequired" => true}]
      }
    )

    result = @verifier.verify_transaction_payload(tx, request)

    refute result.ok?
    assert_match(/Missing required ATA creation/, result.reason)
  end

  def test_rejects_invalid_ata_creation_shapes
    owner = pubkey(1)
    recipient = pubkey(2)
    split_owner = pubkey(3)
    unauthorized_owner = pubkey(4)
    wrong_ata = pubkey(5)
    wrong_payer = pubkey(6)
    wrong_mint = pubkey(7)
    wrong_program = pubkey(8)
    unsupported_token_program = pubkey(9)
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    source_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    dest_ata = ::PayCore::Solana::ATA.derive(owner: recipient, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    split_ata = ::PayCore::Solana::ATA.derive(owner: split_owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    unauthorized_ata = ::PayCore::Solana::ATA.derive(owner: unauthorized_owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    keys = [owner, source_ata, mint, dest_ata, PROGRAMS::TOKEN_PROGRAM, PROGRAMS::ASSOCIATED_TOKEN_PROGRAM, split_owner, split_ata, PROGRAMS::SYSTEM_PROGRAM, wrong_payer, wrong_ata, wrong_mint, wrong_program, unsupported_token_program, PROGRAMS::TOKEN_2022_PROGRAM, unauthorized_owner, unauthorized_ata]
    base_request = charge_request(
      amount: "1000",
      currency: mint,
      recipient: recipient,
      method_details: {
        "network" => "localnet",
        "decimals" => 6,
        "tokenProgram" => PROGRAMS::TOKEN_PROGRAM,
        "splits" => [{"recipient" => split_owner, "amount" => "250", "ataCreationRequired" => true}]
      }
    )
    cases = [
      [[0, 7, 6, 2, 8, 4], "\x00".b, base_request, /Only idempotent/],
      [[0, 7, 6, 2, 8], "\x01".b, base_request, /account layout/],
      [[9, 7, 6, 2, 8, 4], "\x01".b, base_request, /payer/],
      [[0, 7, 6, 11, 8, 4], "\x01".b, base_request, /mint/],
      [[0, 7, 6, 2, 12, 4], "\x01".b, base_request, /System Program/],
      [[0, 7, 6, 2, 8, 13], "\x01".b, base_request, /unsupported token program/],
      [[0, 7, 6, 2, 8, 14], "\x01".b, base_request, /token program/],
      [[0, 10, 6, 2, 8, 4], "\x01".b, base_request, /address/],
      [[0, 16, 15, 2, 8, 4], "\x01".b, base_request, /owner/]
    ]

    cases.each do |accounts, data, request, message|
      tx = tx_base64(
        account_keys: keys,
        instructions: [
          compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(750) + [6].pack("C")),
          compiled_instruction(5, accounts, data),
          compiled_instruction(4, [1, 2, 7, 0], [12].pack("C") + u64(250) + [6].pack("C"))
        ]
      )

      result = @verifier.verify_transaction_payload(tx, request)

      refute result.ok?
      assert_match message, result.reason
    end
  end

  def test_rejects_sol_ata_creation_and_unexpected_memo
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::MEMO_PROGRAM],
      instructions: [
        compiled_instruction(2, [0, 1], u32(2) + u64(1000)),
        compiled_instruction(3, [], "unexpected")
      ]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request)
    refute result.ok?
    assert_match(/Unexpected program instruction/, result.reason)

    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"splits" => [{"recipient" => pubkey(3), "amount" => "1", "ataCreationRequired" => true}]}))
    refute result.ok?
    assert_match(/ataCreationRequired requires/, result.reason)
  end

  def test_rejects_compute_budget_price_and_unsupported_shapes
    payer = pubkey(1)
    recipient = pubkey(2)
    expensive = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
      instructions: [
        compiled_instruction(3, [], [3].pack("C") + u64(5_000_001)),
        compiled_instruction(2, [0, 1], u32(2) + u64(1000))
      ]
    )
    result = @verifier.verify_transaction_payload(expensive, charge_request)
    refute result.ok?
    assert_match(/Compute unit price/, result.reason)

    unsupported = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
      instructions: [
        compiled_instruction(3, [], [9].pack("C")),
        compiled_instruction(2, [0, 1], u32(2) + u64(1000))
      ]
    )
    result = @verifier.verify_transaction_payload(unsupported, charge_request)
    refute result.ok?
    assert_match(/Unsupported compute budget/, result.reason)
  end

  def test_rejects_memo_too_long_and_missing_expected_memo
    payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request(external_id: "x" * 567))
    refute result.ok?
    assert_match(/memo cannot exceed/, result.reason)

    result = @verifier.verify_transaction_payload(tx, charge_request(external_id: "order"))
    refute result.ok?
    assert_match(/No memo instruction/, result.reason)
  end

  def test_rejects_missing_recipient_and_bad_split_amount
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )
    no_recipient = PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: "1000", currency: "SOL")
    result = @verifier.verify_transaction_payload(tx, no_recipient)
    refute result.ok?
    assert_match(/recipient is required/, result.reason)

    result = @verifier.verify_transaction_payload(tx, charge_request(method_details: {"splits" => [{"recipient" => pubkey(3), "amount" => "bad"}]}))
    refute result.ok?
    assert_match(/split.amount/, result.reason)
  end

  def test_rejects_spl_wrong_destination_and_fee_payer_authority
    owner = pubkey(1)
    recipient = pubkey(2)
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    source_ata = ::PayCore::Solana::ATA.derive(owner: owner, mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    wrong_dest = ::PayCore::Solana::ATA.derive(owner: pubkey(3), mint: mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    tx = tx_base64(
      account_keys: [owner, source_ata, mint, wrong_dest, PROGRAMS::TOKEN_PROGRAM],
      instructions: [compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(1000) + [6].pack("C"))]
    )
    request = charge_request(currency: mint, recipient: recipient, method_details: {"network" => "localnet", "decimals" => 6, "tokenProgram" => PROGRAMS::TOKEN_PROGRAM})
    result = @verifier.verify_transaction_payload(tx, request)
    refute result.ok?
    assert_match(/No matching SPL/, result.reason)

    request = charge_request(currency: mint, recipient: recipient, method_details: {"network" => "localnet", "decimals" => 6, "tokenProgram" => PROGRAMS::TOKEN_PROGRAM, "feePayer" => true, "feePayerKey" => owner})
    result = @verifier.verify_transaction_payload(tx, request)
    refute result.ok?
    assert_match(/fee payer cannot authorize|No matching SPL/, result.reason)
  end

  # Audit #25: when the server is the fee payer (fee-sponsored pull mode) a
  # tight compute-unit-price cap (10_000) applies, since the merchant pays the
  # priority fee. A client-paid charge keeps the general 5M ceiling.
  def test_fee_sponsored_compute_unit_price_cap
    fee_payer = pubkey(1)
    payer = pubkey(2)
    recipient = pubkey(3)
    build = lambda do |price|
      # account_keys[0] == fee_payer (matches feePayerKey); the SOL transfer
      # source is `payer` (index 1), not the fee payer, so the value-transfer
      # passes and the compute-budget cap is the deciding gate.
      tx_base64(
        account_keys: [fee_payer, payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
        instructions: [
          compiled_instruction(4, [], [3].pack("C") + u64(price)),
          compiled_instruction(3, [1, 2], u32(2) + u64(1000))
        ]
      )
    end
    fee_sponsored = charge_request(recipient: recipient, method_details: {"feePayer" => true, "feePayerKey" => fee_payer})

    # Just over the tight fee-sponsored cap -> rejected.
    result = @verifier.verify_transaction_payload(build.call(10_001), fee_sponsored)
    refute result.ok?
    assert_match(/Compute unit price.*exceeds maximum 10000/, result.reason)

    # At the tight cap -> passes verification entirely.
    result = @verifier.verify_transaction_payload(build.call(10_000), fee_sponsored)
    assert result.ok?, result.reason
  end

  # Audit #25 regression: the tight cap MUST NOT apply when the client pays
  # its own gas (no server fee payer). A price between the two caps passes.
  def test_client_paid_compute_unit_price_keeps_general_cap
    payer = pubkey(1)
    recipient = pubkey(2)
    tx = tx_base64(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM, PROGRAMS::COMPUTE_BUDGET_PROGRAM],
      instructions: [
        compiled_instruction(3, [], [3].pack("C") + u64(1_000_000)),
        compiled_instruction(2, [0, 1], u32(2) + u64(1000))
      ]
    )

    result = @verifier.verify_transaction_payload(tx, charge_request)

    assert result.ok?, result.reason
  end

  # Audit #28: an arbitrary mint address (not a known stablecoin) with no
  # embedded methodDetails.tokenProgram must be rejected rather than silently
  # defaulting to the legacy Token program (which would derive the wrong ATA
  # for a Token-2022 mint).
  def test_rejects_arbitrary_mint_without_token_program
    arbitrary_mint = pubkey(7)
    request = charge_request(
      currency: arbitrary_mint,
      recipient: pubkey(2),
      method_details: {"network" => "localnet", "decimals" => 6}
    )
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(3), arbitrary_mint, pubkey(4), PROGRAMS::TOKEN_PROGRAM],
      instructions: [compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(1000) + [6].pack("C"))]
    )

    result = @verifier.verify_transaction_payload(tx, request)

    refute result.ok?
    assert_match(/tokenProgram is required for an arbitrary mint/, result.reason)
  end

  # Audit #37: the verifier rejects a non-allowlisted network slug embedded in
  # the SPL branch (e.g. "mainnet-beta").
  def test_rejects_unsupported_network_in_method_details
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    request = charge_request(
      currency: mint,
      recipient: pubkey(2),
      method_details: {"network" => "mainnet-beta", "decimals" => 6, "tokenProgram" => PROGRAMS::TOKEN_PROGRAM}
    )
    tx = tx_base64(
      account_keys: [pubkey(1), pubkey(3), mint, pubkey(4), PROGRAMS::TOKEN_PROGRAM],
      instructions: [compiled_instruction(4, [1, 2, 3, 0], [12].pack("C") + u64(1000) + [6].pack("C"))]
    )

    result = @verifier.verify_transaction_payload(tx, request)

    refute result.ok?
    assert_match(/Unsupported network/, result.reason)
  end

  private

  def tx_base64(account_keys:, instructions:)
    Base64.strict_encode64(legacy_transaction(account_keys: account_keys, instructions: instructions))
  end
end

class ChargeHandlerTest < Minitest::Test
  include RubyMppTestHelpers

  def test_returns_402_without_authorization
    handler = handler_with(FakeRpc.new)
    assert_nil handler.fee_payer_pubkey

    response = handler.handle(nil, charge_request)

    assert_equal 402, response.status
    assert response.headers.key?(PayKit::Protocols::Mpp::Protocol::Core::Headers::WWW_AUTHENTICATE)
  end

  def test_fee_payer_pubkey_and_missing_payload_response
    keypair = ::PayCore::Solana::Account.new(Array.new(64, 1))
    handler = PayKit::Protocols::Mpp::Server::Charge::Handler.new(
      challenges: handler_challenges,
      rpc: FakeRpc.new,
      replay_store: PayKit::Protocols::Mpp::MemoryStore.new,
      fee_payer: keypair,
      network: "localnet"
    )
    assert_equal keypair.public_key.to_s, handler.fee_payer_pubkey

    request = charge_request
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: handler_challenges.create_challenge(request).to_echo, payload: {})
    response = handler.handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/missing transaction or signature/, response.body["message"])
  end

  def test_settles_push_signature_by_fetching_transaction
    request = charge_request
    transaction = Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), request.recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    rpc = FakeRpc.new(transaction_response: {"meta" => {"err" => nil}, "transaction" => [transaction, "base64"]})
    handler = handler_with(rpc)
    challenge = handler_challenges.create_challenge(request)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    response = handler.handle(credential.to_authorization_header, request)

    assert_equal 200, response.status
    assert_equal valid_signature, response.signature
  end

  def test_rejects_replayed_signature
    store = PayKit::Protocols::Mpp::MemoryStore.new
    store.put_if_absent("solana-charge:consumed:#{valid_signature}", true)
    handler = handler_with(FakeRpc.new(transaction_response: transaction_response), store: store)
    request = charge_request
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: handler_challenges.create_challenge(request).to_echo, payload: {"signature" => valid_signature})

    response = handler.handle(credential.to_authorization_header, request)

    assert_equal 402, response.status
    assert_match(/already consumed/, response.body["message"])
  end

  def test_push_mode_reports_transaction_lookup_failures
    request = charge_request
    challenge = handler_challenges.create_challenge(request)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"signature" => valid_signature})

    response = handler_with(SequenceRpc.new(responses: [nil]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/Timed out fetching transaction/, response.body["message"])

    response = handler_with(SequenceRpc.new(responses: [{"transaction" => ["tx", "base64"]}]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/missing transaction metadata/, response.body["message"])

    response = handler_with(SequenceRpc.new(responses: [{"meta" => {"err" => "boom"}, "transaction" => ["tx", "base64"]}]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/failed/, response.body["message"])

    response = handler_with(SequenceRpc.new(responses: [{"meta" => {"err" => nil}, "transaction" => []}]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/missing base64 transaction/, response.body["message"])
  end

  def test_pull_mode_reports_simulation_and_confirmation_failures
    request = charge_request
    transaction = Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), request.recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    challenge = handler_challenges.create_challenge(request)
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(challenge: challenge.to_echo, payload: {"transaction" => transaction})

    response = handler_with(FakeRpc.new(simulation_error: "boom"), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/Simulation failed/, response.body["message"])

    response = handler_with(FakeRpc.new(statuses: [nil]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/Timed out waiting/, response.body["message"])

    response = handler_with(FakeRpc.new(statuses: [{"err" => "boom", "confirmationStatus" => "confirmed"}]), attempts: 1).handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/failed/, response.body["message"])
  end

  private

  def handler_challenges
    @handler_challenges ||= PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "api")
  end

  def handler_with(rpc, store: PayKit::Protocols::Mpp::MemoryStore.new, attempts: 40)
    PayKit::Protocols::Mpp::Server::Charge::Handler.new(
      challenges: handler_challenges,
      rpc: rpc,
      replay_store: store,
      network: "localnet",
      confirmation_attempts: attempts,
      confirmation_delay: 0
    )
  end

  def valid_signature
    ::PayCore::Solana::Base58.encode(("a" * 64).b)
  end

  def transaction_response
    transaction = Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    {"meta" => {"err" => nil}, "transaction" => [transaction, "base64"]}
  end
end
