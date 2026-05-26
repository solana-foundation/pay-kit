# frozen_string_literal: true

require_relative "test_helper"

class HandlerPathsTest < Minitest::Test
  include RubyMppTestHelpers

  def test_pull_settlement_simulates_sends_confirms_and_consumes
    request = charge_request
    rpc = FakeRpc.new(signature: valid_signature)
    handler = handler_with(rpc)
    transaction = Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), request.recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    credential = Mpp::Protocol::Core::Credential.new(
      challenge: challenges.create_challenge(request).to_echo,
      payload: {"transaction" => transaction}
    )

    response = handler.handle(credential.to_authorization_header, request)

    assert_equal 200, response.status
    assert_equal 1, rpc.simulated_transactions.length
    assert_equal 1, rpc.sent_transactions.length
  end

  def test_pull_rejects_simulation_failure
    request = charge_request
    rpc = FakeRpc.new(simulation_error: {"InstructionError" => [0, "Custom"]})
    handler = handler_with(rpc)
    transaction = Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), request.recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    credential = Mpp::Protocol::Core::Credential.new(challenge: challenges.create_challenge(request).to_echo, payload: {"transaction" => transaction})

    response = handler.handle(credential.to_authorization_header, request)

    assert_equal 402, response.status
    assert_match(/Simulation failed/, response.body["message"])
  end

  def test_pull_rejects_wrong_surfpool_network
    handler = handler_with(FakeRpc.new, network: "devnet")

    error = assert_raises(Mpp::VerificationError) do
      handler.send(:check_network_blockhash, Mpp::Server::Charge::Handler::SURFPOOL_BLOCKHASH_PREFIX + "abc")
    end
    assert_match(/Signed against localnet/, error.message)
  end

  def test_push_fetch_timeout_and_failed_meta
    request = charge_request
    timeout = handler_with(FakeRpc.new(transaction_response: nil), attempts: 1)
    credential = Mpp::Protocol::Core::Credential.new(challenge: challenges.create_challenge(request).to_echo, payload: {"signature" => valid_signature})
    response = timeout.handle(credential.to_authorization_header, request)

    assert_equal 402, response.status
    assert_match(/Timed out fetching/, response.body["message"])

    failed = handler_with(FakeRpc.new(transaction_response: {"meta" => {"err" => {"bad" => true}}, "transaction" => ["x", "base64"]}))
    response = failed.handle(credential.to_authorization_header, request)

    assert_equal 402, response.status
    assert_match(/failed/, response.body["message"])
  end

  def test_push_rejects_missing_transaction_metadata_and_wire
    request = charge_request
    credential = Mpp::Protocol::Core::Credential.new(challenge: challenges.create_challenge(request).to_echo, payload: {"signature" => valid_signature})

    missing_meta = handler_with(FakeRpc.new(transaction_response: {"transaction" => ["tx", "base64"]}))
    response = missing_meta.handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/missing transaction metadata/, response.body["message"])

    missing_wire = handler_with(FakeRpc.new(transaction_response: {"meta" => {"err" => nil}, "transaction" => []}))
    response = missing_wire.handle(credential.to_authorization_header, request)
    assert_equal 402, response.status
    assert_match(/missing base64 transaction/, response.body["message"])
  end

  private

  def challenges
    @challenges ||= Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "api")
  end

  def handler_with(rpc, network: "localnet", attempts: 40)
    Mpp::Server::Charge::Handler.new(
      challenges: challenges,
      rpc: rpc,
      replay_store: Mpp::MemoryStore.new,
      network: network,
      confirmation_attempts: attempts,
      confirmation_delay: 0
    )
  end

  def valid_signature
    ::PayCore::Solana::Base58.encode(("b" * 64).b)
  end
end
