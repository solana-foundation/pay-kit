# frozen_string_literal: true

require_relative "../../../test_helper"

# Pull-mode (type="transaction") replay regression.
#
# Cross-SDK parity: the TS reference (typescript/packages/mpp/src/server/Charge.ts)
# once had a broadcast-path bug where the consumed-signature marker was written
# but never checked, and no per-signature lock guarded broadcast, so the same
# signed transaction could settle more than once. Rust
# (rust/crates/kit/src/mpp/server/charge.rs) fixed the canonical order to:
# broadcast_pull -> consume_signature -> await_pull_confirmation.
#
# Ruby's Handler#handle mirrors that canonical order for BOTH paths:
#   signature = settle_payload(...)  # settle_pull broadcasts and returns the sig
#   consume_signature(signature)     # atomic Store#put_if_absent check-and-mark
#   await_settlement(...)            # pull-only confirmation polling
# so a replayed pull credential is rejected as already-consumed before any
# Settlement is returned. These tests pin that behaviour so the TS gap cannot
# regress into the Ruby SDK.

# Minimal RPC double for the pull path: simulate cleanly, return a fixed
# broadcast signature (as Solana would for one signed transaction), and report
# the transaction confirmed. Self-contained so this file runs standalone via
# `ruby -Itest test/pay_kit/protocols/mpp/pull_mode_replay_test.rb`.
class PullReplayFakeRpc
  def initialize(signature:)
    @signature = signature
  end

  def simulate_transaction(_transaction_base64)
    {"err" => nil}
  end

  def send_raw_transaction(_transaction_base64)
    @signature
  end

  def signature_statuses(_signatures)
    [{"err" => nil, "confirmationStatus" => "confirmed"}]
  end
end

class PullModeReplayTest < Minitest::Test
  include RubyMppTestHelpers

  # A pre-seeded consumed marker for the broadcast signature must reject a
  # replayed pull credential (single-request path).
  def test_rejects_replayed_pull_signature
    store = PayKit::Protocols::Mpp::MemoryStore.new
    store.put_if_absent("solana-charge:consumed:#{broadcast_signature}", true)
    handler = handler_with(PullReplayFakeRpc.new(signature: broadcast_signature), store: store)
    request = charge_request
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(
      challenge: handler_challenges.create_challenge(request).to_echo,
      payload: {"transaction" => pull_transaction(request)}
    )

    response = handler.handle(credential.to_authorization_header, request)

    assert_equal 402, response.status
    assert_match(/already consumed/, response.body["message"])
  end

  # TOCTOU: N threads race ONE pull credential against ONE shared replay store.
  # settle_pull broadcasts (Solana dedups the identical signature on-chain, so a
  # single real transfer occurs) and consume_signature reserves that signature
  # through the atomic Store#put_if_absent. Exactly one thread may settle (200);
  # every other is rejected as already-consumed (402). If the pull path ever
  # regressed to the TS shape (mark-without-check / no lock), this would settle
  # more than once.
  def test_rejects_concurrent_replayed_pull_signature
    shared_store = PayKit::Protocols::Mpp::MemoryStore.new
    request = charge_request
    credential = PayKit::Protocols::Mpp::Protocol::Core::Credential.new(
      challenge: handler_challenges.create_challenge(request).to_echo,
      payload: {"transaction" => pull_transaction(request)}
    )
    authorization = credential.to_authorization_header

    thread_count = 8
    results = Array.new(thread_count)
    gate = Thread::Queue.new
    threads = (0...thread_count).map do |index|
      Thread.new do
        # Each thread drives its own handler + RPC (every RPC returns the same
        # deterministic broadcast signature, as Solana would for one signed tx)
        # but shares the one replay store, so the only serialization point is
        # the store reserve.
        handler = handler_with(PullReplayFakeRpc.new(signature: broadcast_signature), store: shared_store)
        gate.pop
        results[index] = handler.handle(authorization, request)
      end
    end
    thread_count.times { gate.push(:go) }
    threads.each(&:join)

    statuses = results.map(&:status)
    assert_equal 1, statuses.count(200), "expected exactly one settlement, got statuses #{statuses.inspect}"
    assert_equal thread_count - 1, statuses.count(402), "expected the rest to be replay-rejected, got statuses #{statuses.inspect}"

    settled = results.select { |response| response.status == 200 }
    assert_equal broadcast_signature, settled.first.signature
    results.each do |response|
      next if response.status == 200

      assert_match(/already consumed/, response.body["message"])
    end
  end

  private

  def handler_challenges
    @handler_challenges ||= PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "api")
  end

  def handler_with(rpc, store:, attempts: 40)
    PayKit::Protocols::Mpp::Server::Charge::Handler.new(
      challenges: handler_challenges,
      rpc: rpc,
      replay_store: store,
      network: "localnet",
      confirmation_attempts: attempts,
      confirmation_delay: 0
    )
  end

  # The signature send_raw_transaction returns for the broadcast, i.e. the
  # on-chain id of the signed pull transaction and the replay key.
  def broadcast_signature
    "3mJr7AoUXx2Wqd"
  end

  # A well-formed SOL transfer transaction for the request, so settle_pull's
  # pre-broadcast path reaches send_raw_transaction and returns a signature.
  def pull_transaction(request)
    Base64.strict_encode64(legacy_transaction(
      account_keys: [pubkey(1), request.recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
  end
end
