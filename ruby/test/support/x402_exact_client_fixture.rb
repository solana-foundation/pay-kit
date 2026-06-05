# frozen_string_literal: true

require "base64"
require "json"
require "securerandom"

# Test-only x402 "exact" client. Ruby ships server support only
# (server-only language), so the on-chain payment builder is NOT part
# of the gem; production clients live in the TS/Rust/Go/Python adapters.
# This fixture exists purely so `x402_server_exact_test.rb` can mint a
# client-signed PaymentSignatureEnvelope to drive the server under test.
# It reuses the shipped library's PayCore + x402 verify-side helpers and
# only adds the transaction-construction code that is otherwise absent
# from the server-only library.
module X402ExactClientFixture
  module_function

  Exact = ::PayKit::Protocols::X402::Protocol::Schemes::Exact
  Constants = ::PayKit::Protocols::X402::Constants

  # Build a client-signed x402 payment envelope. Mirrors the spine
  # `PaymentSignatureEnvelope` shape at
  # `rust/crates/x402/src/protocol/schemes/exact/types.rs:482-493`.
  def build_exact_payment_signature(requirement:, client_secret_key:, recent_blockhash:, resource: nil)
    raise ArgumentError, "only exact payment requirements can be signed" unless requirement["scheme"] == "exact"

    private_key = Exact.private_key_from_json(client_secret_key)
    transaction = build_transaction(
      requirement: requirement,
      private_key: private_key,
      recent_blockhash: recent_blockhash
    )
    envelope = {
      x402Version: Constants::X402_VERSION_V2,
      accepted: requirement,
      payload: {transaction: Base64.strict_encode64(transaction)}
    }
    envelope[:resource] = resource if resource.is_a?(Hash)

    Base64.strict_encode64(JSON.generate(envelope))
  end

  # Build a legacy v1 x402 payment envelope. Mirrors the spine
  # `build_payment_header_v1` shape (client/exact/payment.rs:153-170):
  # `x402Version=1`, top-level `scheme` + plain `network` siblings of
  # `payload`, and NO `accepted` object. `network` is the legacy plain
  # SVM slug (e.g. "solana-devnet"), not CAIP-2.
  def build_v1_exact_payment_signature(requirement:, client_secret_key:, recent_blockhash:, network:)
    raise ArgumentError, "only exact payment requirements can be signed" unless requirement["scheme"] == "exact"

    private_key = Exact.private_key_from_json(client_secret_key)
    transaction = build_transaction(
      requirement: requirement,
      private_key: private_key,
      recent_blockhash: recent_blockhash
    )
    envelope = {
      x402Version: Constants::X402_VERSION_V1,
      scheme: Constants::EXACT_SCHEME,
      network: network,
      payload: {transaction: Base64.strict_encode64(transaction)}
    }

    Base64.strict_encode64(JSON.generate(envelope))
  end

  def build_transaction(requirement:, private_key:, recent_blockhash:)
    signer = private_key.raw_public_key
    fee_payer = Exact.base58_decode(Exact.string_extra(requirement, "feePayer"))
    mint = Exact.base58_decode(requirement.fetch("asset"))
    pay_to = Exact.base58_decode(requirement.fetch("payTo"))
    token_program = Exact.base58_decode(Exact.string_extra(requirement, "tokenProgram"))
    blockhash = Exact.base58_decode(recent_blockhash)
    decimals = Exact.integer_extra(requirement, "decimals")
    amount = Integer(requirement.fetch("amount"), 10)
    source_ata = Exact.associated_token_address(signer, token_program, mint)
    destination_ata = Exact.associated_token_address(pay_to, token_program, mint)
    compute_budget_program = Exact.base58_decode(Constants::COMPUTE_BUDGET_PROGRAM)
    memo_program = Exact.base58_decode(Constants::MEMO_PROGRAM)

    account_keys = [
      fee_payer,
      signer,
      source_ata,
      destination_ata,
      compute_budget_program,
      token_program,
      mint,
      memo_program
    ]

    instructions = [
      compiled_instruction(4, [], [2].pack("C") + [Constants::DEFAULT_COMPUTE_UNIT_LIMIT].pack("V")),
      compiled_instruction(4, [], [3].pack("C") + [Constants::DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS].pack("Q<")),
      compiled_instruction(5, [2, 6, 3, 1], [12].pack("C") + [amount].pack("Q<") + [decimals].pack("C")),
      compiled_instruction(7, [], memo_bytes(requirement))
    ]

    message = [
      [0x80, 2, 1, 4].pack("C*"),
      Exact.short_vec(account_keys.length),
      account_keys.join,
      blockhash,
      Exact.short_vec(instructions.length),
      instructions.join,
      Exact.short_vec(0)
    ].join
    signature = private_key.sign(nil, message)

    [
      Exact.short_vec(2),
      ("\x00".b * 64),
      signature,
      message
    ].join
  end

  def compiled_instruction(program_index, account_indexes, data)
    [
      [program_index].pack("C"),
      Exact.short_vec(account_indexes.length),
      account_indexes.pack("C*"),
      Exact.short_vec(data.bytesize),
      data
    ].join
  end

  def memo_bytes(requirement)
    memo = Exact.string_extra(requirement, "memo", required: false)
    memo = SecureRandom.hex(16) if memo.nil? || memo.empty?
    bytes = memo.b
    raise ArgumentError, "extra.memo exceeds maximum #{Constants::MAX_MEMO_BYTES} bytes" if bytes.bytesize > Constants::MAX_MEMO_BYTES

    bytes
  end
end
