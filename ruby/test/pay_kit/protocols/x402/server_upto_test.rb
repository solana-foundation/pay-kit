# frozen_string_literal: true

require "base64"
require "json"
require "ed25519"

require_relative "../../../test_helper"

# Offline engine + verifier tests for the x402 `upto` payment-channel server.
# A synthesized client `open` transaction and an injected channel fetcher let
# the full verify_open -> settle_actual path run without a validator.
class ServerUptoTest < Minitest::Test
  include RubyMppTestHelpers

  PC = ::PayCore::Solana::PaymentChannels
  MB = ::PayCore::Solana::MessageBuilder
  AM = ::PayCore::Solana::AccountMeta
  Upto = ::PayKit::Protocols::X402::Server::Upto
  UptoTypes = ::PayKit::Protocols::X402::Protocol::Schemes::Upto
  NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  MAX = 100_000

  def setup
    seed = "\x07".b * 32
    signing = ::Ed25519::SigningKey.new(seed)
    @operator = base58(signing.verify_key.to_bytes.bytes)
    @operator_secret = JSON.generate(seed.bytes + signing.verify_key.to_bytes.bytes)
    @payer = pubkey(2)
    @payee = pubkey(3)
    @mint = PROGRAMS::MINTS.fetch("USDC").fetch("devnet")
    @token_program = PROGRAMS::TOKEN_PROGRAM
  end

  # ---- happy paths -------------------------------------------------------
  def test_verify_open_binds_channel
    open = verify(salt: 1)
    assert_equal channel_id(1), open.channel_id
    assert_equal MAX, open.deposit
    assert_equal MAX, open.max_amount
    assert_equal @payer, open.payer
    assert_equal @operator, open.rent_payer
  end

  def test_settle_actual_nonzero
    engine, header, = build_case(salt: 2)
    response = engine.settle_actual(engine.verify_open(header, now: now), 50_000)

    assert_equal true, response["success"]
    assert_equal "50000", response["amount"]
    assert_equal @payer, response["payer"]
    refute_empty response["transaction"]
  end

  def test_settle_actual_zero_is_honored
    engine, header, = build_case(salt: 3)
    response = engine.settle_actual(engine.verify_open(header, now: now), 0)

    assert_equal true, response["success"]
    assert_equal "0", response["amount"]
  end

  def test_settle_actual_rejects_above_ceiling
    engine, header, = build_case(salt: 4)
    open = engine.verify_open(header, now: now)
    error = assert_raises(::PayKit::Protocols::X402::Error::PaymentInvalid) { engine.settle_actual(open, MAX + 1) }

    assert_equal UptoTypes::ERROR_SETTLEMENT_EXCEEDS_AMOUNT, error.message
  end

  # ---- payload rejects ---------------------------------------------------
  def test_rejects_wrong_profile
    assert_reject("invalid payload type") { verify(salt: 5, payload: {"profile" => "permit"}) }
  end

  def test_rejects_amount_mismatch
    assert_reject("amount mismatch") { verify(salt: 6, payload: {"maxAmount" => "999"}) }
  end

  def test_rejects_deposit_not_equal_max
    assert_reject("must equal the authorized maximum") { verify(salt: 7, payload: {"deposit" => "50000"}) }
  end

  def test_rejects_expired
    assert_reject("expired") { verify(salt: 8, now_override: 5_000_000_000) }
  end

  def test_rejects_not_yet_valid
    assert_reject("not yet active") { verify(salt: 9, payload: {"validAfter" => now + 10_000}) }
  end

  def test_rejects_authorized_signer_not_operator
    assert_reject("authorized_signer must be the operator") { verify(salt: 10, payload: {"authorizedSigner" => pubkey(99)}) }
  end

  def test_rejects_missing_open_transaction
    assert_reject("requires openTransaction") { verify(salt: 11, payload: {"openTransaction" => ""}) }
  end

  def test_rejects_network_mismatch
    assert_reject("network mismatch") { verify(salt: 12, network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp") }
  end

  # ---- open-instruction rejects -----------------------------------------
  def test_rejects_wrong_open_program
    assert_reject("unexpected program") { verify(salt: 13, open_program: PROGRAMS::SYSTEM_PROGRAM) }
  end

  def test_rejects_wrong_open_account
    assert_reject("payee mismatch") { verify(salt: 14, open_payee: pubkey(77)) }
  end

  # ---- open-args rejects (pre-broadcast, operator-fee-grief guard) -------
  def test_rejects_open_deposit_below_max
    assert_reject("open deposit") { verify(salt: 30, open_deposit: 50_000) }
  end

  def test_rejects_open_with_recipients
    assert_reject("empty-recipient open") { verify(salt: 31, open_recipients_count: 1) }
  end

  def test_rejects_open_salt_not_deriving_channel
    assert_reject("does not derive the payload channelId") { verify(salt: 32, open_salt: 999) }
  end

  def test_rejects_open_grace_period_mismatch
    assert_reject("grace period") { verify(salt: 33, open_grace_period: 60) }
  end

  # ---- channel rejects ---------------------------------------------------
  def test_rejects_channel_not_open
    assert_reject("not open") { verify(salt: 15, channel: {status: 1}) }
  end

  def test_rejects_mint_mismatch
    assert_reject("token mint mismatch") { verify(salt: 16, channel: {mint: pubkey(50)}) }
  end

  def test_rejects_payee_mismatch
    assert_reject("recipient mismatch") { verify(salt: 17, channel: {payee: pubkey(51)}) }
  end

  def test_rejects_non_empty_distribution
    assert_reject("empty-recipient") { verify(salt: 18, channel: {distribution_hash: "\x01".b * 32}) }
  end

  def test_rejects_channel_authorized_signer_mismatch
    assert_reject("authorized_signer is not the operator") { verify(salt: 19, channel: {authorized_signer: pubkey(52)}) }
  end

  def test_rejects_deposit_mismatch
    assert_reject("on-chain deposit") { verify(salt: 20, channel: {deposit: 1}) }
  end

  def test_rejects_payer_mismatch
    assert_reject("does not match payload.from") { verify(salt: 21, channel: {payer: pubkey(53)}) }
  end

  # ---- envelope + concurrency -------------------------------------------
  def test_rejects_non_upto_scheme
    engine, = build_case(salt: 22)
    bad = Base64.strict_encode64(JSON.generate({"scheme" => "exact", "payload" => {}}))
    assert_raises(::PayKit::Protocols::X402::Error::InvalidPayloadType) { engine.verify_open(bad, now: now) }
  end

  def test_in_flight_guard_blocks_concurrent_same_channel
    engine, header, = build_case(salt: 23)
    engine.verify_open(header, now: now) # holds the reservation (not settled)
    assert_reject("already being processed") { engine.verify_open(header, now: now) }
  end

  private

  def now = 1_000_000

  def channel_id(salt)
    PC.find_channel_pda(payer: @payer, payee: @payee, mint: @mint, authorized_signer: @operator, salt: salt)
  end

  # Build [engine, header, channel] for a fresh salt. Knobs let each test
  # corrupt exactly one input.
  def build_case(salt:, payload: {}, channel: {}, network: NETWORK, open_program: PC::PROGRAM_ID, open_payee: nil,
    open_salt: nil, open_deposit: nil, open_recipients_count: 0, open_grace_period: 900)
    cid = channel_id(salt)
    header = open_header(salt: salt, cid: cid, network: network, payload: payload,
      open_program: open_program, open_payee: open_payee || @payee,
      open_salt: open_salt || salt, open_deposit: open_deposit || MAX, open_recipients_count: open_recipients_count,
      open_grace_period: open_grace_period)
    fake = fake_channel(channel)
    engine = ::PayKit::Protocols::X402::Server::Upto.new(
      Upto::Config.new(
        rpc_url: "http://localhost:8899", pay_to: @payee, facilitator_secret_key: @operator_secret,
        amount: MAX.to_s, mint: @mint, network: NETWORK, token_program: @token_program,
        transaction_sender: ->(_c, _b) { "SiGnAtUrE1111111111111111111111111111111111" },
        signature_confirmer: ->(_c, sig) { sig }, channel_fetcher: ->(_c, _id) { fake },
        recent_blockhash_provider: -> { pubkey(9) }
      )
    )
    [engine, header, fake]
  end

  def verify(salt:, payload: {}, channel: {}, network: NETWORK, open_program: PC::PROGRAM_ID, open_payee: nil,
    now_override: nil, open_salt: nil, open_deposit: nil, open_recipients_count: 0, open_grace_period: 900)
    engine, header, = build_case(salt: salt, payload: payload, channel: channel, network: network,
      open_program: open_program, open_payee: open_payee,
      open_salt: open_salt, open_deposit: open_deposit, open_recipients_count: open_recipients_count,
      open_grace_period: open_grace_period)
    engine.verify_open(header, now: now_override || now)
  end

  def open_header(salt:, cid:, network:, payload:, open_program:, open_payee:, open_salt:, open_deposit:, open_recipients_count:, open_grace_period:)
    payer_token = ::PayCore::Solana::ATA.derive(owner: @payer, mint: @mint, token_program: @token_program)
    channel_token = ::PayCore::Solana::ATA.derive(owner: cid, mint: @mint, token_program: @token_program)
    ea = PC.find_event_authority_pda
    accounts = [
      AM.signer_writable(@payer), AM.signer_writable(@operator), AM.readonly(open_payee), AM.readonly(@mint),
      AM.readonly(@operator), AM.writable(cid), AM.writable(payer_token), AM.writable(channel_token),
      AM.readonly(@token_program), AM.readonly(PC::SYSTEM_PROGRAM), AM.readonly(PC::RENT_SYSVAR),
      AM.readonly(PC::ASSOCIATED_TOKEN_PROGRAM), AM.readonly(ea), AM.readonly(PC::PROGRAM_ID)
    ]
    data = [1].pack("C") + PC.u64_le(open_salt) + PC.u64_le(open_deposit) + PC.u32_le(open_grace_period) + PC.u32_le(open_recipients_count)
    open_recipients_count.times { data += ::PayCore::Solana::Base58.decode(@payee) + [1].pack("v") }
    tx = MB.build_legacy(fee_payer: @operator, recent_blockhash: pubkey(9),
      instructions: [::PayCore::Solana::PreparedInstruction.new(open_program, accounts, data)])
    body = {
      "profile" => "payment-channel", "from" => @payer, "maxAmount" => MAX.to_s, "expiresAt" => 4_102_444_800,
      "validAfter" => 0, "nonce" => "n#{salt}", "channelId" => cid, "deposit" => MAX.to_s,
      "authorizedSigner" => @operator, "openTransaction" => tx.to_base64
    }.merge(payload)
    Base64.strict_encode64(JSON.generate({"x402Version" => 2, "scheme" => "upto", "network" => network, "payload" => body}))
  end

  def fake_channel(overrides)
    defaults = {
      status: 0, deposit: MAX, mint: @mint, payee: @payee, distribution_hash: PC::EMPTY_DISTRIBUTION_HASH,
      authorized_signer: @operator, rent_payer: @operator, payer: @payer, settled: 0
    }
    PC::Channel.new(**defaults.merge(overrides))
  end

  def assert_reject(fragment)
    error = assert_raises(::PayKit::Protocols::X402::Error::PaymentInvalid) { yield }
    assert_includes error.message, fragment
  end
end
