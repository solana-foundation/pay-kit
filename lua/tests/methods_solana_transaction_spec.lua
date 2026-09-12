local helper = require('tests.test_helper')
local transaction = require('pay_kit.solana.transaction')
local base58 = require('pay_kit.solana.base58')
local base64_std = require('pay_kit.util.base64_std')

-- Helper: build a minimal transaction wire payload with one signature, one
-- account key, the System Program implicit recipient, a known blockhash, and
-- one zero-byte instruction. `versioned` selects the v0 framing (0x80 prefix
-- plus an empty address-table-lookup vector) the codec accepts; the legacy
-- framing is only built to assert rejection.
local function build_fixture(versioned)
  local signature = string.rep('\x11', 64)
  local fee_payer = string.rep('\xa1', 32)
  local recipient = string.rep('\xb2', 32)
  local blockhash = string.rep('\xc3', 32)
  -- message: header (1 required signature, 0 readonly signed, 1 readonly
  -- unsigned), 2 account keys, blockhash, 1 instruction referencing program
  -- id index 1 with empty accounts and empty data.
  local message = table.concat({
    versioned and string.char(0x80) or '',  -- v0 marker
    string.char(1, 0, 1),         -- header
    transaction.compact_u16(2),    -- 2 account keys
    fee_payer,
    recipient,
    blockhash,
    transaction.compact_u16(1),    -- 1 instruction
    string.char(1),                -- program_id_index
    transaction.compact_u16(0),    -- 0 accounts
    transaction.compact_u16(0),    -- 0 data bytes
    versioned and transaction.compact_u16(0) or '',  -- 0 address-table lookups
  })
  local raw = table.concat({
    transaction.compact_u16(1),    -- 1 signature
    signature,
    message,
  })
  return {
    raw = raw,
    signature = signature,
    fee_payer = base58.encode(fee_payer),
    recipient = base58.encode(recipient),
    blockhash = base58.encode(blockhash),
    message = message,
  }
end

local function build_v0_fixture() return build_fixture(true) end

helper.test('transaction.from_bytes rejects a legacy (unprefixed) message', function()
  local fixture = build_fixture(false)
  local ok, err = pcall(transaction.from_bytes, fixture.raw)
  helper.assert_true(not ok, 'legacy wire must be rejected')
  helper.assert_equal(err, 'legacy transactions are not supported; use a version 0 or version 1 message')
  -- from_base64 surfaces the same text verbatim (no payload-wrap prefix).
  local ok64, err64 = pcall(transaction.from_base64, base64_std.encode(fixture.raw))
  helper.assert_true(not ok64, 'legacy wire must be rejected')
  helper.assert_equal(err64, transaction.LEGACY_UNSUPPORTED)
end)

helper.test('transaction.from_bytes parses a minimal v0 fixture', function()
  local fixture = build_v0_fixture()
  local tx = transaction.from_bytes(fixture.raw)
  helper.assert_equal(#tx.signatures, 1)
  helper.assert_equal(tx.signatures[1], fixture.signature)
  helper.assert_equal(tx.version, 0)
  helper.assert_equal(tx.message.header.required_signatures, 1)
  helper.assert_equal(tx.message.account_keys[1], fixture.fee_payer)
  helper.assert_equal(tx.message.account_keys[2], fixture.recipient)
  helper.assert_equal(tx.message.recent_blockhash, fixture.blockhash)
  helper.assert_equal(#tx.message.instructions, 1)
  helper.assert_equal(tx.message.instructions[1].program_id_index, 1)
  helper.assert_equal(#tx.message.address_table_lookups, 0)
end)

helper.test('transaction.to_bytes round-trips a v0 fixture', function()
  local fixture = build_v0_fixture()
  local tx = transaction.from_bytes(fixture.raw)
  helper.assert_equal(transaction.to_bytes(tx), fixture.raw)
end)

helper.test('transaction.from_base64 decodes the standard-alphabet payload', function()
  local fixture = build_v0_fixture()
  local encoded = base64_std.encode(fixture.raw)
  local tx = transaction.from_base64(encoded)
  helper.assert_equal(transaction.to_base64(tx), encoded)
end)

helper.test('transaction.from_bytes parses a v0 fixture with a single lookup', function()
  -- Build a v0 transaction: 0x80 prefix, header, 1 account key, blockhash,
  -- 0 instructions, 1 address-table lookup referencing one writable index.
  local signature = string.rep('\x22', 64)
  local payer = string.rep('\xa1', 32)
  local lookup_account = string.rep('\xa2', 32)
  local blockhash = string.rep('\xc3', 32)
  local message = table.concat({
    string.char(0x80),             -- v0 marker
    string.char(1, 0, 0),          -- header
    transaction.compact_u16(1),    -- 1 account key
    payer,
    blockhash,
    transaction.compact_u16(0),    -- 0 instructions
    transaction.compact_u16(1),    -- 1 address table lookup
    lookup_account,
    transaction.compact_u16(1),    -- 1 writable index
    string.char(0),
    transaction.compact_u16(0),    -- 0 readonly indices
  })
  local raw = table.concat({
    transaction.compact_u16(1),
    signature,
    message,
  })
  local tx = transaction.from_bytes(raw)
  helper.assert_equal(tx.version, 0)
  helper.assert_equal(#tx.message.address_table_lookups, 1)
  helper.assert_equal(#tx.message.address_table_lookups[1].writable, 1)
  helper.assert_equal(tx.message.address_table_lookups[1].writable[1], 0)
end)

helper.test('transaction.compact_u16 round-trips known small and large values', function()
  -- 0 -> single byte 0x00
  helper.assert_equal(transaction.compact_u16(0), string.char(0))
  -- 127 -> single byte 0x7f
  helper.assert_equal(transaction.compact_u16(127), string.char(0x7f))
  -- 128 -> two bytes 0x80 0x01
  helper.assert_equal(transaction.compact_u16(128), string.char(0x80, 0x01))
  -- 16384 -> three bytes 0x80 0x80 0x01
  helper.assert_equal(transaction.compact_u16(16384), string.char(0x80, 0x80, 0x01))
end)

helper.test('transaction.replace_signature swaps one signature slot in place', function()
  local fixture = build_v0_fixture()
  local tx = transaction.from_bytes(fixture.raw)
  local fresh = string.rep('\xee', 64)
  transaction.replace_signature(tx, 1, fresh)
  helper.assert_equal(tx.signatures[1], fresh)
  helper.assert_error(function()
    transaction.replace_signature(tx, 1, 'short')
  end, 'signature must be')
end)

helper.test('transaction.index_of_account returns the matching account index', function()
  local fixture = build_v0_fixture()
  local tx = transaction.from_bytes(fixture.raw)
  helper.assert_equal(transaction.index_of_account(tx, fixture.fee_payer), 1)
  helper.assert_equal(transaction.index_of_account(tx, fixture.recipient), 2)
  helper.assert_true(transaction.index_of_account(tx, '11111111111111111111111111111111') == nil)
end)
