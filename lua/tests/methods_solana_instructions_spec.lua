local helper = require('tests.test_helper')
local instructions = require('mpp.methods.solana.instructions')

local function build_ix(data, accounts)
  return { data = data, accounts = accounts or {}, program_id_index = 0 }
end

local function le_u64(value)
  local bytes = {}
  for _ = 1, 8 do
    bytes[#bytes + 1] = string.char(value % 256)
    value = math.floor(value / 256)
  end
  return table.concat(bytes)
end

local function le_u32(value)
  local bytes = {}
  for _ = 1, 4 do
    bytes[#bytes + 1] = string.char(value % 256)
    value = math.floor(value / 256)
  end
  return table.concat(bytes)
end

helper.test('parse_transfer_checked decodes amount and decimals', function()
  local data = string.char(12) .. le_u64(1000000) .. string.char(6)
  local parsed = instructions.parse_transfer_checked(build_ix(data, { 0, 1, 2, 3 }))
  helper.assert_true(parsed ~= nil)
  helper.assert_equal(parsed.kind, 'spl_transfer_checked')
  helper.assert_equal(parsed.amount, '1000000')
  helper.assert_equal(parsed.decimals, 6)
end)

helper.test('parse_transfer_checked rejects a non-transferChecked discriminator', function()
  local data = string.char(3) .. le_u64(1) .. string.char(6)
  helper.assert_true(instructions.parse_transfer_checked(build_ix(data, { 0, 1, 2, 3 })) == nil)
end)

helper.test('parse_system_transfer decodes the lamport amount', function()
  local data = le_u32(2) .. le_u64(123456)
  local parsed = instructions.parse_system_transfer(build_ix(data, { 0, 1 }))
  helper.assert_true(parsed ~= nil)
  helper.assert_equal(parsed.kind, 'system_transfer')
  helper.assert_equal(parsed.lamports, '123456')
end)

helper.test('parse_system_transfer rejects a non-transfer discriminator', function()
  local data = le_u32(0) .. le_u64(1)
  helper.assert_true(instructions.parse_system_transfer(build_ix(data, { 0, 1 })) == nil)
end)

helper.test('parse_memo returns the data field verbatim', function()
  local parsed = instructions.parse_memo(build_ix('hello-memo', {}))
  helper.assert_equal(parsed.kind, 'memo')
  helper.assert_equal(parsed.memo, 'hello-memo')
end)

helper.test('parse_ata_create distinguishes idempotent from create', function()
  helper.assert_equal(instructions.parse_ata_create(build_ix('', {})).idempotent, false)
  helper.assert_equal(instructions.parse_ata_create(build_ix(string.char(0), {})).idempotent, false)
  helper.assert_equal(instructions.parse_ata_create(build_ix(string.char(1), {})).idempotent, true)
  helper.assert_true(instructions.parse_ata_create(build_ix(string.char(2), {})) == nil)
end)

helper.test('parse_compute_budget enforces the unit limit cap', function()
  local under = string.char(2) .. le_u32(200000)
  local parsed = instructions.parse_compute_budget(build_ix(under, {}))
  helper.assert_equal(parsed.kind, 'compute_budget_set_limit')
  helper.assert_equal(parsed.limit, '200000')
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(2) .. le_u32(200001), {}))
  end, 'exceeds maximum')
end)

helper.test('parse_compute_budget enforces the unit price cap', function()
  local under = string.char(3) .. le_u64(5000000)
  local parsed = instructions.parse_compute_budget(build_ix(under, {}))
  helper.assert_equal(parsed.kind, 'compute_budget_set_price')
  helper.assert_equal(parsed.price, '5000000')
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(3) .. le_u64(5000001), {}))
  end, 'exceeds maximum')
end)

helper.test('parse_compute_budget rejects accounts and unknown discriminators', function()
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(2) .. le_u32(1), { 0 }))
  end, 'must not have accounts')
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(0), {}))
  end, 'Unsupported')
end)

helper.test('decode_le_uint round-trips a 2^63 value as a decimal string', function()
  -- 2^63 = 9223372036854775808; the high bit lives in the eighth byte.
  local high = string.rep('\0', 7) .. string.char(0x80)
  helper.assert_equal(instructions.decode_le_uint(high, 1, 8), '9223372036854775808')
end)

helper.test('program_id_for resolves the program-id index against the account keys', function()
  local tx = {
    message = {
      account_keys = { 'AKey1', 'BKey2', 'CKey3' },
    },
  }
  helper.assert_equal(instructions.program_id_for(tx, { program_id_index = 1 }), 'BKey2')
  helper.assert_error(function()
    instructions.program_id_for(tx, { program_id_index = 7 })
  end, 'invalid program id')
end)
