local helper = require('tests.test_helper')
local instructions = require('pay_kit.solana.instructions')

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
  -- Discriminator 99 has no documented compute-budget semantics, so the
  -- parser must reject it. The previously-bundled-in cases (disc 0/1/4)
  -- are now valid non-cap pass-through and have a dedicated test below.
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(99), {}))
  end, 'Unsupported')
end)

helper.test('parse_compute_budget accepts disc 0/1/4 as non-cap pass-through', function()
  -- The hooks-based verifier in `pay_kit.protocols.mpp.server.solana_verify` accepts
  -- discriminators 0 (RequestUnits, deprecated), 1 (RequestHeapFrame),
  -- and 4 (SetLoadedAccountsDataSizeLimit) without enforcing compute
  -- caps. The real verifier path here must match that behavior so a
  -- wallet that inserts a RequestHeapFrame instruction does not
  -- verify under hooks but fail with `payment_invalid` under the
  -- real verifier. Regression coverage for the behavioral split.
  for _, disc in ipairs({ 0, 1, 4 }) do
    local parsed = instructions.parse_compute_budget(build_ix(string.char(disc), {}))
    helper.assert_equal(parsed.kind, 'compute_budget_noop')
    helper.assert_equal(parsed.discriminator, disc)
  end
end)

helper.test('decode_le_uint round-trips a 2^63 value as a decimal string', function()
  -- 2^63 = 9223372036854775808; the high bit lives in the eighth byte.
  local high = string.rep('\0', 7) .. string.char(0x80)
  helper.assert_equal(instructions.decode_le_uint(high, 1, 8), '9223372036854775808')
end)

helper.test('parse_compute_budget compares u64 prices through uint.compare, not tonumber', function()
  -- Earlier draft used tonumber(price_str) before comparing against the
  -- cap. Lua doubles only carry 53 significant bits, so a u64 price above
  -- 2^53 collapses to the nearest representable float and the cap check
  -- fires on the wrong side of the boundary. Regression test:
  --
  -- (a) A value one above 2^53 must compare strictly greater than the
  --     current cap of 5_000_000. Confirms the string-comparison path is
  --     live (the float comparison would say 2^53+1 == 2^53 and could
  --     drop below the cap when the cap is also coerced to float).
  -- (b) A value one above the cap (5_000_001) must reject.
  -- (c) A value exactly at the cap (5_000_000) must accept.

  local function build_price(value_decimal_string)
    -- Convert a decimal string into 8 little-endian bytes for the price
    -- payload. Operates on the digits directly so values above 2^53 stay
    -- exact (the same reason the parser itself avoids tonumber).
    local digits = { 0, 0, 0, 0, 0, 0, 0, 0 }
    for i = 1, #value_decimal_string do
      local carry = tonumber(value_decimal_string:sub(i, i))
      for j = 1, 8 do
        local v = digits[j] * 10 + carry
        digits[j] = v % 256
        carry = math.floor(v / 256)
      end
    end
    local out = {}
    for j = 1, 8 do out[j] = string.char(digits[j]) end
    return table.concat(out)
  end

  -- (a) 2^53 + 1 over the u64 cap must reject through the string path.
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(3) .. build_price('9007199254740993'), {}))
  end, 'exceeds maximum')

  -- (b) cap + 1 rejects.
  helper.assert_error(function()
    instructions.parse_compute_budget(build_ix(string.char(3) .. build_price('5000001'), {}))
  end, 'exceeds maximum')

  -- (c) cap itself is allowed.
  local at_cap = instructions.parse_compute_budget(build_ix(string.char(3) .. build_price('5000000'), {}))
  helper.assert_equal(at_cap.kind, 'compute_budget_set_price')
  helper.assert_equal(at_cap.price, '5000000')
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
