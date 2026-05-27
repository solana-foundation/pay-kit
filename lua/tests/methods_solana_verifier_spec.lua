local helper = require('tests.test_helper')
local transaction = require('pay_kit.solana.transaction')
local verifier = require('pay_kit.solana.verifier')
local base58 = require('pay_kit.solana.base58')
local ata = require('pay_kit.solana.ata')
local instructions = require('pay_kit.solana.instructions')

local function le_u64(value)
  local bytes = {}
  for _ = 1, 8 do
    bytes[#bytes + 1] = string.char(value % 256)
    value = math.floor(value / 256)
  end
  return table.concat(bytes)
end

-- Encode an instruction in wire format.
local function encode_instruction(program_id_index, accounts, data)
  local parts = { string.char(program_id_index), transaction.compact_u16(#accounts) }
  for _, a in ipairs(accounts) do
    parts[#parts + 1] = string.char(a)
  end
  parts[#parts + 1] = transaction.compact_u16(#data)
  parts[#parts + 1] = data
  return table.concat(parts)
end

-- Build a legacy transaction message from the given account keys list
-- (32-byte raw strings), a blockhash, and an array of instruction wire
-- payloads.
local function build_message(account_key_bytes, blockhash, instructions_wire, required_signatures)
  local parts = {
    string.char(required_signatures, 0, 0),
    transaction.compact_u16(#account_key_bytes),
  }
  for _, k in ipairs(account_key_bytes) do
    parts[#parts + 1] = k
  end
  parts[#parts + 1] = blockhash
  parts[#parts + 1] = transaction.compact_u16(#instructions_wire)
  for _, ix in ipairs(instructions_wire) do
    parts[#parts + 1] = ix
  end
  return table.concat(parts)
end

local function tx_from(message, signature_count)
  local parts = { transaction.compact_u16(signature_count) }
  for _ = 1, signature_count do
    parts[#parts + 1] = string.rep('\0', 64)
  end
  parts[#parts + 1] = message
  return transaction.from_bytes(table.concat(parts))
end

local USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
local USDC_BYTES = base58.decode(USDC)
local TOKEN_PROGRAM_BYTES = base58.decode(instructions.TOKEN_PROGRAM)
local SYSTEM_PROGRAM_BYTES = base58.decode(instructions.SYSTEM_PROGRAM)
local MEMO_PROGRAM_BYTES = base58.decode(instructions.MEMO_PROGRAM)

helper.test('verifier accepts a basic SPL transferChecked of the requested amount', function()
  local payer_bytes = string.rep('\x01', 32)
  local source_ata_bytes = string.rep('\x02', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata = ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM)
  local recipient_ata_bytes = base58.decode(recipient_ata)

  local account_keys = {
    payer_bytes, source_ata_bytes, recipient_ata_bytes, recipient_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES,
  }
  local data = string.char(12) .. le_u64(1000000) .. string.char(6)
  local ix = encode_instruction(5, { 1, 4, 2, 0 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  verifier.verify_transaction(tx, {
    amount = '1000000',
    currency = USDC,
    recipient = recipient_pub,
    methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM },
  })
end)

helper.test('verifier rejects an amount mismatch', function()
  local payer_bytes = string.rep('\x01', 32)
  local source_ata_bytes = string.rep('\x02', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata_bytes = base58.decode(ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM))
  local account_keys = {
    payer_bytes, source_ata_bytes, recipient_ata_bytes, recipient_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES,
  }
  local data = string.char(12) .. le_u64(999999) .. string.char(6)
  local ix = encode_instruction(5, { 1, 4, 2, 0 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000000', currency = USDC, recipient = recipient_pub,
      methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM },
    })
  end, 'No matching SPL transferChecked')
end)

helper.test('verifier rejects an unauthorized program after the transfer matches', function()
  -- The allowlist sweep runs after the transfer match succeeds, so the
  -- "unexpected program" path requires a transaction that contains both
  -- a valid transferChecked and an unrelated extra instruction whose
  -- program id is outside the allowlist.
  local payer_bytes = string.rep('\x01', 32)
  local source_ata_bytes = string.rep('\x02', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata_bytes = base58.decode(ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM))
  local random_program_bytes = string.rep('\x55', 32)
  local account_keys = {
    payer_bytes, source_ata_bytes, recipient_ata_bytes, recipient_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES, random_program_bytes,
  }
  local transfer = encode_instruction(5, { 1, 4, 2, 0 },
    string.char(12) .. le_u64(1000000) .. string.char(6))
  local stranger = encode_instruction(6, { 0 }, 'unknown-program-payload')
  local message = build_message(account_keys, string.rep('\xc3', 32), { transfer, stranger }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000000', currency = USDC, recipient = recipient_pub,
      methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM },
    })
  end, 'Unexpected program')
end)

helper.test('verifier accepts a SOL transfer to the recipient', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local account_keys = {
    payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES,
  }
  local data = string.char(2, 0, 0, 0) .. le_u64(5000)
  local ix = encode_instruction(2, { 0, 1 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  verifier.verify_transaction(tx, {
    amount = '5000',
    currency = 'SOL',
    recipient = recipient_pub,
    methodDetails = {},
  })
end)

helper.test('verifier rejects v0 address-table lookups', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES }
  -- Build a v0 transaction with one address-table lookup.
  local message = table.concat({
    string.char(0x80),
    string.char(1, 0, 0),
    transaction.compact_u16(#account_keys),
    table.concat(account_keys),
    string.rep('\xc3', 32),
    transaction.compact_u16(0),
    transaction.compact_u16(1),
    string.rep('\xa9', 32),
    transaction.compact_u16(0),
    transaction.compact_u16(0),
  })
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1', currency = 'SOL', recipient = recipient_pub,
      methodDetails = {},
    })
  end, 'v0 address lookup tables are not supported')
end)

helper.test('verifier rejects a memo over 566 bytes', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local oversized = string.rep('m', 567)
  -- Build a SOL flow with the oversized externalId; the transaction only
  -- needs the SOL transfer plus the (oversized) memo instruction so the
  -- verifier's memo branch is the one that raises.
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES, MEMO_PROGRAM_BYTES }
  local transfer = encode_instruction(2, { 0, 1 }, string.char(2, 0, 0, 0) .. le_u64(1))
  local memo = encode_instruction(3, {}, oversized)
  local message = build_message(account_keys, string.rep('\xc3', 32), { transfer, memo }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1', currency = 'SOL', recipient = recipient_pub,
      externalId = oversized,
      methodDetails = {},
    })
  end, 'memo cannot exceed 566 bytes')
end)

helper.test('verifier rejects an SPL transfer with the wrong decimals byte', function()
  local payer_bytes = string.rep('\x01', 32)
  local source_ata_bytes = string.rep('\x02', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata_bytes = base58.decode(ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM))
  local account_keys = {
    payer_bytes, source_ata_bytes, recipient_ata_bytes, recipient_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES,
  }
  local data = string.char(12) .. le_u64(1000000) .. string.char(9) -- wrong decimals
  local ix = encode_instruction(5, { 1, 4, 2, 0 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000000', currency = USDC, recipient = recipient_pub,
      methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM },
    })
  end, 'No matching SPL transferChecked')
end)

helper.test('verifier rejects when fee_payer authority equals the signer', function()
  -- feePayer=true with the fee_payer matching the transferChecked authority
  -- must reject (the fee payer is not allowed to be the source of the payment).
  local fee_payer_bytes = string.rep('\x01', 32)
  local fee_payer_pub = base58.encode(fee_payer_bytes)
  local source_ata_bytes = string.rep('\x02', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata_bytes = base58.decode(ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM))
  local account_keys = {
    fee_payer_bytes, source_ata_bytes, recipient_ata_bytes, recipient_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES,
  }
  local data = string.char(12) .. le_u64(1000000) .. string.char(6)
  -- authority is account_keys[1] = fee_payer_bytes; the verifier rejects.
  local ix = encode_instruction(5, { 1, 4, 2, 0 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000000', currency = USDC, recipient = recipient_pub,
      methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM,
        feePayer = true, feePayerKey = fee_payer_pub, network = 'mainnet-beta' },
    })
  end, 'fee payer cannot authorize')
end)

helper.test('verifier rejects feePayer=true without feePayerKey', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES }
  local data = string.char(2, 0, 0, 0) .. le_u64(1)
  local ix = encode_instruction(2, { 0, 1 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1', currency = 'SOL', recipient = recipient_pub,
      methodDetails = { feePayer = true },
    })
  end, 'feePayer=true requires feePayerKey')
end)

helper.test('verifier rejects too many splits', function()
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local payer_bytes = string.rep('\x01', 32)
  local message = build_message({ payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES },
    string.rep('\xc3', 32), {}, 1)
  local tx = tx_from(message, 1)
  local many = {}
  for i = 1, 9 do
    many[#many + 1] = { recipient = recipient_pub, amount = '1' }
  end
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '100', currency = 'SOL', recipient = recipient_pub,
      methodDetails = { splits = many },
    })
  end, 'too many splits')
end)

helper.test('verifier rejects an SPL transfer where source_ata equals the fee-payer ATA', function()
  local fee_payer_bytes = string.rep('\x01', 32)
  local fee_payer_pub = base58.encode(fee_payer_bytes)
  local fee_payer_ata_bytes = base58.decode(ata.derive(fee_payer_pub, USDC, instructions.TOKEN_PROGRAM))
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local recipient_ata_bytes = base58.decode(ata.derive(recipient_pub, USDC, instructions.TOKEN_PROGRAM))
  -- Place a separate authority pubkey so the "authority == fee payer" branch
  -- is bypassed and the test exercises the source_ata == fee_payer_ata branch.
  local separate_authority_bytes = string.rep('\x44', 32)
  local account_keys = {
    fee_payer_bytes, fee_payer_ata_bytes, recipient_ata_bytes, separate_authority_bytes,
    USDC_BYTES, TOKEN_PROGRAM_BYTES,
  }
  local data = string.char(12) .. le_u64(1000) .. string.char(6)
  local ix = encode_instruction(5, { 1, 4, 2, 3 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000', currency = USDC, recipient = recipient_pub,
      methodDetails = { decimals = 6, tokenProgram = instructions.TOKEN_PROGRAM,
        feePayer = true, feePayerKey = fee_payer_pub, network = 'mainnet-beta' },
    })
  end, 'fee payer token account cannot fund')
end)

helper.test('verifier verify_transaction_base64 round-trips a wire payload', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES }
  local data = string.char(2, 0, 0, 0) .. le_u64(7)
  local ix = encode_instruction(2, { 0, 1 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local raw = table.concat({ transaction.compact_u16(1), string.rep('\0', 64), message })
  local b64 = require('pay_kit.util.base64_std').encode(raw)
  verifier.verify_transaction_base64(b64, {
    amount = '7', currency = 'SOL', recipient = recipient_pub,
    methodDetails = {},
  })
end)

helper.test('verifier new_callback wraps verify_transaction_base64 with a request', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES }
  local data = string.char(2, 0, 0, 0) .. le_u64(11)
  local ix = encode_instruction(2, { 0, 1 }, data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { ix }, 1)
  local raw = table.concat({ transaction.compact_u16(1), string.rep('\0', 64), message })
  local b64 = require('pay_kit.util.base64_std').encode(raw)
  local callback = verifier.new_callback()
  callback(b64, {
    amount = '11', currency = 'SOL', recipient = recipient_pub,
    methodDetails = {},
  })
end)

helper.test('verifier new_blockhash_extractor returns the parsed blockhash', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local blockhash_bytes = string.rep('\xc3', 32)
  local account_keys = { payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES }
  local message = build_message(account_keys, blockhash_bytes, {}, 1)
  local raw = table.concat({ transaction.compact_u16(1), string.rep('\0', 64), message })
  local b64 = require('pay_kit.util.base64_std').encode(raw)
  local extractor = verifier.new_blockhash_extractor()
  helper.assert_equal(extractor(b64), base58.encode(blockhash_bytes))
end)

helper.test('verifier rejects ataCreationRequired for any symbol resolving to a different mint', function()
  -- Earlier draft only rejected when the credential currency was one of
  -- five hardcoded stablecoin symbols (USDC, USDT, USDG, PYUSD, CASH).
  -- Any other symbol that protocol.resolve_mint expanded to a known mint
  -- silently bypassed the guard. The fix removes the whitelist and
  -- mirrors `ruby/lib/mpp/methods/solana/verifier.rb`: reject whenever
  -- the resolved mint differs from request.currency.
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local payer_bytes = string.rep('\x01', 32)
  local message = build_message({ payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES },
    string.rep('\xc3', 32), {}, 1)
  local tx = tx_from(message, 1)

  -- Lowercase 'usdc' resolves to the canonical USDC mint, which differs
  -- from the credential's 'usdc' string. Must reject.
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000', currency = 'usdc', recipient = recipient_pub,
      methodDetails = {
        decimals = 6,
        tokenProgram = instructions.TOKEN_PROGRAM,
        network = 'mainnet-beta',
        splits = { { recipient = recipient_pub, amount = '100', ataCreationRequired = true } },
      },
    })
  end, 'ataCreationRequired requires currency to be an SPL token mint address')

  -- Stablecoin alias paths. USDG resolves via the Token-2022 symbol table;
  -- the old whitelist happened to list it, but a future Token-2022 alias
  -- added to KNOWN_MINTS without updating the whitelist would slip past.
  -- The new guard rejects unconditionally on mint mismatch.
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1000', currency = 'USDG', recipient = recipient_pub,
      methodDetails = {
        decimals = 6,
        tokenProgram = instructions.TOKEN_2022_PROGRAM,
        network = 'mainnet-beta',
        splits = { { recipient = recipient_pub, amount = '100', ataCreationRequired = true } },
      },
    })
  end, 'ataCreationRequired requires currency to be an SPL token mint address')
end)

helper.test('verifier rejects compute-budget over the unit limit cap', function()
  local payer_bytes = string.rep('\x01', 32)
  local recipient_bytes = string.rep('\x03', 32)
  local recipient_pub = base58.encode(recipient_bytes)
  local compute_budget_bytes = base58.decode(instructions.COMPUTE_BUDGET_PROGRAM)
  local account_keys = {
    payer_bytes, recipient_bytes, SYSTEM_PROGRAM_BYTES, compute_budget_bytes,
  }
  local transfer = encode_instruction(2, { 0, 1 }, string.char(2, 0, 0, 0) .. le_u64(1))
  -- limit 200001 = one above the cap.
  local cb_data = string.char(2) .. string.char(0x41, 0x0d, 0x03, 0x00) -- 200001 LE
  local cb = encode_instruction(3, {}, cb_data)
  local message = build_message(account_keys, string.rep('\xc3', 32), { transfer, cb }, 1)
  local tx = tx_from(message, 1)
  helper.assert_error(function()
    verifier.verify_transaction(tx, {
      amount = '1', currency = 'SOL', recipient = recipient_pub,
      methodDetails = {},
    })
  end, 'Compute unit limit')
end)
