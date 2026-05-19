package.path = table.concat({
  '../../lua/?.lua',
  '../../lua/?/init.lua',
  './lua/?.lua',
  './lua/?/init.lua',
  package.path,
}, ';')

local json = require('mpp.util.json')
local mpp = require('mpp')

local function read_stdin()
  return io.read('*a')
end

local function write_json(value)
  io.write(json.encode(value))
  io.write('\n')
end

local function required(input, key)
  local value = input[key]
  if value == nil or value == '' then
    error(key .. ' is required')
  end
  return value
end

local function new_server(input, verify_payment)
  return mpp.server.new({
    recipient = required(input, 'recipient'),
    currency = required(input, 'currency'),
    decimals = input.decimals or 6,
    network = input.network or 'localnet',
    secret_key = required(input, 'secretKey'),
    fee_payer = input.feePayer == true,
    fee_payer_key = input.feePayerKey,
    recent_blockhash = input.recentBlockhash,
    store = mpp.store.memory(),
    verify_payment = verify_payment,
  })
end

local function challenge(input)
  local server = new_server(input, function(context)
    return { reference = context.payload.signature or context.payload.transaction }
  end)
  local challenge_value = server:charge_with_options(required(input, 'price'), {
    description = input.description,
    fee_payer = input.feePayer == true,
    fee_payer_key = input.feePayerKey,
    recent_blockhash = input.recentBlockhash,
    splits = input.splits,
  })
  write_json({
    type = 'challenge',
    wwwAuthenticate = mpp.FormatWWWAuthenticate(challenge_value),
    request = challenge_value.request:decode(),
  })
end

local function verify(input)
  local authorization = required(input, 'authorization')
  local credential = mpp.ParseAuthorization(authorization)
  local server = new_server(input, function(context)
    return { reference = context.payload.signature or context.payload.transaction }
  end)
  local receipt = server:verify_credential_with_expected(
    credential,
    required(input, 'expected'),
    input.now
  )
  write_json({
    type = 'verified',
    receipt = mpp.FormatReceipt(receipt),
    reference = receipt.reference,
    transaction = credential.payload and credential.payload.transaction or nil,
    signature = credential.payload and credential.payload.signature or nil,
  })
end

local function main()
  local input = json.decode(read_stdin())
  local command = required(input, 'command')
  if command == 'challenge' then
    challenge(input)
    return
  end
  if command == 'verify' then
    verify(input)
    return
  end
  error('unsupported command: ' .. tostring(command))
end

local ok, err = pcall(main)
if not ok then
  write_json({
    type = 'error',
    error = tostring(err),
  })
  os.exit(1)
end
