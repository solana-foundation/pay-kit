--[[
Boot-time soundness checks for the operator wallet. Mirrors Ruby PR
#142 follow-up:

1. The fee payer (operator.signer) has enough SOL to settle.
2. Every stablecoin in `c.stablecoins` has an ATA owned by the
   operator's recipient.

On `solana_localnet` with the gem-shipped demo signer, missing
accounts are auto-provisioned via Surfnet's cheatcodes
(`surfnet_setAccount`, `surfnet_setTokenAccount`) so the example
apps "just work" against https://402.surfnet.dev:8899 without
manual setup. Everywhere else, missing accounts raise so the
operator is told at boot rather than at the first 402 retry.

RPC failures during preflight are logged, not raised, so an
unreachable endpoint never blocks boot. The runtime resurfaces the
connection problem on the first request.

Opt-out: `c.preflight = false` or `PAY_KIT_DISABLE_PREFLIGHT=1`.
]]

local rpc_mod       = require('pay_kit.solana.rpc')
local rpc_transport = require('pay_kit.solana.rpc_transport')
local ata_mod       = require('pay_kit.solana.ata')
local solana_mod    = require('pay_kit.solana.mints')

local M = {}

-- Env var name + on-disk key for the MPP challenge-binding secret. Matches
-- the Ruby preflight convention (`PAY_KIT_MPP_CHALLENGE_BINDING_SECRET`)
-- so the same orchestrator-supplied env var feeds every server-side port.
M.MPP_SECRET_ENV_VAR = 'PAY_KIT_MPP_CHALLENGE_BINDING_SECRET'

-- 0.001 SOL: ~200 settlement txs at 5000 lamports each.
M.MIN_FEE_PAYER_LAMPORTS = 1000000
-- Generous local sandbox budget so a developer can poke the example
-- for hours without re-funding.
M.AUTOFUND_LAMPORTS = 10000000000
M.SYSTEM_PROGRAM_ID = '11111111111111111111111111111111'

local function log_warn(msg)
  io.stderr:write('[pay_kit preflight] WARN ' .. msg .. '\n')
end

local function log_info(msg)
  io.stderr:write('[pay_kit preflight] INFO ' .. msg .. '\n')
end

local function pay_kit_network_label(network)
  if network == 'solana_mainnet' then return 'mainnet' end
  if network == 'solana_devnet' then return 'devnet' end
  if network == 'solana_localnet' then return 'localnet' end
  error('pay_kit preflight: no mints label for network ' .. tostring(network))
end

-- Localnet + demo signer is the only combination where we silently
-- mutate on-chain state. Both gates matter: we never want preflight
-- to touch a real wallet's funds, and we never want to issue
-- cheatcodes against a network that does not support them.
local function autofix_enabled(config)
  if config.network ~= 'solana_localnet' then return false end
  local signer = config.operator and config.operator:signer()
  return signer and signer.demo and signer:demo()
end

local function check_fee_payer_sol(config, rpc, autofix)
  if not (config.operator and config.operator:fee_payer()) then return end
  local pubkey = config.operator:signer():pubkey()
  local result = rpc:call('getBalance', {pubkey, {commitment = 'confirmed'}})
  local lamports = (type(result) == 'table' and result.value) or 0
  if lamports >= M.MIN_FEE_PAYER_LAMPORTS then return end

  if autofix then
    log_info('funding demo fee-payer ' .. pubkey ..
             ' with ' .. M.AUTOFUND_LAMPORTS .. ' lamports via surfnet_setAccount')
    rpc:call('surfnet_setAccount', {
      pubkey,
      {
        lamports   = M.AUTOFUND_LAMPORTS,
        data       = '',
        executable = false,
        owner      = M.SYSTEM_PROGRAM_ID,
        rentEpoch  = 0,
      },
    })
  else
    error('pay_kit preflight: fee-payer ' .. pubkey .. ' has ' ..
          tostring(lamports) .. ' lamports on ' .. config.network ..
          ' (need >= ' .. M.MIN_FEE_PAYER_LAMPORTS ..
          '). Fund the account before booting.')
  end
end

local function check_recipient_ata(config, rpc, coin, network_label, autofix)
  local mint = solana_mod.resolve_mint(coin, network_label)
  -- Native SOL: no ATA to check.
  if not mint or (mint == coin and coin:upper() == 'SOL') then return end
  local token_program = solana_mod.default_token_program_for_currency(coin, network_label)
  local recipient = config.operator:effective_recipient()
  local ata = ata_mod.derive(recipient, mint, token_program)

  local info = rpc:call('getAccountInfo',
    {ata, {encoding = 'base64', commitment = 'confirmed'}})
  if type(info) == 'table' and info.value ~= nil then return end

  if autofix then
    log_info('provisioning ' .. coin .. ' ATA for ' .. recipient ..
             ' (mint=' .. mint .. ') via surfnet_setTokenAccount')
    rpc:call('surfnet_setTokenAccount', {
      recipient,
      mint,
      {amount = 0, state = 'initialized'},
      token_program,
    })
  else
    error('pay_kit preflight: recipient ' .. recipient .. ' has no ' ..
          coin .. ' ATA on ' .. config.network .. ' (expected ' .. ata ..
          '). Create the ATA before booting.')
  end
end

local function dotenv_path()
  return (os.getenv('PWD') or '.') .. '/.env'
end

-- Lock a file to owner read/write only (0600). Prefers luaposix's chmod
-- (no subprocess, no shell quoting concerns); falls back to `chmod 600`
-- via os.execute. Best effort: a failure to tighten permissions is logged
-- but does not abort persistence (the secret is still written). Returns
-- true if the mode was applied, false otherwise.
local function restrict_file_permissions(path)
  local ok_posix, posix = pcall(require, 'posix')
  if ok_posix and type(posix) == 'table' then
    local chmod = posix.chmod
    if type(chmod) ~= 'function' and type(posix.sys) == 'table'
       and type(posix.sys.stat) == 'table' then
      chmod = posix.sys.stat.chmod
    end
    if type(chmod) == 'function' then
      local ok = pcall(chmod, path, 'rw-------')
      if ok then return true end
      -- Some bindings expect an octal number rather than a symbolic string.
      if pcall(chmod, path, tonumber('600', 8)) then return true end
    end
  end
  -- Fallback: shell out. Single-quote the path and escape embedded quotes
  -- so a path with spaces or quotes cannot break out of the argument.
  local quoted = "'" .. tostring(path):gsub("'", "'\\''") .. "'"
  local ok = os.execute('chmod 600 ' .. quoted)
  return ok == true or ok == 0
end

-- Read a single key from `./.env`. Returns nil if the file does not exist,
-- the key is absent, or the line is malformed. Tolerant parser: ignores
-- blank lines and `#` comments and supports `KEY=value`, `KEY="value"`,
-- and `KEY='value'`. No external dotenv dependency (parity with Ruby's
-- Preflight.read_dotenv_value).
function M.read_dotenv_value(key, path)
  path = path or dotenv_path()
  local fh = io.open(path, 'r')
  if not fh then return nil end
  local value
  for line in fh:lines() do
    local stripped = line:gsub('^%s+', ''):gsub('%s+$', '')
    if stripped ~= '' and stripped:sub(1, 1) ~= '#' then
      local name, raw = stripped:match('^([^=]+)=(.*)$')
      if name and name:gsub('%s+$', '') == key then
        value = raw:gsub('^%s+', ''):gsub('%s+$', '')
        if (value:sub(1, 1) == '"' and value:sub(-1) == '"')
           or (value:sub(1, 1) == "'" and value:sub(-1) == "'") then
          value = value:sub(2, -2)
        end
        break
      end
    end
  end
  fh:close()
  return value
end

-- Append a `KEY="value"` line to `./.env`, creating the file if absent.
-- Returns true on success, false if the directory is unwritable (parity
-- with Ruby's Preflight.persist_dotenv_value).
function M.persist_dotenv_value(key, value, path)
  path = path or dotenv_path()
  local existing = io.open(path, 'r')
  local need_newline = false
  local file_pre_existed = existing ~= nil
  if existing then
    local body = existing:read('*a')
    existing:close()
    need_newline = body ~= '' and body:sub(-1) ~= '\n'
  end
  local fh = io.open(path, 'a')
  if not fh then return false end
  if need_newline then fh:write('\n') end
  fh:write(string.format('%s="%s"\n', key, value))
  fh:close()
  -- A freshly created .env holds the CSPRNG challenge-binding secret, which
  -- must not be world-readable (default umask 022 leaves it 644). Lock it to
  -- owner read/write only. We only touch newly created files so we never
  -- relax or override permissions an operator set on a pre-existing .env.
  if not file_pre_existed then
    restrict_file_permissions(path)
  end
  return true
end

-- Cryptographically secure 32-byte hex secret. Prefers luasodium's
-- randombytes_buf, then /dev/urandom, then a last-resort os.time-seeded
-- math.random (logged as weak). 64 hex chars == 32 bytes, matching Ruby's
-- SecureRandom.hex(32).
function M.secure_random_hex(num_bytes)
  num_bytes = num_bytes or 32
  local hex_chars = '0123456789abcdef'

  local ok_sodium, sodium = pcall(require, 'luasodium')
  if ok_sodium and type(sodium.randombytes_buf) == 'function' then
    local raw = sodium.randombytes_buf(num_bytes)
    if type(raw) == 'string' and #raw == num_bytes then
      return (raw:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
    end
  end

  local fh = io.open('/dev/urandom', 'rb')
  if fh then
    local raw = fh:read(num_bytes)
    fh:close()
    if type(raw) == 'string' and #raw == num_bytes then
      return (raw:gsub('.', function(c) return string.format('%02x', string.byte(c)) end))
    end
  end

  log_warn('no CSPRNG available (luasodium/dev-urandom); falling back to a ' ..
           'weak math.random secret. Set ' .. M.MPP_SECRET_ENV_VAR ..
           ' explicitly in production.')
  math.randomseed(os.time() + os.clock() * 1000000)
  local out = {}
  for i = 1, num_bytes * 2 do
    local idx = math.random(1, 16)
    out[i] = hex_chars:sub(idx, idx)
  end
  return table.concat(out)
end

-- Resolve `config.mpp.challenge_binding_secret` when the caller did not set
-- it explicitly. Resolution order, first hit wins (parity with Ruby
-- Preflight.ensure_challenge_binding_secret!):
--
--   1. `os.getenv(PAY_KIT_MPP_CHALLENGE_BINDING_SECRET)` — the production
--      pattern (orchestrator-supplied env var).
--   2. `./.env` in the current working directory — sticky across restarts.
--   3. A freshly generated CSPRNG secret, persisted to `./.env` so
--      subsequent boots reuse it. If `./.env` is unwritable the secret
--      rotates per boot (logged), which invalidates in-flight challenges.
function M.ensure_challenge_binding_secret(config)
  if config.mpp.challenge_binding_secret and config.mpp.challenge_binding_secret ~= '' then
    return config.mpp.challenge_binding_secret
  end

  local from_env = os.getenv(M.MPP_SECRET_ENV_VAR)
  if from_env and from_env ~= '' then
    config.mpp.challenge_binding_secret = from_env
    return from_env
  end

  local from_dotenv = M.read_dotenv_value(M.MPP_SECRET_ENV_VAR)
  if from_dotenv and from_dotenv ~= '' then
    config.mpp.challenge_binding_secret = from_dotenv
    return from_dotenv
  end

  local generated = M.secure_random_hex(32)
  local persisted = M.persist_dotenv_value(M.MPP_SECRET_ENV_VAR, generated)
  if persisted then
    log_info('generated ' .. M.MPP_SECRET_ENV_VAR .. ' and wrote it to ./.env. ' ..
             'Add `.env` to .gitignore and override via your orchestrator in production.')
  else
    log_warn('generated ' .. M.MPP_SECRET_ENV_VAR .. ' but could not persist to ./.env; ' ..
             'the secret will rotate on every boot, invalidating in-flight challenges. ' ..
             'Set ' .. M.MPP_SECRET_ENV_VAR .. ' explicitly to make it sticky.')
  end
  config.mpp.challenge_binding_secret = generated
  return generated
end

function M.run(config)
  -- Secret resolution runs first: it needs no RPC and must not be skipped
  -- when the network is unreachable.
  if config.mpp then
    M.ensure_challenge_binding_secret(config)
  end

  local rpc_url = config.rpc_url or solana_mod.default_rpc_url(
    pay_kit_network_label(config.network))
  local rpc = rpc_mod.new({url = rpc_url, transport = rpc_transport.new()})
  local autofix = autofix_enabled(config)
  local network_label = pay_kit_network_label(config.network)

  local ok_sol, sol_err = pcall(check_fee_payer_sol, config, rpc, autofix)
  if not ok_sol then
    -- ConfigurationError messages start with the pay_kit prefix; pure
    -- RPC errors come through as table or formatted strings. Treat
    -- pay_kit-prefixed errors as bootstrap-fatal; everything else as
    -- transient and re-surface as a warning.
    if type(sol_err) == 'string' and sol_err:find('pay_kit preflight', 1, true) then
      error(sol_err)
    end
    log_warn('skipped fee-payer balance check (' .. tostring(sol_err) .. ')')
  end

  if type(config.stablecoins) == 'table' then
    for _, coin in ipairs(config.stablecoins) do
      local ok, err = pcall(check_recipient_ata, config, rpc, coin, network_label, autofix)
      if not ok then
        if type(err) == 'string' and err:find('pay_kit preflight', 1, true) then
          error(err)
        end
        log_warn('skipped ' .. tostring(coin) .. ' ATA check (' .. tostring(err) .. ')')
      end
    end
  end
end

-- Convenience used by `configure()`. Returns true if preflight is
-- opted in AND the env-var kill switch is not set.
function M.should_run(config)
  if config.preflight == false then return false end
  local raw = os.getenv('PAY_KIT_DISABLE_PREFLIGHT')
  if raw == '1' or raw == 'true' then return false end
  return true
end

return M
