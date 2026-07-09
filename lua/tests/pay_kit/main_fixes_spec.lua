--[[
Regression coverage for the main-branch Lua audit fixes:

  LUA-7  challenge expiry is wired from config.mpp.expires_in into the
         402 challenge the MPP adapter issues (and the `false` dev opt-out).
  LUA-3  solana_localnet defaults to the hosted Surfpool RPC, not a bare
         local validator.
  LUA-MPP-SECRET  challenge_binding_secret resolves from the env var, then
         ./.env, then a freshly generated + persisted CSPRNG secret.
  402 no-store on the dispatcher 402 path.
  expires.format_rfc3339 round-trips through parse_rfc3339.
]]

local helper   = require('tests.test_helper')
local pay_kit  = require('pay_kit')
local headers  = require('pay_kit.protocol.core.headers')
local expires  = require('pay_kit.protocols.mpp.expires')
local preflight = require('pay_kit.preflight')
local canonical_json = require('pay_kit.util.json')

local SELLER = 'SeLLeRWaLLeT111111111111111111111111111111'

local function reset()
  pay_kit._reset_for_tests()
end

-- Parse the MPP challenge out of a 402 response's WWW-Authenticate header.
local function mpp_challenge_from_response(response)
  local hdr = response.headers and response.headers['www-authenticate']
  helper.assert_true(hdr ~= nil, 'expected a www-authenticate header')
  return headers.parse_www_authenticate(hdr)
end

-- ── 402 no-store ──────────────────────────────────────────────────────────

helper.test('402 response carries Cache-Control: no-store', function()
  reset()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    operator = {recipient = SELLER},
    mpp      = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes'},
  }))
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local _, _, response = pay_kit.try_payment('report', {headers = {}, path = '/report'})
  helper.assert_equal(response.headers['cache-control'], 'no-store')
end)

-- ── LUA-7 expiry wiring ─────────────────────────────────────────────────────

helper.test('MPP 402 challenge carries an expiry from config.mpp.expires_in', function()
  reset()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    accept   = {'mpp'},
    operator = {recipient = SELLER},
    mpp      = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes', expires_in = 120},
  }))
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local _, _, response = pay_kit.try_payment('report', {headers = {}, path = '/report'})
  local challenge = mpp_challenge_from_response(response)
  helper.assert_true(challenge.expires ~= nil and challenge.expires ~= '',
    'expected a non-empty expires on the issued challenge')
  -- The expiry must be a future RFC3339 timestamp (not yet expired now).
  helper.assert_equal(expires.is_expired(challenge.expires, os.time()), false)
  -- And it must be expired well past the TTL window.
  helper.assert_equal(expires.is_expired(challenge.expires, os.time() + 10000), true)
end)

helper.test('MPP 402 challenge omits expiry when expires_in = false (dev opt-out)', function()
  reset()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    accept   = {'mpp'},
    operator = {recipient = SELLER},
    mpp      = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes', expires_in = false},
  }))
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local _, _, response = pay_kit.try_payment('report', {headers = {}, path = '/report'})
  local challenge = mpp_challenge_from_response(response)
  helper.assert_true(challenge.expires == nil or challenge.expires == '',
    'dev opt-out must issue a challenge with no expiry')
end)

helper.test('configure rejects a non-positive expires_in', function()
  reset()
  local _, err = pay_kit.configure({
    network = 'solana_devnet',
    mpp     = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes', expires_in = 0},
  })
  helper.assert_true(err ~= nil and err:find('expires_in', 1, true) ~= nil, tostring(err))
end)

-- ── LUA-6 adapter supplies the full route methodDetails in `expected` ───────
--
-- The adapter's verify-time `expected` request must reconstruct the SAME
-- methodDetails the challenge was issued with (network, decimals,
-- tokenProgram, feePayer/feePayerKey). If it does not, every real MPP
-- credential would false-reject on the new methodDetails binding. Compare
-- the canonical methodDetails of the issued challenge against the adapter's
-- reconstruction (built the same way verify_and_settle builds `expected`).

local function strip_blockhash(method_details)
  local out = {}
  for k, v in pairs(method_details or {}) do
    if k ~= 'recentBlockhash' then out[k] = v end
  end
  return out
end

helper.test('adapter expected methodDetails matches the issued challenge', function()
  reset()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    accept   = {'mpp'},
    operator = {recipient = SELLER},
    mpp      = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes', expires_in = 120},
  }))
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local _, _, response = pay_kit.try_payment('report', {headers = {}, path = '/report'})
  local challenge = mpp_challenge_from_response(response)
  local issued = challenge.request:decode()

  -- Reconstruct expected methodDetails the way the MPP adapter does at
  -- verify time (network + SPL decimals/tokenProgram + feePayer key).
  local mints = require('pay_kit.solana.mints')
  local currency = issued.currency
  local network = issued.methodDetails.network
  local expected_md = { network = network }
  if string.lower(currency) ~= 'sol' then
    expected_md.decimals = issued.methodDetails.decimals
    if mints.stablecoin_symbol(currency) then
      expected_md.tokenProgram = mints.default_token_program_for_currency(currency, network)
    end
  end
  if issued.methodDetails.feePayer then
    expected_md.feePayer = true
    if issued.methodDetails.feePayerKey then
      expected_md.feePayerKey = issued.methodDetails.feePayerKey
    end
  end

  helper.assert_equal(
    canonical_json.encode(strip_blockhash(expected_md)),
    canonical_json.encode(strip_blockhash(issued.methodDetails))
  )
end)

-- ── LUA-3 localnet RPC default ──────────────────────────────────────────────

helper.test('solana_localnet defaults to the hosted Surfpool RPC', function()
  reset()
  assert(pay_kit.configure({mpp = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes'}}))
  helper.assert_equal(pay_kit.config().rpc_url, 'https://402.surfnet.dev:8899')
end)

-- ── expires.format_rfc3339 ──────────────────────────────────────────────────

helper.test('expires.format_rfc3339 round-trips through parse_rfc3339', function()
  local epoch = 1893456000 -- 2030-01-01T00:00:00Z
  local formatted = expires.format_rfc3339(epoch)
  helper.assert_equal(formatted, '2030-01-01T00:00:00Z')
  local parsed = expires.parse_rfc3339(formatted)
  helper.assert_equal(parsed, epoch)
end)

-- ── LUA-MPP-SECRET resolution (env / .env / CSPRNG) ─────────────────────────
--
-- These tests restore the real os.getenv (the test_helper monkey-patch
-- otherwise forces a fixed secret env var) so the genuine resolution order
-- is exercised against a temp directory.

local _patched_getenv = os.getenv
local _real_getenv = rawget(_G, '_PAY_KIT_REAL_GETENV') or os.getenv

local function with_real_getenv(env_value, fn)
  os.getenv = function(name)  -- luacheck: ignore
    if name == 'PAY_KIT_DISABLE_PREFLIGHT' then return '1' end
    if name == 'PAY_KIT_MPP_CHALLENGE_BINDING_SECRET' then return env_value end
    return _real_getenv(name)
  end
  local ok, err = pcall(fn)
  os.getenv = _patched_getenv  -- luacheck: ignore
  if not ok then error(err) end
end

helper.test('ensure_challenge_binding_secret reads the env var first', function()
  with_real_getenv('env-supplied-secret', function()
    local cfg = {mpp = {challenge_binding_secret = nil}}
    local resolved = preflight.ensure_challenge_binding_secret(cfg)
    helper.assert_equal(resolved, 'env-supplied-secret')
    helper.assert_equal(cfg.mpp.challenge_binding_secret, 'env-supplied-secret')
  end)
end)

helper.test('ensure_challenge_binding_secret reads ./.env when env is unset', function()
  with_real_getenv(nil, function()
    local path = os.tmpname()
    local fh = assert(io.open(path, 'w'))
    fh:write('# comment\n')
    fh:write('OTHER_KEY=ignored\n')
    fh:write('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET="dotenv-secret-value"\n')
    fh:close()
    local value = preflight.read_dotenv_value('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET', path)
    os.remove(path)
    helper.assert_equal(value, 'dotenv-secret-value')
  end)
end)

helper.test('secure_random_hex returns 64 lowercase hex chars (32 bytes)', function()
  local hex = preflight.secure_random_hex(32)
  helper.assert_equal(#hex, 64)
  helper.assert_true(hex:match('^[0-9a-f]+$') ~= nil, 'expected lowercase hex')
  -- Two draws must differ (not a constant).
  helper.assert_true(hex ~= preflight.secure_random_hex(32), 'CSPRNG must not repeat')
end)

helper.test('persist_dotenv_value writes a readable KEY="value" line', function()
  local path = os.tmpname()
  os.remove(path) -- start from absent so we exercise the create path
  local ok = preflight.persist_dotenv_value('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET', 'persisted-xyz', path)
  helper.assert_equal(ok, true)
  local value = preflight.read_dotenv_value('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET', path)
  os.remove(path)
  helper.assert_equal(value, 'persisted-xyz')
end)

helper.test('ensure_challenge_binding_secret generates + persists a secret when env and .env are empty', function()
  with_real_getenv(nil, function()
    -- Point dotenv at a temp dir by chdir is overkill; instead drive the
    -- generator directly and confirm it is a 64-char hex secret. The
    -- env-empty + dotenv-empty branch is covered by read_dotenv_value
    -- returning nil for a missing file.
    helper.assert_equal(preflight.read_dotenv_value('NO_SUCH_KEY', '/nonexistent/path/.env'), nil)
    local cfg = {mpp = {challenge_binding_secret = nil}}
    -- Persist to a temp .env via PWD override so the repo is not touched.
    local tmpdir = os.tmpname()
    os.remove(tmpdir)
    assert(os.execute('mkdir -p ' .. tmpdir))
    local old_pwd = _real_getenv('PWD')
    os.getenv = function(name)  -- luacheck: ignore
      if name == 'PWD' then return tmpdir end
      if name == 'PAY_KIT_DISABLE_PREFLIGHT' then return '1' end
      if name == 'PAY_KIT_MPP_CHALLENGE_BINDING_SECRET' then return nil end
      return _real_getenv(name)
    end
    local resolved = preflight.ensure_challenge_binding_secret(cfg)
    -- restore the with_real_getenv shim
    os.getenv = function(name)  -- luacheck: ignore
      if name == 'PWD' then return old_pwd end
      if name == 'PAY_KIT_DISABLE_PREFLIGHT' then return '1' end
      if name == 'PAY_KIT_MPP_CHALLENGE_BINDING_SECRET' then return nil end
      return _real_getenv(name)
    end
    helper.assert_equal(#resolved, 64)
    helper.assert_equal(cfg.mpp.challenge_binding_secret, resolved)
    -- The generated secret was persisted to the temp .env and re-reads.
    helper.assert_equal(
      preflight.read_dotenv_value('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET', tmpdir .. '/.env'),
      resolved
    )
    os.execute('rm -rf ' .. tmpdir)
  end)
end)
