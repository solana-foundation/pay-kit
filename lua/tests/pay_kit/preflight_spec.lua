--[[
Preflight unit tests. Drives the run() function against a stubbed RPC
+ stubbed config so we can assert each branch (low-balance raise,
autofund on localnet+demo, missing-ATA raise, missing-ATA autoprovision,
RPC-failure soft-skip) without a real network.

Mirrors Ruby PR #142's config_test.rb additions.
]]

local helper    = require('tests.test_helper')
local preflight = require('pay_kit.preflight')
local signer    = require('pay_kit.signer')

-- Build a fake config table that satisfies the preflight contract:
--   .network, .stablecoins[], .operator (with .signer().pubkey(),
--   .effective_recipient(), .fee_payer()), .rpc_url.
-- Build a fresh signer-shape table per call so flipping `demo` on
-- the non-demo variant doesn't mutate the demo singleton.
local function make_signer(demo_flag)
  local demo_inst = signer.demo()
  return {
    pubkey  = function() return demo_inst:pubkey() end,
    sign    = function(_, msg) return demo_inst:sign(msg) end,
    demo    = function() return demo_flag ~= false end,
    fee_payer = function() return true end,
    _secret_key_bytes = function()
      return demo_inst._secret_key_bytes and demo_inst:_secret_key_bytes()
    end,
  }
end

local function make_operator(recipient, sgn)
  return {
    signer  = function() return sgn end,
    effective_recipient = function() return recipient end,
    fee_payer = function() return true end,
  }
end

-- Build a minimal config and a stub RPC by overriding the
-- pay_kit.solana.rpc module in package.loaded BEFORE re-requiring the
-- preflight module. Earlier specs in the suite may have already
-- monkey-patched pay_kit.solana.rpc with a different shape, so we evict
-- the preflight module too to force it to re-bind to our fixture.
local function install_rpc_stub(fixture)
  package.loaded['pay_kit.solana.rpc'] = {
    new = function(_)
      return {
        call = function(_, method, params)
          return fixture[method] and fixture[method](params) or nil
        end,
      }
    end,
  }
  package.loaded['pay_kit.preflight'] = nil
end
local function restore_rpc()
  package.loaded['pay_kit.solana.rpc']           = nil
  package.loaded['pay_kit.preflight']  = nil
end

helper.test('preflight: should_run respects PAY_KIT_DISABLE_PREFLIGHT', function()
  -- The suite-wide patch in test_helper forces the var to '1'; assert
  -- the path returns false there.
  helper.assert_equal(preflight.should_run({preflight = true}), false)
end)

helper.test('preflight: should_run returns false when c.preflight=false', function()
  -- Temporarily unset the env so we exercise the explicit-off branch.
  local saved = os.getenv
  os.getenv = function(_) return nil end  -- luacheck: ignore
  helper.assert_equal(preflight.should_run({preflight = false}), false)
  os.getenv = saved  -- luacheck: ignore
end)

helper.test('preflight: should_run returns true when neither knob blocks', function()
  local saved = os.getenv
  os.getenv = function(_) return nil end  -- luacheck: ignore
  helper.assert_equal(preflight.should_run({preflight = true}), true)
  os.getenv = saved  -- luacheck: ignore
end)

helper.test('preflight raises ConfigurationError on low fee-payer balance off localnet', function()
  install_rpc_stub({
    getBalance = function() return {value = 1} end,  -- below min
    getAccountInfo = function() return {value = {}} end,
  })
  local sgn = make_signer()
  local cfg = {
    network = 'solana_devnet',
    rpc_url = 'https://devnet.example.com',
    stablecoins = {'USDC'},
    operator = make_operator(require('pay_kit.solana.base58').encode(string.rep('\5', 32)), sgn),
  }
  local pf = require('pay_kit.preflight')
  local ok, err = pcall(pf.run, cfg)
  restore_rpc()
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('fee%-payer'))
end)

helper.test('preflight raises ConfigurationError on missing recipient ATA off localnet', function()
  install_rpc_stub({
    getBalance = function() return {value = 1000000000} end,  -- well-funded
    getAccountInfo = function() return {value = nil} end,     -- no ATA
  })
  local sgn = make_signer(false)  -- non-demo signer so autofix off
  local cfg = {
    network = 'solana_devnet',
    rpc_url = 'https://devnet.example.com',
    stablecoins = {'USDC'},
    operator = make_operator(require('pay_kit.solana.base58').encode(string.rep('\5', 32)), sgn),
  }
  local pf = require('pay_kit.preflight')
  local ok, err = pcall(pf.run, cfg)
  restore_rpc()
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('no USDC ATA'))
end)

helper.test('preflight auto-funds the fee-payer on localnet with demo signer', function()
  local funded = false
  install_rpc_stub({
    getBalance = function() return {value = 1} end,
    getAccountInfo = function() return {value = {}} end,
    surfnet_setAccount = function() funded = true; return {} end,
    surfnet_setTokenAccount = function() return {} end,
  })
  local cfg = {
    network = 'solana_localnet',
    rpc_url = 'https://402.surfnet.dev:8899',
    stablecoins = {'USDC'},
    operator = make_operator(require('pay_kit.solana.base58').encode(string.rep('\5', 32)),
                             make_signer()),  -- demo
  }
  local pf = require('pay_kit.preflight')
  local ok = pcall(pf.run, cfg)
  restore_rpc()
  helper.assert_true(ok)
  helper.assert_true(funded)
end)

helper.test('preflight auto-provisions a missing ATA on localnet with demo signer', function()
  local provisioned = false
  install_rpc_stub({
    getBalance = function() return {value = 1000000000} end,
    getAccountInfo = function() return {value = nil} end,
    surfnet_setTokenAccount = function() provisioned = true; return {} end,
  })
  local cfg = {
    network = 'solana_localnet',
    rpc_url = 'https://402.surfnet.dev:8899',
    stablecoins = {'USDC'},
    operator = make_operator(require('pay_kit.solana.base58').encode(string.rep('\5', 32)),
                             make_signer()),  -- demo
  }
  local pf = require('pay_kit.preflight')
  local ok = pcall(pf.run, cfg)
  restore_rpc()
  helper.assert_true(ok)
  helper.assert_true(provisioned)
end)

helper.test('preflight downgrades RPC failure to warning (no raise)', function()
  install_rpc_stub({
    getBalance     = function() error('rpc unreachable') end,
    getAccountInfo = function() error('rpc unreachable') end,
  })
  local cfg = {
    network = 'solana_devnet',
    rpc_url = 'https://unreachable.example.com',
    stablecoins = {'USDC'},
    operator = make_operator(require('pay_kit.solana.base58').encode(string.rep('\5', 32)),
                             make_signer()),
  }
  local pf = require('pay_kit.preflight')
  local ok = pcall(pf.run, cfg)
  restore_rpc()
  helper.assert_true(ok, 'preflight must not raise on RPC failure')
end)
