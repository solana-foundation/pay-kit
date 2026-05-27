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
  if not mint or mint == coin and coin:upper() == 'SOL' then return end
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

function M.run(config)
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
