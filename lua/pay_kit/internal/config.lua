--[[
Boot-time configuration.

Single `configure(opts)` call wires the gem for the lifetime of the
worker. Mirrors `init_by_lua_block` semantics in OpenResty: master
init evaluates the block once and the resulting state survives all
workers via module caching.

Surface (issue #140):

  pay_kit.configure({
    network          = "solana_devnet",
    accept           = { "x402", "mpp" },     -- preference order
    stablecoins      = { "USDC" },
    rpc_url          = "https://...",         -- nil -> default per network
    operator = {
      recipient = "...",                       -- nil -> signer.pubkey()
      signer    = signer.demo(),               -- nil -> signer.demo()
      fee_payer = true,
    },
    x402 = {
      facilitator_url = nil,                   -- delegated mode if set
      scheme          = "exact",
      requires_payment_identifier = false,     -- advertise + require payment-identifier
    },
    mpp = {
      realm                    = "MyApp",
      challenge_binding_secret = "...",
      expires_in               = 300,
    },
  })

Returns (true, nil) on success or (nil, err) on validation failure.
The configure call is immutable - calling twice in the same worker
returns the "already configured" error. Test suites call `_reset()`
to clear the cached state.
]]

local operator_mod = require('pay_kit.internal.operator')
local errors       = require('pay_kit.errors')

local M = {}

local VALID_NETWORKS = { solana_mainnet = true, solana_devnet = true, solana_localnet = true }
local VALID_ACCEPT_SCHEMES = { x402 = true, mpp = true }
local VALID_X402_SCHEMES = { exact = true }

-- Default per-network RPC endpoints used when the caller does not pass an
-- explicit `rpc_url`. The localnet default points at the hosted Surfpool
-- clone of mainnet state (https://402.surfnet.dev:8899) so
-- `configure { network = 'solana_localnet' }` boots against something
-- reachable without the developer running a local validator. This matches
-- the Ruby/`pay_kit.solana.mints` localnet default and the preflight
-- auto-bootstrap path; the previous `http://localhost:8899` only worked
-- when a validator happened to be running locally.
local PUBLIC_RPC_URLS = {
  solana_mainnet  = 'https://api.mainnet-beta.solana.com',
  solana_devnet   = 'https://api.devnet.solana.com',
  solana_localnet = 'https://402.surfnet.dev:8899',
}

local current_config

local function warn(msg)
  local ngx_ref = rawget(_G, 'ngx')
  if ngx_ref and ngx_ref.log and ngx_ref.WARN then
    ngx_ref.log(ngx_ref.WARN, msg)
  else
    io.stderr:write('[pay_kit] WARN: ' .. msg .. '\n')
  end
end

local function validate_accept(list)
  if type(list) ~= 'table' or #list == 0 then
    return nil, 'pay_kit: accept must be a non-empty array'
  end
  local seen, out = {}, {}
  for i = 1, #list do
    local s = list[i]
    if type(s) ~= 'string' then
      return nil, 'pay_kit: accept[' .. i .. '] must be a string'
    end
    if not VALID_ACCEPT_SCHEMES[s] then
      return nil, 'pay_kit: unknown scheme in accept: ' .. s
    end
    if not seen[s] then
      seen[s] = true
      out[#out + 1] = s
    end
  end
  return out
end

local function validate_stablecoins(list)
  if list == nil then return { 'USDC' } end
  if type(list) ~= 'table' or #list == 0 then
    return nil, 'pay_kit: stablecoins must be a non-empty array'
  end
  local out = {}
  for i = 1, #list do
    if type(list[i]) ~= 'string' or list[i] == '' then
      return nil, 'pay_kit: stablecoins[' .. i .. '] must be a non-empty string'
    end
    out[i] = list[i]
  end
  return out
end

-- Resolve the operator table. Allows the caller to pass either a
-- pre-built Operator (via `operator_mod.new`) or a plain options
-- table; both ultimately funnel through `operator_mod.new`.
local function resolve_operator(raw)
  if raw == nil then
    return operator_mod.new({})
  end
  if type(raw) == 'table' and type(raw.effective_recipient) == 'function' then
    return raw -- already an Operator instance
  end
  if type(raw) ~= 'table' then
    return nil, 'pay_kit: operator must be a table or an Operator instance'
  end
  return operator_mod.new(raw)
end

-- Boot-time configuration. Returns (true, nil) on success or
-- (nil, err) on validation failure.
function M.configure(opts)
  if current_config then
    return nil, errors.CONFIGURE_ALREADY_CALLED
  end
  opts = opts or {}

  -- Network.
  local network = opts.network or 'solana_localnet'
  if not VALID_NETWORKS[network] then
    return nil, 'pay_kit: unknown network ' .. tostring(network) ..
      ' (expected solana_mainnet, solana_devnet, or solana_localnet)'
  end

  -- Accept list.
  local accept, accept_err = validate_accept(opts.accept or {'x402', 'mpp'})
  if not accept then return nil, accept_err end

  -- Stablecoins.
  local stablecoins, sc_err = validate_stablecoins(opts.stablecoins)
  if not stablecoins then return nil, sc_err end

  -- Operator.
  local op, op_err = resolve_operator(opts.operator)
  if not op then return nil, op_err end

  -- Mainnet + demo signer refusal.
  if network == 'solana_mainnet' and op:signer():demo() then
    return nil, errors.DEMO_SIGNER_ON_MAINNET
  end

  -- rpc_url + public-default warning.
  local rpc_url = opts.rpc_url
  local using_public_default = (rpc_url == nil or rpc_url == '')
  if using_public_default then
    rpc_url = PUBLIC_RPC_URLS[network]
  end
  if network == 'solana_mainnet' and using_public_default then
    warn('pay_kit: network=solana_mainnet uses the public Solana RPC by ' ..
         'default. Public mainnet RPC is rate-limited and unsuitable for ' ..
         'production traffic. Set rpc_url to a dedicated endpoint.')
  end

  -- x402 sub-config.
  local x402 = opts.x402 or {}
  local x402_scheme = x402.scheme or 'exact'
  if not VALID_X402_SCHEMES[x402_scheme] then
    return nil, 'pay_kit: unknown x402.scheme ' .. tostring(x402_scheme)
  end
  local x402_facilitator_url = x402.facilitator_url
  if x402_facilitator_url ~= nil and type(x402_facilitator_url) ~= 'string' then
    return nil, 'pay_kit: x402.facilitator_url must be a string or nil'
  end
  local x402_signer_override
  if x402.signer ~= nil then
    -- Reuse operator validation by funnelling through operator_mod.new.
    local _, sig_err = operator_mod.new({signer = x402.signer})
    if sig_err then return nil, sig_err:gsub('operator.signer', 'x402.signer') end
    x402_signer_override = x402.signer
  end
  -- x402 v2 `payment-identifier` extension toggle. When true the server
  -- advertises `payment-identifier` with info.required=true on the
  -- PAYMENT-REQUIRED challenge and rejects any credential that does not echo
  -- back a valid `pay_`-shaped id. Mirrors the rust spine
  -- (PaymentExtensions::requires_payment_identifier + the coinbase 400 gate).
  local x402_requires_payment_identifier = x402.requires_payment_identifier
  if x402_requires_payment_identifier == nil then
    x402_requires_payment_identifier = false
  end
  if type(x402_requires_payment_identifier) ~= 'boolean' then
    return nil, 'pay_kit: x402.requires_payment_identifier must be a boolean or nil'
  end

  -- MPP sub-config.
  local mpp = opts.mpp or {}
  local mpp_realm = mpp.realm or 'App'
  local mpp_secret = mpp.challenge_binding_secret
  -- expires_in defaults to a short 300s TTL so issued challenges are not
  -- valid indefinitely (parity with Python/Rust/Ruby short-TTL defaults
  -- and the PHP/Lua expiry-wiring fix). `expires_in = false` is the
  -- explicit development opt-out: challenges are then issued with no
  -- expiry. Any non-positive number is rejected so `0` is not silently
  -- treated as "never expires".
  local mpp_expires_in = mpp.expires_in
  if mpp_expires_in == nil then
    mpp_expires_in = 300
  end
  if mpp_secret ~= nil and type(mpp_secret) ~= 'string' then
    return nil, 'pay_kit: mpp.challenge_binding_secret must be a string or nil'
  end
  if mpp_expires_in ~= false then
    if type(mpp_expires_in) ~= 'number' or mpp_expires_in <= 0 then
      return nil, 'pay_kit: mpp.expires_in must be a positive number or false (dev opt-out)'
    end
  end

  -- Preflight opt-out: default true, opt out via opts.preflight = false.
  local preflight_enabled = opts.preflight
  if preflight_enabled == nil then preflight_enabled = true end

  -- Preserve every caller-supplied mpp.* field (notably mpp.replay_store,
  -- the shared atomic store operators inject to satisfy the multi-worker
  -- replay-protection warning) while overlaying the normalized realm /
  -- secret / expires_in. Rebuilding mpp from only the three normalized
  -- fields silently dropped replay_store and any future mpp option.
  local mpp_config = {}
  for k, v in pairs(mpp) do
    mpp_config[k] = v
  end
  mpp_config.realm = mpp_realm
  mpp_config.challenge_binding_secret = mpp_secret
  mpp_config.expires_in = mpp_expires_in

  current_config = {
    network                  = network,
    accept                   = accept,
    stablecoins              = stablecoins,
    rpc_url                  = rpc_url,
    using_public_rpc_default = using_public_default,
    operator                 = op,
    preflight                = preflight_enabled,
    recent_blockhash_provider = opts.recent_blockhash_provider,
    x402 = {
      scheme           = x402_scheme,
      facilitator_url  = x402_facilitator_url,
      signer_override  = x402_signer_override,
      delegated        = x402_facilitator_url ~= nil and x402_facilitator_url ~= '',
      requires_payment_identifier = x402_requires_payment_identifier,
    },
    mpp = mpp_config,
  }

  -- Convenience accessors on the resolved config table.
  function current_config.effective_x402_signer(self)
    return self.x402.signer_override or self.operator:signer()
  end
  function current_config.effective_recipient(self)
    return self.operator:effective_recipient()
  end

  -- Boot-time preflight. Mirrors Ruby PR #142: checks fee-payer SOL
  -- balance + recipient ATA, auto-bootstraps on localnet+demo via
  -- surfnet cheatcodes. Opt-out via opts.preflight=false or
  -- PAY_KIT_DISABLE_PREFLIGHT=1.
  local preflight = require('pay_kit.preflight')

  -- Resolve the MPP challenge-binding secret regardless of whether the
  -- (RPC-touching) preflight checks run. When the caller did not pass
  -- `mpp.challenge_binding_secret`, this reads
  -- PAY_KIT_MPP_CHALLENGE_BINDING_SECRET, then ./.env, then generates a
  -- CSPRNG secret and persists it (Ruby preflight.rb parity). Without
  -- this the MPP adapter would either crash on a nil secret or rotate a
  -- per-process random one on every boot, invalidating challenges.
  if mpp_secret == nil or mpp_secret == '' then
    local ok_secret, secret_err = pcall(preflight.ensure_challenge_binding_secret, current_config)
    if not ok_secret then
      current_config = nil
      return nil, tostring(secret_err)
    end
  end

  if preflight.should_run(current_config) then
    local ok, err = pcall(preflight.run, current_config)
    if not ok then
      current_config = nil  -- so a follow-up configure() can retry
      return nil, tostring(err)
    end
  end

  return true
end

-- Return the current resolved config or nil if configure() was not
-- called yet. Read-only by convention - callers must not mutate.
function M.current()
  return current_config
end

-- Test-only: clear the cached config so a subsequent configure() runs
-- fresh. Production callers never need this. signer.demo's singleton
-- is independently resettable via signer.demo.reset_for_tests().
function M._reset_for_tests()
  current_config = nil
end

return M
