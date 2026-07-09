--[[
Kong master-init bootstrap.

Wired via:
  KONG_NGINX_HTTP_INIT_BY_LUA_BLOCK="require('plugins.kong.plugins.pay-kit.init').setup()"

Reads the canonical PAY_KIT_* env vars and calls
`pay_kit.configure()` exactly once at master init so all workers
share the same operator identity, signer, RPC URL, and MPP secret.

Env vars (all optional; defaults boot a localnet demo):
  PAY_KIT_NETWORK                          solana_mainnet | solana_devnet | solana_localnet
  PAY_KIT_RPC_URL                          Solana RPC endpoint
  PAY_KIT_OPERATOR_RECIPIENT               base58 Solana address that receives charges
  PAY_KIT_OPERATOR_KEY                     64-byte Solana secret (JSON array / base58 / hex)
  PAY_KIT_ACCEPT                           comma-separated, e.g. "x402,mpp"
  PAY_KIT_STABLECOINS                      comma-separated, e.g. "USDC,USDT"
  PAY_KIT_X402_FACILITATOR_URL             optional; set for delegated x402
  PAY_KIT_MPP_REALM                        realm string for MPP challenges
  PAY_KIT_MPP_CHALLENGE_BINDING_SECRET     HMAC secret for MPP challenge binding
  PAY_KIT_MPP_EXPIRES_IN                   challenge expiry seconds

For devnet/mainnet MPP, declare `lua_shared_dict mpp_replay 10m;` in the
nginx `http` block. The bootstrap binds it as the replay store; without it,
MPP verification fails closed instead of using process-local memory.

Gates are registered via per-plugin config on the route. Apps wanting
a catalog-style Pricing class can call pay_kit.gate() after setup().

MPP replay store (production): outside localnet the MPP adapter REQUIRES a
durable, process-shared replay store (a settled signature is otherwise
replayable across workers/restarts for a second settlement). The env-driven
setup() below does not wire one, so on solana_devnet / solana_mainnet an
operator using MPP must inject a shared store after setup() -- e.g. build
`pay_kit.protocols.mpp.server.store_shared_dict.new(ngx.shared.<dict>)` and pass
it as `config.mpp.replay_store` via a custom init block -- or the first MPP
request will fail closed. x402 replay protection is unaffected (it uses the
dispatcher's `pay_kit.store` shared-dict backend automatically).
]]

local pay_kit = require('pay_kit')
local signer  = require('pay_kit.signer')

local M = {}

local function mpp_replay_store()
  local ngx_ref = rawget(_G, 'ngx')
  local dict = ngx_ref and ngx_ref.shared and ngx_ref.shared.mpp_replay
  if not dict then return nil end
  return require('pay_kit.protocols.mpp.server.store_shared_dict').new(dict)
end

local function split_csv(s)
  if not s or s == '' then return nil end
  local out = {}
  for part in s:gmatch('[^,]+') do
    local trimmed = part:match('^%s*(.-)%s*$')
    if trimmed ~= '' then out[#out + 1] = trimmed end
  end
  if #out == 0 then return nil end
  return out
end

local function env_int(name, default)
  local raw = os.getenv(name)
  if not raw or raw == '' then return default end
  local n = tonumber(raw)
  return n or default
end

function M.setup()
  local opts = {
    network     = os.getenv('PAY_KIT_NETWORK') or 'solana_devnet',
    rpc_url     = os.getenv('PAY_KIT_RPC_URL'),
    accept      = split_csv(os.getenv('PAY_KIT_ACCEPT')) or {'x402', 'mpp'},
    stablecoins = split_csv(os.getenv('PAY_KIT_STABLECOINS')) or {'USDC'},
    operator = {
      recipient = os.getenv('PAY_KIT_OPERATOR_RECIPIENT'),
      signer    = signer.from_env('PAY_KIT_OPERATOR_KEY'),
    },
    x402 = {
      facilitator_url = os.getenv('PAY_KIT_X402_FACILITATOR_URL'),
      scheme          = 'exact',
    },
    mpp = {
      realm                    = os.getenv('PAY_KIT_MPP_REALM') or 'PayKit (Kong)',
      challenge_binding_secret = os.getenv('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET'),
      expires_in               = env_int('PAY_KIT_MPP_EXPIRES_IN', 300),
      replay_store             = mpp_replay_store(),
    },
  }
  local ok, err = pay_kit.configure(opts)
  if not ok then
    local ngx_ref = rawget(_G, 'ngx')
    if ngx_ref and ngx_ref.log and ngx_ref.ERR then
      ngx_ref.log(ngx_ref.ERR, 'pay-kit bootstrap: ', err)
    else
      io.stderr:write('[pay_kit] ERR: bootstrap: ' .. tostring(err) .. '\n')
    end
    error(err)
  end
end

return M
