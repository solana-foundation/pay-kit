--[[
Kong custom plugin for the MPP charge intent.

Phase: access. The plugin builds an `mpp.server` (and the supporting
charge handler + verifier + RPC transport) lazily on the first
request, caches the handle in `kong.plugin.<name>.cache`, and either
issues a 402 challenge or runs the full settlement lifecycle against
the configured Solana RPC.

Usage in `kong.conf` (or the equivalent declarative configuration):

  plugins = bundled,mpp-charge

  -- Per-service configuration:
  services:
    - name: protected-api
      url:  http://localhost:9000
      plugins:
        - name: mpp-charge
          config:
            recipient: <base58 pubkey>
            currency:  USDC
            network:   mainnet-beta
            secret_key: <hmac secret>
            amount:    "1.50"     -- human display form; parse_units(amount, decimals) converts to base units
            rpc_url:   https://api.mainnet-beta.solana.com
            fee_payer_secret_key: "[..64 bytes..]"
]]

local mpp = require('mpp')
local headers = require('mpp.protocol.core.headers')
local solana_verify = require('mpp.server.solana_verify')
local charge_handler_module = require('mpp.server.charge_handler')
local rpc_module = require('mpp.solana.rpc')
local rpc_transport = require('mpp.solana.rpc_transport')
local signer_module = require('mpp.methods.solana.signer')
local store_shared_dict = require('mpp.server.store_shared_dict')
local error_codes = require('mpp.protocol.core.error_codes')
local intents = require('mpp.protocol.intents.charge')
local json = require('mpp.util.json')

local plugin = {
  PRIORITY = 1000,
  VERSION = '0.1.0',
}

local cache = {}

local function get_server(conf)
  if cache[conf] then
    return cache[conf]
  end
  local fee_payer
  if conf.fee_payer_secret_key and conf.fee_payer_secret_key ~= '' then
    fee_payer = signer_module.from_json_array(conf.fee_payer_secret_key)
  end
  local rpc = rpc_module.new({
    url = conf.rpc_url,
    transport = rpc_transport.new(),
  })
  -- Cross-worker replay store. Kong's default `worker_processes auto`
  -- spawns one Lua state per CPU core; an in-memory store would be
  -- invisible across workers and let an attacker replay a consumed
  -- Payment credential against a different worker. The shared-dict
  -- store routes every put_if_absent through nginx-managed shared
  -- memory so the consumed-signature set is one global view. The
  -- `lua_shared_dict <name> <size>` directive must be present at the
  -- http-block level; the example nginx.conf ships with
  -- `lua_shared_dict mpp_replay 10m;`.
  local dict_name = conf.shared_dict_name or 'mpp_replay'
  local dict = ngx and ngx.shared and ngx.shared[dict_name]
  if not dict then
    error(
      'mpp-charge requires lua_shared_dict ' .. dict_name ..
      ' to be declared in the http block; see lua/examples/openresty/kong-plugin/README.md'
    )
  end
  local replay_store = store_shared_dict.new(dict)
  local verifier_bundle = solana_verify.new_real_verifier({ pull_signer = fee_payer })
  local handler = charge_handler_module.new({
    rpc = rpc,
    network = conf.network,
    replay_store = replay_store,
    transaction_verifier = verifier_bundle.transaction_verifier,
    pull_transaction_signer = verifier_bundle.pull_transaction_signer,
    pull_blockhash_extractor = verifier_bundle.pull_blockhash_extractor,
  })
  local server = mpp.server.new({
    recipient  = conf.recipient,
    currency   = conf.currency,
    decimals   = conf.decimals or 6,
    network    = conf.network,
    rpc_url    = conf.rpc_url,
    secret_key = conf.secret_key,
    realm      = conf.realm or 'MPP',
    store      = replay_store,
    fee_payer  = fee_payer ~= nil,
    fee_payer_key = fee_payer and fee_payer.public_key or nil,
    verify_payment = handler:as_callback(),
  })
  -- `conf.amount` is the human display form (e.g. "1.50" or "1000"). The
  -- server stores the challenge in base units after parse_units, so the
  -- verifier-side `expected.amount` must also be in base units; otherwise
  -- every settlement returns `charge_request_mismatch`. Convert once at
  -- cache time using the configured decimals.
  local decimals = conf.decimals or 6
  local expected_base_units = intents.parse_units(conf.amount, decimals)
  cache[conf] = {
    server = server,
    display_amount = conf.amount,
    expected_amount = expected_base_units,
  }
  return cache[conf]
end

local function send_challenge(server, amount, err_value)
  local challenge = server:charge(amount)
  ngx.status = 402
  ngx.header['content-type'] = 'application/json'
  ngx.header['www-authenticate'] = headers.format_www_authenticate(challenge)
  local response
  if err_value ~= nil then
    response = error_codes.to_response(err_value)
  else
    response = {
      error = 'payment required',
      message = 'payment required',
      code = error_codes.CHALLENGE_VERIFICATION_FAILED,
    }
  end
  ngx.say(json.encode(response))
  return ngx.exit(402)
end

function plugin:access(conf)
  local handle = get_server(conf)
  local authorization = ngx.req.get_headers()['authorization']
  if authorization == nil or authorization == '' then
    return send_challenge(handle.server, handle.display_amount)
  end
  local credential, parse_err = headers.parse_authorization(authorization)
  if not credential then
    ngx.log(ngx.ERR, 'mpp-charge: failed to parse authorization: ', tostring(parse_err))
    return send_challenge(handle.server, handle.display_amount, parse_err)
  end
  local ok, settlement = pcall(function()
    return handle.server:verify_credential_with_expected(credential, {
      amount = handle.expected_amount,
      currency = conf.currency,
      recipient = conf.recipient,
    })
  end)
  if not ok then
    local response = error_codes.to_response(settlement)
    ngx.log(ngx.ERR, 'mpp-charge: settlement failed: ', tostring(response.message),
      ' (', tostring(response.code), ')')
    return send_challenge(handle.server, handle.display_amount, settlement)
  end
  if settlement and settlement.reference then
    ngx.header[mpp.PaymentReceiptHeader] = headers.format_receipt(settlement)
  end
end

return plugin
