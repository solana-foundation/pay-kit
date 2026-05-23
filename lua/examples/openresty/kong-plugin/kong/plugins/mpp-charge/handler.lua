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
            amount:    "1000"
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
local store_module = require('mpp.store')

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
  local verifier_bundle = solana_verify.new_real_verifier({ pull_signer = fee_payer })
  local handler = charge_handler_module.new({
    rpc = rpc,
    network = conf.network,
    replay_store = store_module.memory(),
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
    fee_payer  = fee_payer ~= nil,
    fee_payer_key = fee_payer and fee_payer.public_key or nil,
    verify_payment = handler:as_callback(),
  })
  cache[conf] = { server = server, amount = conf.amount }
  return cache[conf]
end

local function send_challenge(server, amount)
  local challenge = server:charge(amount)
  ngx.status = 402
  ngx.header['content-type'] = 'application/json'
  ngx.header['www-authenticate'] = headers.format_www_authenticate(challenge)
  ngx.say('{"error":"payment required"}')
  return ngx.exit(402)
end

function plugin:access(conf)
  local handle = get_server(conf)
  local authorization = ngx.req.get_headers()['authorization']
  if authorization == nil or authorization == '' then
    return send_challenge(handle.server, handle.amount)
  end
  local credential, parse_err = headers.parse_authorization(authorization)
  if not credential then
    ngx.log(ngx.ERR, 'mpp-charge: failed to parse authorization: ', tostring(parse_err))
    return send_challenge(handle.server, handle.amount)
  end
  local ok, settlement = pcall(function()
    return handle.server:verify_credential_with_expected(credential, {
      amount = handle.amount,
      currency = conf.currency,
      recipient = conf.recipient,
    })
  end)
  if not ok then
    local detail = type(settlement) == 'table' and settlement.message or tostring(settlement)
    ngx.log(ngx.ERR, 'mpp-charge: settlement failed: ', tostring(detail))
    return send_challenge(handle.server, handle.amount)
  end
  if settlement and settlement.reference then
    ngx.header[mpp.PaymentReceiptHeader] = headers.format_receipt(settlement)
  end
end

return plugin
