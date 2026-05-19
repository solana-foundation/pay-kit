local assets = require('mpp.server.html_assets.gen')
local base64url = require('mpp.util.base64url')
local json = require('mpp.util.json')

local M = {}

local function html_escape(str)
  if type(str) ~= 'string' then
    return ''
  end
  return str
    :gsub('&', '&amp;')
    :gsub('<', '&lt;')
    :gsub('>', '&gt;')
    :gsub('"', '&quot;')
    :gsub("'", '&#39;')
end

function M.accepts_html(accept_header)
  if type(accept_header) ~= 'string' then
    return false
  end
  return accept_header:find('text/html', 1, true) ~= nil
end

function M.is_service_worker_request(uri_args)
  if type(uri_args) ~= 'table' then
    return false
  end
  return uri_args.__mpp_worker ~= nil
end

function M.service_worker_js()
  return assets.service_worker_js
end

local function replace_once(input, token, value)
  local output = input:gsub(token, function()
    return value
  end, 1)
  return output
end

local function amount_display(request)
  local amount = tonumber(request.amount or '')
  if amount == nil then
    return tostring(request.amount or '')
  end
  local method_details = request.methodDetails or {}
  local decimals = tonumber(method_details.decimals or 6) or 6
  local divisor = 10 ^ decimals
  local value = amount / divisor
  if value % 1 == 0 then
    return '$' .. tostring(value)
  end
  return '$' .. string.format('%.2f', value)
end

function M.challenge_to_html(challenge, rpc_url)
  local plain = {
    id = challenge.id,
    realm = challenge.realm,
    method = challenge.method,
    intent = challenge.intent,
    request = challenge.request:raw(),
    expires = challenge.expires,
    description = challenge.description,
    digest = challenge.digest,
    opaque = challenge.opaque and challenge.opaque:raw() or nil,
  }

  local challenge_json = json.encode(plain)

  -- Decode the base64url request field to extract display data and network.
  local network = 'mainnet-beta'
  local request_data = {}
  local decoded_payload, decode_err = base64url.decode(plain.request)
  if decoded_payload then
    local ok, decoded_request = pcall(json.decode, decoded_payload)
    if ok and type(decoded_request) == 'table' then
      request_data = decoded_request
      local method_details = decoded_request.methodDetails
      if type(method_details) == 'table' and type(method_details.network) == 'string' then
        network = method_details.network
      end
    end
  end

  local test_mode = (network == 'devnet' or network == 'localnet')

  local embedded_data = {
    challenge = plain,
    network = network,
    rpcUrl = rpc_url,
    testMode = test_mode,
  }
  local embedded_json = json.encode(embedded_data):gsub('<', '\\u003c')

  local description = challenge.description or request_data.description
  local description_html = ''
  if type(description) == 'string' and description ~= '' then
    description_html = '<p class="mppx-summary-description">' .. html_escape(description) .. '</p>'
  end

  local expires_html = ''
  if type(challenge.expires) == 'string' and challenge.expires ~= '' then
    local escaped_expires = html_escape(challenge.expires)
    expires_html = '<p class="mppx-summary-expires">Expires at <time datetime="' .. escaped_expires .. '">' .. escaped_expires .. '</time></p>'
  end

  local output = assets.html_template
  output = replace_once(output, '{{AMOUNT}}', html_escape(amount_display(request_data)))
  output = replace_once(output, '{{DESCRIPTION}}', description_html)
  output = replace_once(output, '{{EXPIRES}}', expires_html)
  output = replace_once(output, '{{DATA_JSON}}', embedded_json)
  output = output:gsub('^<!doctype html>', '<!DOCTYPE html>', 1)

  -- Keep the old debug block so local tests and developers can inspect the
  -- challenge without executing the generated browser bundle.
  return output .. '\n<details hidden><pre>' .. html_escape(challenge_json) .. '</pre></details>'
end

return M
