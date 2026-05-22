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

  -- Decode the base64url request field to extract network from methodDetails.
  local network = 'mainnet-beta'
  local decoded_payload, _decode_err = base64url.decode(plain.request)
  if decoded_payload then
    local ok, request_data = pcall(json.decode, decoded_payload)
    if ok and type(request_data) == 'table' then
      local method_details = request_data.methodDetails
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
  local embedded_json = json.encode(embedded_data)

  local parts = {
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>Payment Required</title>',
    '<style>',
    'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; background: #f7fafc; color: #1a202c; }',
    'pre { background: #edf2f7; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; max-width: 600px; margin: 20px auto; }',
    '</style>',
    '</head>',
    '<body>',
    '<details style="max-width:600px;margin:0 auto 20px">',
    '<summary style="cursor:pointer;color:#718096;font-size:14px">Challenge details</summary>',
    '<pre>' .. html_escape(challenge_json) .. '</pre>',
    '</details>',
    '<div id="root"></div>',
    -- JSON inside <script type="application/json"> is not parsed as HTML.
    -- json.encode already escapes special chars in string values.
    '<script type="application/json" id="__MPP_DATA__">' .. embedded_json .. '</script>',
    -- The generated payment-UI JS bundle is produced by `html/` and copied in
    -- via the html-assets workflow artifact. Render the page even when the
    -- bundle is absent (e.g. local dev without `npm run build`) so the test
    -- and example flows can still exercise the HTML response shape.
    '<script>' .. (assets.payment_ui_js or '') .. '</script>',
    '</body>',
    '</html>',
  }

  return table.concat(parts, '\n')
end

return M
