--[[
Minimal Solana JSON-RPC client used by the Lua charge server's settlement
lifecycle. Mirrors the surface of `ruby/lib/mpp/methods/solana/rpc.rb` and
`php/src/Rpc/RpcClient.php`. The five methods exposed cover the entire
broadcast/await flow needed by `pay_kit.protocols.mpp.server.charge_handler`:

  - getLatestBlockhash
  - sendTransaction
  - simulateTransaction
  - getSignatureStatuses
  - getTransaction

The transport is injected so unit tests can drive the client without a real
RPC server. Production callers pass in an HTTP transport that performs
`POST <url>` with a JSON body and returns the raw response body as a string.
A reference `socket.http` transport is provided in `pay_kit.solana.rpc_transport`
(PR B) for example servers; this module deliberately does not depend on it
to keep `pay_kit.solana.rpc` itself test-only and pure-Lua.

Network and protocol errors surface as Lua `error()` values shaped like
`{ code = 'rpc-error'|'transport-error'|'protocol-error', message = '...' }`
so callers can distinguish socket-level failures from JSON-RPC errors. This
mirrors the wrapping discipline in Ruby `PayCore::Solana::Rpc`, which
catches `Errno::ECONNREFUSED` and friends and raises
`PayCore::Solana::Rpc::RpcError`.
]]

local json = require('pay_kit.util.json')

local M = {}

local DEFAULT_COMMITMENT = 'confirmed'

local Rpc = {}
Rpc.__index = Rpc

--- Construct a new RPC client.
--
-- @param config table  required keys: `url`, `transport` (function(url, body) -> body|nil, err)
-- @return table the RPC client instance
function M.new(config)
  if type(config) ~= 'table' then
    error('config table is required')
  end
  if type(config.url) ~= 'string' or config.url == '' then
    error('url is required')
  end
  if type(config.transport) ~= 'function' then
    error('transport function is required')
  end
  local instance = {
    url = config.url,
    transport = config.transport,
    commitment = config.commitment or DEFAULT_COMMITMENT,
    _request_id = 0,
  }
  return setmetatable(instance, Rpc)
end

local function rpc_error(message)
  error({ code = 'rpc-error', message = message })
end

local function transport_error(message)
  error({ code = 'transport-error', message = message })
end

local function protocol_error(message)
  error({ code = 'protocol-error', message = message })
end

--- Send a JSON-RPC `method` call with the given params.
-- Returns the `result` field of the JSON-RPC response on success.
-- Raises a typed error table on transport, protocol, or RPC-level failures.
function Rpc:call(method, params)
  self._request_id = self._request_id + 1
  local body = json.encode({
    jsonrpc = '2.0',
    id = self._request_id,
    method = method,
    params = params or {},
  })

  -- Run the transport under pcall so a raising HTTP client surfaces as a
  -- typed transport-error instead of leaking the raw Lua error to callers,
  -- mirroring Ruby's `rescue *NETWORK_ERRORS`/`Timeout::Error` wrapping.
  local pcall_ok, response_body, err = pcall(self.transport, self.url, body)
  if not pcall_ok then
    local raised = response_body
    local message = type(raised) == 'table' and raised.message or tostring(raised)
    transport_error(method .. ': ' .. message)
  end
  if response_body == nil then
    transport_error(method .. ': ' .. tostring(err or 'transport returned nil body'))
  end
  if type(response_body) ~= 'string' or response_body == '' then
    transport_error(method .. ': transport returned an empty response body')
  end

  local ok, parsed = pcall(json.decode, response_body)
  if not ok then
    protocol_error(method .. ': failed to decode response body: ' .. tostring(parsed))
  end
  if type(parsed) ~= 'table' then
    protocol_error(method .. ': response body is not a JSON object')
  end
  -- A well-formed JSON-RPC 2.0 response carries either a `result` or an
  -- `error` field. An array or empty object lacks both and is rejected so
  -- callers see a typed protocol-error instead of `nil` downstream.
  if parsed.result == nil and parsed.error == nil then
    protocol_error(method .. ': response body is missing both result and error fields')
  end

  if parsed.error ~= nil then
    local message = 'unknown error'
    if type(parsed.error) == 'table' and parsed.error.message then
      message = tostring(parsed.error.message)
    elseif type(parsed.error) == 'string' then
      message = parsed.error
    end
    rpc_error(method .. ': ' .. message)
  end

  return parsed.result
end

--- Return the latest blockhash from the configured commitment level.
function Rpc:latest_blockhash()
  local result = self:call('getLatestBlockhash', {
    { commitment = self.commitment },
  })
  if type(result) ~= 'table' or type(result.value) ~= 'table' then
    protocol_error('getLatestBlockhash: missing value envelope')
  end
  local blockhash = result.value.blockhash
  if type(blockhash) ~= 'string' or blockhash == '' then
    protocol_error('getLatestBlockhash: missing blockhash field')
  end
  return blockhash
end

--- Simulate a base64-encoded signed transaction. Returns the inner `value`
-- table from the RPC envelope so callers can inspect `err`/`logs` directly.
function Rpc:simulate_transaction(transaction_base64)
  local result = self:call('simulateTransaction', {
    transaction_base64,
    {
      encoding = 'base64',
      commitment = self.commitment,
      sigVerify = false,
    },
  })
  if type(result) ~= 'table' or type(result.value) ~= 'table' then
    protocol_error('simulateTransaction: missing value envelope')
  end
  return result.value
end

--- Submit a signed base64-encoded transaction. Returns the base58 signature.
function Rpc:send_raw_transaction(transaction_base64)
  local signature = self:call('sendTransaction', {
    transaction_base64,
    {
      encoding = 'base64',
      skipPreflight = false,
      preflightCommitment = self.commitment,
    },
  })
  if type(signature) ~= 'string' or signature == '' then
    protocol_error('sendTransaction: missing signature in response')
  end
  return signature
end

--- Return the status table for each signature, in input order.
function Rpc:signature_statuses(signatures)
  if type(signatures) ~= 'table' or #signatures == 0 then
    error('signatures must be a non-empty array')
  end
  local result = self:call('getSignatureStatuses', { signatures })
  if type(result) ~= 'table' or type(result.value) ~= 'table' then
    protocol_error('getSignatureStatuses: missing value envelope')
  end
  return result.value
end

--- Fetch a confirmed transaction by signature using base64 encoding. Returns
-- the raw RPC response table or nil if the transaction has not been observed
-- yet so callers can drive their own backoff loop.
function Rpc:transaction(signature)
  if type(signature) ~= 'string' or signature == '' then
    error('signature must be a non-empty string')
  end
  return self:call('getTransaction', {
    signature,
    {
      encoding = 'base64',
      commitment = self.commitment,
      maxSupportedTransactionVersion = 0,
    },
  })
end

M.Rpc = Rpc
M.DEFAULT_COMMITMENT = DEFAULT_COMMITMENT

return M
