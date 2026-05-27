local t = require('tests.test_helper')
local rpc = require('pay_kit.solana.rpc')
local json = require('pay_kit.util.json')

--- Build a fake transport that returns canned responses in order. Each
--- response can be a string (returned verbatim) or a table that is
--- JSON-encoded before being handed back. Capture the requests sent so the
--- tests can assert on method, params, and id assignment.
local function fake_transport(responses)
  local state = { requests = {}, index = 0 }
  state.fn = function(url, body)
    state.index = state.index + 1
    state.requests[#state.requests + 1] = { url = url, body = body }
    local response = responses[state.index]
    if response == nil then
      error('unexpected request #' .. state.index)
    end
    if type(response) == 'function' then
      return response(url, body)
    end
    if type(response) == 'table' then
      return json.encode(response)
    end
    return response
  end
  return state
end

t.test('rpc constructor rejects missing url', function()
  t.assert_error(function()
    rpc.new({ transport = function() return '' end })
  end, 'url is required')
end)

t.test('rpc constructor rejects missing transport', function()
  t.assert_error(function()
    rpc.new({ url = 'http://example' })
  end, 'transport function is required')
end)

t.test('rpc constructor rejects non-table config', function()
  t.assert_error(function()
    rpc.new('not a table')
  end, 'config table is required')
end)

t.test('rpc call assigns monotonic ids', function()
  local fake = fake_transport({
    { jsonrpc = '2.0', id = 1, result = 'one' },
    { jsonrpc = '2.0', id = 2, result = 'two' },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  t.assert_equal(client:call('method-a', {}), 'one')
  t.assert_equal(client:call('method-b', {}), 'two')
  local req1 = json.decode(fake.requests[1].body)
  local req2 = json.decode(fake.requests[2].body)
  t.assert_equal(req1.id, 1)
  t.assert_equal(req2.id, 2)
  t.assert_equal(req1.method, 'method-a')
  t.assert_equal(req2.method, 'method-b')
  t.assert_equal(req1.jsonrpc, '2.0')
end)

t.test('rpc call surfaces transport nil-body errors with transport-error code', function()
  local fake = fake_transport({
    function() return nil, 'ECONNREFUSED' end,
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok, 'expected error')
  t.assert_equal(err.code, 'transport-error')
  t.assert_true(err.message:find('ECONNREFUSED', 1, true) ~= nil)
end)

t.test('rpc call wraps raising transport as transport-error', function()
  -- Mirrors Ruby's `rescue *NETWORK_ERRORS`: a transport that raises must
  -- surface as the typed transport-error so callers do not need to know
  -- the underlying HTTP client error class.
  local client = rpc.new({
    url = 'http://example',
    transport = function() error('boom from socket layer') end,
  })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok, 'expected error')
  t.assert_equal(err.code, 'transport-error')
  t.assert_true(err.message:find('boom from socket', 1, true) ~= nil)
end)

t.test('rpc call wraps raising transport that raises a typed error table', function()
  local client = rpc.new({
    url = 'http://example',
    transport = function() error({ code = 'timeout', message = 'read timeout' }) end,
  })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'transport-error')
  t.assert_true(err.message:find('read timeout', 1, true) ~= nil)
end)

t.test('rpc call rejects empty response body', function()
  local fake = fake_transport({ '' })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'transport-error')
end)

t.test('rpc call surfaces malformed JSON as protocol-error', function()
  local fake = fake_transport({ '{not json' })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('rpc call surfaces non-object response as protocol-error', function()
  local fake = fake_transport({ '[]' })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('rpc call surfaces JSON-RPC error object as rpc-error', function()
  local fake = fake_transport({
    { jsonrpc = '2.0', id = 1, error = { code = -32601, message = 'method not found' } },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'rpc-error')
  t.assert_true(err.message:find('method not found', 1, true) ~= nil)
end)

t.test('rpc call surfaces JSON-RPC string error as rpc-error', function()
  local fake = fake_transport({
    '{"jsonrpc":"2.0","id":1,"error":"boom"}',
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:call('m', {}) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'rpc-error')
  t.assert_true(err.message:find('boom', 1, true) ~= nil)
end)

t.test('latest_blockhash returns blockhash from value envelope', function()
  local fake = fake_transport({
    {
      jsonrpc = '2.0',
      id = 1,
      result = { context = { slot = 1 }, value = { blockhash = 'hashy', lastValidBlockHeight = 42 } },
    },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  t.assert_equal(client:latest_blockhash(), 'hashy')
  local req = json.decode(fake.requests[1].body)
  t.assert_equal(req.method, 'getLatestBlockhash')
  t.assert_equal(req.params[1].commitment, 'confirmed')
end)

t.test('latest_blockhash rejects missing value envelope', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = {} } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:latest_blockhash() end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('latest_blockhash rejects missing blockhash field', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = { value = {} } } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:latest_blockhash() end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('simulate_transaction returns value envelope', function()
  local fake = fake_transport({
    {
      jsonrpc = '2.0',
      id = 1,
      result = { context = { slot = 1 }, value = { err = nil, logs = { 'ok' } } },
    },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local value = client:simulate_transaction('AAAA')
  t.assert_equal(type(value), 'table')
  t.assert_equal(value.logs[1], 'ok')
  local req = json.decode(fake.requests[1].body)
  t.assert_equal(req.method, 'simulateTransaction')
  t.assert_equal(req.params[1], 'AAAA')
  t.assert_equal(req.params[2].encoding, 'base64')
  t.assert_equal(req.params[2].sigVerify, false)
end)

t.test('simulate_transaction rejects missing value envelope', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = {} } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:simulate_transaction('AAAA') end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('send_raw_transaction returns base58 signature', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = 'sigxyz' } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  t.assert_equal(client:send_raw_transaction('AAAA'), 'sigxyz')
  local req = json.decode(fake.requests[1].body)
  t.assert_equal(req.method, 'sendTransaction')
  t.assert_equal(req.params[1], 'AAAA')
  t.assert_equal(req.params[2].encoding, 'base64')
  t.assert_equal(req.params[2].skipPreflight, false)
end)

t.test('send_raw_transaction rejects empty signature', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = '' } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:send_raw_transaction('AAAA') end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('signature_statuses returns value array', function()
  local fake = fake_transport({
    {
      jsonrpc = '2.0',
      id = 1,
      result = {
        context = { slot = 1 },
        value = {
          { confirmationStatus = 'confirmed', err = nil },
          { confirmationStatus = 'finalized', err = nil },
        },
      },
    },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local statuses = client:signature_statuses({ 'a', 'b' })
  t.assert_equal(#statuses, 2)
  t.assert_equal(statuses[1].confirmationStatus, 'confirmed')
  t.assert_equal(statuses[2].confirmationStatus, 'finalized')
end)

t.test('signature_statuses rejects empty input array', function()
  local fake = fake_transport({})
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  t.assert_error(function() client:signature_statuses({}) end, 'non%-empty')
end)

t.test('signature_statuses rejects missing value envelope', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = {} } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local ok, err = pcall(function() client:signature_statuses({ 'a' }) end)
  t.assert_true(not ok)
  t.assert_equal(err.code, 'protocol-error')
end)

t.test('transaction returns raw response', function()
  local fake = fake_transport({
    {
      jsonrpc = '2.0',
      id = 1,
      result = { meta = { err = nil }, transaction = { 'b64', 'base64' } },
    },
  })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  local response = client:transaction('sig')
  t.assert_equal(response.meta.err, nil)
  t.assert_equal(response.transaction[1], 'b64')
  local req = json.decode(fake.requests[1].body)
  t.assert_equal(req.method, 'getTransaction')
  t.assert_equal(req.params[1], 'sig')
  t.assert_equal(req.params[2].encoding, 'base64')
end)

t.test('transaction returns nil for unknown signature', function()
  local fake = fake_transport({ { jsonrpc = '2.0', id = 1, result = json.null } })
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  -- json.null sentinel decodes as the null sentinel, callers must treat it as
  -- "not yet observed" the same way they treat a real nil. The RPC layer does
  -- not down-convert that for them so the contract is identical to Ruby's.
  local response = client:transaction('sig')
  t.assert_true(response == json.null)
end)

t.test('transaction rejects empty signature input', function()
  local fake = fake_transport({})
  local client = rpc.new({ url = 'http://example', transport = fake.fn })
  t.assert_error(function() client:transaction('') end, 'non%-empty')
end)

t.test('rpc passes through configured commitment', function()
  local fake = fake_transport({
    {
      jsonrpc = '2.0',
      id = 1,
      result = { value = { blockhash = 'h', lastValidBlockHeight = 1 } },
    },
  })
  local client = rpc.new({
    url = 'http://example',
    transport = fake.fn,
    commitment = 'finalized',
  })
  client:latest_blockhash()
  local req = json.decode(fake.requests[1].body)
  t.assert_equal(req.params[1].commitment, 'finalized')
end)
