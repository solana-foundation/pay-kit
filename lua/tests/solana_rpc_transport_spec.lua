local helper = require('tests.test_helper')

-- The transport module depends on socket.http / ssl.https / ltn12 at
-- require-time. The tests stub those out so the suite stays
-- transport-free; the integration coverage runs through the manual DX
-- gate and the focused harness matrix.

-- Use the real ltn12 from luasocket; stub only socket.http and ssl.https
-- so the test stays transport-free. Production coverage runs through the
-- manual DX gate and the focused harness matrix.
local real_http = package.loaded['socket.http']
local real_https = package.loaded['ssl.https']

local fake_http_called
local function install_http_stub(status)
  package.loaded['socket.http'] = {
    request = function(req)
      fake_http_called = req
      local ltn12 = require('ltn12')
      ltn12.pump.all(req.source, req.sink)
      return 1, status, {}, 'HTTP/1.1 ' .. tostring(status) .. ' OK'
    end,
  }
end

local fake_https_called
local function install_https_stub(body)
  package.loaded['ssl.https'] = {
    request = function(req)
      fake_https_called = req
      local ltn12 = require('ltn12')
      ltn12.pump.all(req.source, req.sink)
      -- Sink already received the request body; overwrite with the
      -- mocked response by appending the configured body.
      -- The simplest stub: ignore the request body and write the response.
      if req.sink then
        ltn12.pump.all(ltn12.source.string(body), req.sink)
      end
      return 1, 200, {}, 'HTTP/1.1 200 OK'
    end,
  }
end

helper.test('rpc_transport routes http:// through luasocket', function()
  install_http_stub(200)
  package.loaded['pay_kit.solana.rpc_transport'] = nil
  local rpc_transport = require('pay_kit.solana.rpc_transport')
  fake_http_called = nil
  local _ok, _err = pcall(rpc_transport.new(), 'http://localhost:8899', '{"jsonrpc":"2.0"}')
  helper.assert_true(fake_http_called ~= nil, 'luasocket request was called')
  helper.assert_equal(fake_http_called.method, 'POST')
  helper.assert_equal(fake_http_called.url, 'http://localhost:8899')
  package.loaded['socket.http'] = real_http
end)

helper.test('rpc_transport raises a typed error on 5xx', function()
  install_http_stub(500)
  package.loaded['pay_kit.solana.rpc_transport'] = nil
  local rpc_transport = require('pay_kit.solana.rpc_transport')
  helper.assert_error(function()
    rpc_transport.new()('http://localhost/', '{}')
  end, 'http request returned 500')
  package.loaded['socket.http'] = real_http
end)

helper.test('rpc_transport raises when the request fails outright', function()
  package.loaded['socket.http'] = { request = function(_) return nil, 'econnrefused' end }
  package.loaded['pay_kit.solana.rpc_transport'] = nil
  local rpc_transport = require('pay_kit.solana.rpc_transport')
  helper.assert_error(function()
    rpc_transport.new()('http://localhost/', '{}')
  end, 'http request failed')
  package.loaded['socket.http'] = real_http
end)

if real_https then
  helper.test('rpc_transport routes https:// through luasec when available', function()
    install_https_stub('{"jsonrpc":"2.0","result":"https","id":1}')
    package.loaded['pay_kit.solana.rpc_transport'] = nil
    local rpc_transport = require('pay_kit.solana.rpc_transport')
    local response = rpc_transport.new()('https://api.mainnet-beta.solana.com', '{"jsonrpc":"2.0"}')
    helper.assert_true(response:match('https') ~= nil, 'response carries the stubbed payload')
    package.loaded['ssl.https'] = real_https
  end)

  helper.test('rpc_transport enables luasec peer cert verification by default', function()
    install_https_stub('{"jsonrpc":"2.0","result":"x","id":1}')
    package.loaded['pay_kit.solana.rpc_transport'] = nil
    fake_https_called = nil
    local rpc_transport = require('pay_kit.solana.rpc_transport')
    rpc_transport.new()('https://api.mainnet-beta.solana.com', '{"jsonrpc":"2.0"}')
    helper.assert_true(fake_https_called ~= nil, 'luasec request was called')
    helper.assert_equal(fake_https_called.verify, 'peer')
    helper.assert_equal(fake_https_called.protocol, 'tlsv1_2')
    helper.assert_true(type(fake_https_called.options) == 'table', 'ssl options set')
    package.loaded['ssl.https'] = real_https
  end)

  helper.test('rpc_transport allows opts.ssl_verify override for explicit insecure callers', function()
    install_https_stub('{"jsonrpc":"2.0","result":"x","id":1}')
    package.loaded['pay_kit.solana.rpc_transport'] = nil
    fake_https_called = nil
    local rpc_transport = require('pay_kit.solana.rpc_transport')
    rpc_transport.new({ ssl_verify = 'none' })('https://api.mainnet-beta.solana.com', '{"jsonrpc":"2.0"}')
    helper.assert_equal(fake_https_called.verify, 'none')
    package.loaded['ssl.https'] = real_https
  end)
end
