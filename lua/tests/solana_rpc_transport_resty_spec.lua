--[[
Tests for the non-blocking cosocket transport used by the Kong /
OpenResty plugin. Codex PR #103 review flagged P1 that the Kong
plugin handler must NOT use the blocking LuaSocket / LuaSec
transport. This spec verifies that the resty transport:

  * refuses to run outside a cosocket-capable nginx phase
  * forwards POST + JSON body + headers to `resty.http:request_uri`
  * returns the response body string on 2xx
  * raises a typed transport-error on connection failure
  * raises a typed transport-error on 5xx upstream

The test fakes `ngx` and the `resty.http` module so the suite stays
nginx-free; production coverage runs through the focused harness
matrix once a Kong container is available.
]]

local helper = require('tests.test_helper')

local real_ngx = _G.ngx
local real_resty_http = package.loaded['resty.http']

local function install_ngx_stub(phase)
  _G.ngx = {
    get_phase = function() return phase or 'access' end,
  }
end

local function uninstall()
  _G.ngx = real_ngx
  package.loaded['resty.http'] = real_resty_http
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
end

local function install_resty_stub(behavior)
  package.loaded['resty.http'] = {
    new = function()
      return {
        set_timeouts = function(_self, _connect, _send, _read) end,
        request_uri = function(_self, url, opts)
          behavior.last_url = url
          behavior.last_opts = opts
          if behavior.connect_err then
            return nil, behavior.connect_err
          end
          return {
            status = behavior.status or 200,
            body = behavior.body or '{"jsonrpc":"2.0","result":"ok","id":1}',
            headers = {},
          }
        end,
      }
    end,
  }
end

helper.test('rpc_transport_resty refuses to run outside a cosocket phase', function()
  install_ngx_stub('init')
  install_resty_stub({})
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  helper.assert_error(function()
    resty.new()('https://api.mainnet-beta.solana.com', '{}')
  end, 'cosocket')
  uninstall()
end)

helper.test('rpc_transport_resty refuses to run with no ngx at all', function()
  _G.ngx = nil
  install_resty_stub({})
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  helper.assert_error(function()
    resty.new()('https://api.mainnet-beta.solana.com', '{}')
  end, 'cosocket')
  uninstall()
end)

helper.test('rpc_transport_resty forwards POST + body + headers via cosocket', function()
  install_ngx_stub('access')
  local behavior = { body = '{"jsonrpc":"2.0","result":"hi","id":1}' }
  install_resty_stub(behavior)
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  local response = resty.new()('https://api.example.com', '{"jsonrpc":"2.0"}')
  helper.assert_equal(response, '{"jsonrpc":"2.0","result":"hi","id":1}')
  helper.assert_equal(behavior.last_url, 'https://api.example.com')
  helper.assert_equal(behavior.last_opts.method, 'POST')
  helper.assert_equal(behavior.last_opts.body, '{"jsonrpc":"2.0"}')
  helper.assert_equal(behavior.last_opts.headers['content-type'], 'application/json')
  helper.assert_equal(behavior.last_opts.headers['accept'], 'application/json')
  helper.assert_true(behavior.last_opts.headers['content-length'] ~= nil,
    'content-length header is set')
  uninstall()
end)

helper.test('rpc_transport_resty raises typed transport-error on connect failure', function()
  install_ngx_stub('access')
  install_resty_stub({ connect_err = 'connection refused' })
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  helper.assert_error(function()
    resty.new()('http://localhost:1/', '{}')
  end, 'http request failed')
  uninstall()
end)

helper.test('rpc_transport_resty raises typed transport-error on 5xx', function()
  install_ngx_stub('access')
  install_resty_stub({ status = 503 })
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  helper.assert_error(function()
    resty.new()('http://localhost/', '{}')
  end, 'http request returned 503')
  uninstall()
end)

helper.test('rpc_transport_resty raises a clear error when resty.http is missing', function()
  install_ngx_stub('access')
  -- Force resty.http loading to fail by injecting a sentinel module that
  -- raises on first access; the transport pcalls require and surfaces
  -- the failure as a typed transport-error.
  package.loaded['resty.http'] = nil
  package.preload['resty.http'] = function()
    error('resty.http rock is not installed')
  end
  package.loaded['pay_kit.solana.rpc_transport_resty'] = nil
  local resty = require('pay_kit.solana.rpc_transport_resty')
  helper.assert_error(function()
    resty.new()('http://localhost/', '{}')
  end, 'resty.http is required')
  package.preload['resty.http'] = nil
  uninstall()
end)
