local t = require('tests.test_helper')
local mpp = require('tests._mpp')
local html = require('pay_kit.protocols.mpp.server.html')

local function new_server(overrides)
  overrides = overrides or {}
  return mpp.server.new({
    recipient = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h',
    currency = 'USDC',
    decimals = 6,
    network = overrides.network or 'localnet',
    secret_key = 'test-secret-key-long-enough-for-hmac',
    store = mpp.store.memory(),
    html = overrides.html,
    verify_payment = function(context)
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  })
end

-- accepts_html tests

t.test('accepts_html returns true for text/html', function()
  t.assert_true(html.accepts_html('text/html'))
end)

t.test('accepts_html returns false for application/json', function()
  t.assert_true(not html.accepts_html('application/json'))
end)

t.test('accepts_html returns true for text/html,application/json', function()
  t.assert_true(html.accepts_html('text/html,application/json'))
end)

t.test('accepts_html returns false for nil', function()
  t.assert_true(not html.accepts_html(nil))
end)

t.test('accepts_html returns false for empty string', function()
  t.assert_true(not html.accepts_html(''))
end)

-- is_service_worker_request tests

t.test('is_service_worker_request returns true when __mpp_worker is set', function()
  t.assert_true(html.is_service_worker_request({ __mpp_worker = '1' }))
end)

t.test('is_service_worker_request returns false when __mpp_worker is absent', function()
  t.assert_true(not html.is_service_worker_request({ foo = 'bar' }))
end)

t.test('is_service_worker_request returns false for nil', function()
  t.assert_true(not html.is_service_worker_request(nil))
end)

-- service_worker_js tests

t.test('service_worker_js returns non-empty string', function()
  local js = html.service_worker_js()
  t.assert_true(type(js) == 'string')
  t.assert_true(#js > 0)
end)

-- challenge_to_html tests

t.test('challenge_to_html renders valid HTML with challenge data', function()
  local server = new_server()
  local challenge = server:charge_with_options('0.50', {
    description = 'Test payment',
    external_id = 'html-test-1',
  })
  local output = server:challenge_to_html(challenge)
  t.assert_true(output:find('<!DOCTYPE html>', 1, true) ~= nil, 'expected <!DOCTYPE html>')
  t.assert_true(output:find('__MPP_DATA__', 1, true) ~= nil, 'expected __MPP_DATA__')
  t.assert_true(output:find('id="root"', 1, true) ~= nil, 'expected id="root"')
  t.assert_true(output:find(challenge.id, 1, true) ~= nil, 'expected challenge id in output')
end)

-- html_enabled tests

t.test('html_enabled returns false by default', function()
  local server = new_server()
  t.assert_true(not server:html_enabled())
end)

t.test('html_enabled returns true when html option is set', function()
  local server = new_server({ html = true })
  t.assert_true(server:html_enabled())
end)

-- devnet network / testMode tests

t.test('challenge_to_html with devnet contains testMode true', function()
  local server = new_server({ network = 'devnet' })
  local challenge = server:charge('1')
  local output = server:challenge_to_html(challenge)
  t.assert_true(output:find('"testMode":true', 1, true) ~= nil
    or output:find('"testMode": true', 1, true) ~= nil,
    'expected testMode to be true for devnet')
end)

-- XSS test

t.test('challenge_to_html escapes HTML in description', function()
  local server = new_server()
  local challenge = server:charge_with_options('1', {
    description = '<script>alert("xss")</script>',
  })
  local output = server:challenge_to_html(challenge)
  -- The <pre> block should contain escaped HTML, not raw <script> tags
  t.assert_true(output:find('<script>alert', 1, true) == nil,
    'raw <script> tag should not appear in the <pre> output')
  t.assert_true(output:find('&lt;script&gt;', 1, true) ~= nil,
    'expected escaped &lt;script&gt; in output')
end)
