-- Access-phase PayKit gate for OpenResty / nginx.
--
-- One line gates the route declared in nginx.conf's init_by_lua_block.
-- The umbrella issues the 402 + WWW-Authenticate / PAYMENT-REQUIRED
-- headers and halts via ngx.exit on unpaid traffic; on a valid
-- credential it stamps the settlement headers and lets the content
-- phase render the protected payload.
--
-- Boot wiring (configure + gate) lives in nginx.conf's
-- init_by_lua_block, which runs once at master init.

local pay_kit = require('pay_kit')

pay_kit.require_payment('report')

-- Reaching here means the credential settled. pay_kit.payment() exposes
-- the signature / settlement headers if downstream Lua needs them.
