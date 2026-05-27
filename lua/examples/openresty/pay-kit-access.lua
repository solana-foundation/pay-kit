-- Access-phase PayKit middleware for OpenResty / Kong.
--
-- One-line gating via the new `pay_kit` umbrella. Replaces the
-- legacy `mpp.server.new(...)` boilerplate in lua/examples/nginx/
-- access.lua. Drop into an `access_by_lua_file` block; the lib emits
-- the 402 + WWW-Authenticate / PAYMENT-REQUIRED headers via
-- pay_kit.require_payment() and halts via ngx.exit on unpaid traffic.
--
-- Boot wiring lives in `init_by_lua_block` (run once at master init;
-- see `nginx.conf` in this directory). configure() pins the
-- operator + signer + RPC URL + MPP secret; pay_kit.gate() declares
-- each paid surface up front so the access-phase call is just the
-- lookup.

local pay_kit = require('pay_kit')

pay_kit.require_payment('report')

-- If we got here, pay_kit.ctx is populated and the protected route
-- runs in the content phase. `pay_kit.payment()` is also available
-- via the same `pay_kit` module if downstream Lua needs the
-- signature, scheme, or settlement headers.
