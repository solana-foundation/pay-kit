--[[
OpenResty helper. Re-exports `pay_kit` and adds two thin nginx-flavoured
convenience methods so the typical access-phase usage doesn't need a
multi-line `access_by_lua_block`.

Usage:

  -- In init_by_lua_block:
  local pay_kit = require('plugins.resty.pay-kit')
  pay_kit.configure({ network = 'solana_localnet' })
  pay_kit.gate('report', { amount = pay_kit.usd('0.10') })

  -- In access_by_lua_*:
  require('plugins.resty.pay-kit').require_payment('report')

The umbrella's `require_payment` already halts via `ngx.exit(402)`
when no credential is present; this module is a re-export so users
can keep imports under one path.
]]

local pay_kit = require('pay_kit')

-- Re-exported surface, no behaviour change.
return pay_kit
