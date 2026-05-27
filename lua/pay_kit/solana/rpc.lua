--[[
Cosocket-aware Solana JSON-RPC client.

Public surface listed in the design (issue #140 Layers section):
`pay_kit.solana.rpc`. Thin re-export of `mpp.solana.rpc` so
callers can stick to the pay_kit namespace and not reach into
the legacy `mpp.*` tree as it moves toward the deprecation-removal
window. The transport choice (`resty.http` cosocket vs `luasocket`
plain-Lua) is still picked at `rpc.new(...)` call time per the
inner module's options.
]]

return require('mpp.solana.rpc')
