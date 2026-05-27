-- Pure-Lua base58 (public surface per issue #140 Layers section).
-- Re-exports the legacy mpp.util.base58 implementation so callers
-- stay inside the pay_kit namespace.
return require('mpp.util.base58')
