-- Canonical-JSON (RFC 8785) for MPP challenge binding. Public surface
-- per issue #140 Layers section. Re-exports the legacy mpp.util.json
-- implementation, which already does the deterministic key-order
-- encoding the cross-language spec requires for HMAC reproducibility.
return require('mpp.util.json')
