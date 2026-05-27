--[[
KMS-backed signer namespace (reserved, not implemented in v1).

The design locks in the `pay_kit.kms.*` module path now so the
post-v1 follow-up can land remote-enclave signer backends (GCP KMS,
AWS KMS, HashiCorp Vault, Turnkey, Privy, Fireblocks, HSMs) without
forcing every caller to rename their require lines.

Each factory raises `pay_kit: not implemented` so a caller who reaches
for the namespace early gets a deterministic error instead of a silent
nil. Return shape (`signer, err`) when implemented will match the
local signer family in `pay_kit.signer` (`:pubkey()`, `:sign()`,
`:fee_payer()`, `:demo()`).
]]

local M = {}

local function not_implemented(name)
  return nil, 'pay_kit.kms.' .. name .. ' is reserved for a post-v1 release; not implemented yet'
end

function M.gcp(_opts)
  return not_implemented('gcp')
end

function M.aws(_opts)
  return not_implemented('aws')
end

function M.vault(_opts)
  return not_implemented('vault')
end

return M
