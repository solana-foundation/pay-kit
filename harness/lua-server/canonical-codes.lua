-- Mirror the consumed-signature rules in harness/src/canonical-codes.ts.
-- A duplicate pull-mode broadcast can fail at the RPC before the replay store.
local M = {}

function M.is_signature_consumed(message)
  if type(message) ~= 'string' then return false end
  local lower = message:lower()
  return lower:find('already consumed', 1, true) ~= nil
    or lower:find('signature.*consumed') ~= nil
    or lower:find('already been processed', 1, true) ~= nil
    or lower:find('transaction.*already.*processed') ~= nil
end

return M
