local M = {}

local function days_from_civil(year, month, day)
  year = year - (month <= 2 and 1 or 0)
  local era = math.floor((year >= 0 and year or year - 399) / 400)
  local yoe = year - era * 400
  local mp = month + (month > 2 and -3 or 9)
  local doy = math.floor((153 * mp + 2) / 5) + day - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
end

local function days_in_month(year, month)
  if month == 2 then
    local leap = (year % 4 == 0 and year % 100 ~= 0) or (year % 400 == 0)
    return leap and 29 or 28
  end
  if month == 4 or month == 6 or month == 9 or month == 11 then
    return 30
  end
  return 31
end

-- Strict RFC 3339 date-time grammar (sec 5.6).
-- Accepts: T/t separator, Z/z or +/-HH:MM offset, optional 1..9 digit fractional seconds.
-- Rejects: missing time-offset, lowercase compat from older parser only, calendar dates that do not exist, year > 9999.
function M.parse_rfc3339(value)
  if type(value) ~= 'string' then
    return nil, 'invalid RFC3339 timestamp'
  end
  -- RFC 3339 sec 5.6 grammar: optional `time-secfrac = "." 1*DIGIT`. The dot must be
  -- accompanied by at least one digit. Match the fractional component as one optional
  -- group so a bare dot (e.g. "2099-01-01T00:00:00.Z") fails parsing rather than being
  -- silently accepted as zero fractional seconds (diverges from PHP/Ruby strict parsers).
  local year, month, day, hour, min, sec, rest = value:match(
    '^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt](%d%d):(%d%d):(%d%d)(.*)$'
  )
  if not year then
    return nil, 'invalid RFC3339 timestamp'
  end
  local frac, offset = rest:match('^%.(%d+)([Zz%+%-][%d:]*)$')
  if not frac then
    frac = ''
    offset = rest:match('^([Zz%+%-][%d:]*)$')
    if not offset then
      return nil, 'invalid RFC3339 timestamp'
    end
  end
  if #frac > 9 then
    return nil, 'fractional seconds exceed 9 digits'
  end
  year = tonumber(year)
  month = tonumber(month)
  day = tonumber(day)
  hour = tonumber(hour)
  min = tonumber(min)
  sec = tonumber(sec)

  if year > 9999 then
    return nil, 'invalid RFC3339 year'
  end
  if month < 1 or month > 12 then
    return nil, 'invalid RFC3339 month'
  end
  -- RFC 3339 §5.7 allows sec = 60 for positive leap seconds. The
  -- broader RFC requires that a leap second be inserted only at
  -- 23:59:60 UTC; we accept the value at the parser level and let
  -- downstream consumers reject the rare time-of-day combinations.
  if hour > 23 or min > 59 or sec > 60 then
    return nil, 'invalid RFC3339 time-of-day'
  end
  if day < 1 or day > days_in_month(year, month) then
    return nil, 'invalid RFC3339 calendar date'
  end

  local offset_secs
  if offset == 'Z' or offset == 'z' then
    offset_secs = 0
  else
    local sign, oh, om = offset:match('^([%+%-])(%d%d):(%d%d)$')
    if not sign then
      return nil, 'invalid RFC3339 offset'
    end
    oh = tonumber(oh)
    om = tonumber(om)
    if oh > 23 or om > 59 then
      return nil, 'invalid RFC3339 offset'
    end
    offset_secs = (oh * 60 + om) * 60
    if sign == '+' then
      offset_secs = -offset_secs
    end
  end

  local days = days_from_civil(year, month, day)
  return ((days * 24 + hour) * 60 + min) * 60 + sec + offset_secs
end

-- Format a UTC epoch second as a strict RFC 3339 / ISO 8601 timestamp
-- (`YYYY-MM-DDTHH:MM:SSZ`), the wire form the `expires` challenge field
-- and `parse_rfc3339` round-trip on. Used by the MPP adapter to turn a
-- config `expires_in` (seconds-from-now) into an absolute expiry.
function M.format_rfc3339(epoch)
  return os.date('!%Y-%m-%dT%H:%M:%SZ', epoch)
end

function M.is_expired(value, now_epoch)
  if value == nil or value == '' then
    return false
  end
  local expires_at = M.parse_rfc3339(value)
  if not expires_at then
    return true
  end
  return expires_at <= now_epoch
end

return M
