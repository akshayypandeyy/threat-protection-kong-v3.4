-- threat-protection/handler.lua
local kong = kong
local ngx = ngx
local cjson = require "cjson.safe"

local plugin = {
  PRIORITY = 2000,
  VERSION = "1.0.0",
}

-- Regex scanner
local function scan_string(value, patterns)
  for _, pattern in ipairs(patterns) do
    local m, err = ngx.re.match(value, pattern, "ijo")
    if m then return true, pattern, value end
  end
  return false
end

-- Header/query scanner
local function scan_table(tbl, patterns)
  for _, val in pairs(tbl) do
    local value = type(val) == "table" and table.concat(val, " ") or tostring(val)
    local found, pattern, matched = scan_string(value, patterns)
    if found then return true, pattern, matched end
  end
  return false
end

-- Recursive JSON validator
local function check_json(value, config, depth)
  if depth > config.max_json_depth then
    return false, "JSON exceeds max depth"
  end

  if type(value) == "table" then
    local key_count = 0

    for k, v in pairs(value) do
      key_count = key_count + 1

      for _, forbidden_key in ipairs(config.forbidden_json_keys or {}) do
        if tostring(k):lower() == forbidden_key:lower() then
          return false, "Forbidden JSON key: " .. k
        end
      end

      if type(v) == "string" then
        for _, pattern in ipairs(config.forbidden_patterns or {}) do
          if ngx.re.match(v, pattern, "ijo") then
            return false, "Forbidden pattern in JSON value: " .. pattern
          end
        end
      elseif type(v) == "table" then
        local ok, err = check_json(v, config, depth + 1)
        if not ok then return false, err end
      end
    end

    if key_count > config.max_json_keys then
      return false, "JSON exceeds max keys"
    end
  end

  return true
end

function plugin:access(conf)
  local patterns = conf.forbidden_patterns or {}

  -- 1. Raw query string
  local raw_query = kong.request.get_raw_query()
  if raw_query and raw_query ~= "" then
    local found, pattern, matched = scan_string(raw_query, patterns)
    if found then
      return kong.response.exit(403, {
        message = "Blocked: pattern in raw query",
        pattern = pattern,
        value = matched
      })
    end
  end

  -- 2. Parsed query
  local query = kong.request.get_query() or {}
  local found_q, pattern_q, match_q = scan_table(query, patterns)
  if found_q then
    return kong.response.exit(403, {
      message = "Blocked: pattern in query param",
      pattern = pattern_q,
      value = match_q
    })
  end

  -- 3. Headers
  local headers = kong.request.get_headers() or {}
  local found_h, pattern_h, match_h = scan_table(headers, patterns)
  if found_h then
    return kong.response.exit(403, {
      message = "Blocked: pattern in headers",
      pattern = pattern_h,
      value = match_h
    })
  end

  -- 4. JSON body check (only if content-type is JSON)
  local content_type = kong.request.get_header("content-type") or ""
  if ngx.re.find(content_type, "application/json", "ijo") then
    local raw_body = kong.request.get_raw_body()
    if raw_body and raw_body ~= "" then
      local parsed, err = cjson.decode(raw_body)
      if not parsed then
        return kong.response.exit(400, { message = "Malformed JSON" })
      end

      local ok, reason = check_json(parsed, conf, 1)
      if not ok then
        return kong.response.exit(403, {
          message = "Blocked: JSON violation",
          reason = reason
        })
      end
    end
  end

  -- 5. Optional: Scan raw body for patterns (if enabled)
  if conf.scan_raw_body then
    local raw_body = kong.request.get_raw_body()
    if raw_body and raw_body ~= "" then
      local found_rb, pattern_rb, matched_rb = scan_string(raw_body, patterns)
      if found_rb then
        return kong.response.exit(403, {
          message = "Blocked: pattern in raw body",
          pattern = pattern_rb,
          value = matched_rb
        })
      end
    end
  end
end

return plugin