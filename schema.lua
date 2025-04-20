-- threat-protection/schema.lua
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "threat-protection",
  fields = {
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {
          { max_json_depth = { type = "integer", default = 10 } },
          { max_json_keys = { type = "integer", default = 100 } },
          {
            forbidden_json_keys = {
              type = "array",
              elements = { type = "string" },
              default = { "__proto__", "constructor", "$where" }
            }
          },
          {
            forbidden_patterns = {
              type = "array",
              elements = { type = "string" },
              default = {
                -- SQLi
                "UNION", "SELECT", "INSERT", "DROP", "--", ";",
                -- XSS
                "<script>", "javascript:", "onerror=", "eval\\(", "document\\."
              }
            }
          },
          {
            scan_raw_body = { type = "boolean", default = false }
          }
        }
      }
    }
  }
}