local http = require "http"
local json = require "json"
local math = require "math"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Looks for exposed API documentation and API entry points on web servers.

It probes a list of well-known paths and validates the content of each
response, so a generic 200 page is not reported as a finding:

* OpenAPI / Swagger specification files (JSON are parsed, YAML are detected).
  For parsed specs it reports the version, title, server URL, number of paths,
  a sample of endpoints and the declared authentication schemes.
* API documentation UIs (Swagger UI, ReDoc, RapiDoc, GraphiQL).
* GraphQL endpoints. A single read-only query is sent to check whether
  introspection is enabled.
* Common API roots (/api, /api/v1, Spring Boot /actuator). Responses that look
  like the server's "not found" answer are ignored; 401/403 responses are
  reported as "exists, requires authentication".

Before probing it requests a random path to learn how the server answers
unknown URLs, which reduces false positives on catch-all (soft 404) servers.

The script only sends GET requests and one read-only GraphQL POST. Use it only
on systems you are authorized to test.
]]

---
-- @usage
-- nmap -p80,443,8080 --script api-discovery <target>
-- nmap --script api-discovery --script-args 'api-discovery.basepath=/app' <target>
-- nmap --script api-discovery --script-args 'api-discovery.paths=/internal/docs,/v4/api-docs' <target>
--
-- @args api-discovery.paths      Comma-separated extra paths to check (they are
--                                tested as spec, UI or API root automatically).
-- @args api-discovery.basepath   Prefix added to every path (e.g. /app).
-- @args api-discovery.maxendpoints  Max number of endpoints listed per spec.
--                                Default: 10.
-- @args api-discovery.introspection Set to "false" to send a trivial
--                                { __typename } query instead of the
--                                introspection query. Default: true.
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | api-discovery:
-- |   paths_checked: 27
-- |   findings:
-- |     /openapi.json:
-- |       type: OpenAPI specification
-- |       status: 200
-- |       version: 3.0.1
-- |       title: Pet Store API
-- |       paths_total: 14
-- |       endpoints:
-- |         GET /pets
-- |         GET,POST /users
-- |       auth_schemes:
-- |         bearerAuth (http)
-- |     /graphql:
-- |       type: GraphQL endpoint
-- |       status: 200
-- |       introspection: enabled
-- |_      query_type: Query

author = "2Fac3R"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

-- kind: spec | ui | graphql | generic
local CANDIDATES = {
  -- OpenAPI / Swagger specification files
  {path = "/openapi.json", kind = "spec"},
  {path = "/openapi.yaml", kind = "spec"},
  {path = "/swagger.json", kind = "spec"},
  {path = "/swagger.yaml", kind = "spec"},
  {path = "/swagger/v1/swagger.json", kind = "spec"},
  {path = "/v2/api-docs", kind = "spec"},
  {path = "/v3/api-docs", kind = "spec"},
  {path = "/api-docs", kind = "spec"},
  {path = "/api/swagger.json", kind = "spec"},
  {path = "/api/openapi.json", kind = "spec"},
  {path = "/api/v1/openapi.json", kind = "spec"},
  -- Documentation UIs
  {path = "/swagger-ui.html", kind = "ui"},
  {path = "/swagger-ui/", kind = "ui"},
  {path = "/swagger/", kind = "ui"},
  {path = "/swagger/index.html", kind = "ui"},
  {path = "/docs", kind = "ui"},
  {path = "/api/docs", kind = "ui"},
  {path = "/redoc", kind = "ui"},
  {path = "/graphiql", kind = "ui"},
  -- GraphQL
  {path = "/graphql", kind = "graphql"},
  {path = "/api/graphql", kind = "graphql"},
  {path = "/v1/graphql", kind = "graphql"},
  -- API roots
  {path = "/api", kind = "generic", note = "API root"},
  {path = "/api/v1", kind = "generic", note = "API root"},
  {path = "/api/v2", kind = "generic", note = "API root"},
  {path = "/actuator", kind = "generic", note = "Spring Boot Actuator"},
}

local UI_SIGNATURES = {
  {"swagger-ui", "Swagger UI"},
  {"swaggeruibundle", "Swagger UI"},
  {"redoc.standalone", "ReDoc"},
  {"<redoc", "ReDoc"},
  {"rapi-doc", "RapiDoc"},
  {"graphiql", "GraphiQL"},
}

local HTTP_METHODS = {
  get = true, post = true, put = true, delete = true,
  patch = true, head = true, options = true,
}

local function new_opts()
  return {
    no_cache = true,
    redirect_ok = false,
    header = {["Accept"] = "application/json, text/html;q=0.8, */*;q=0.5"},
  }
end

local function lower(s)
  return (s or ""):lower()
end

local function is_json_body(body)
  return body ~= nil and body:match("^%s*[%{%[]") ~= nil
end

local function random_path()
  local chars = "abcdefghijklmnopqrstuvwxyz0123456789"
  local t = {"/"}
  for _ = 1, 14 do
    local i = math.random(1, #chars)
    t[#t + 1] = chars:sub(i, i)
  end
  return table.concat(t)
end

-- True if the response looks like the server's answer to an unknown URL.
local function looks_like_baseline(resp, bl)
  if not bl then
    return false
  end
  return resp.status == bl.status
    and math.abs(#(resp.body or "") - #(bl.body or "")) < 32
end

local function first_server(spec)
  if type(spec.servers) == "table" and type(spec.servers[1]) == "table"
    and type(spec.servers[1].url) == "string" then
    return spec.servers[1].url
  end
  if type(spec.host) == "string" then
    return spec.host .. (type(spec.basePath) == "string" and spec.basePath or "")
  end
  return nil
end

local function auth_schemes(spec)
  local src
  if type(spec.components) == "table" and type(spec.components.securitySchemes) == "table" then
    src = spec.components.securitySchemes
  elseif type(spec.securityDefinitions) == "table" then
    src = spec.securityDefinitions
  end
  if not src then
    return nil
  end
  local names = {}
  for name, def in pairs(src) do
    local t = type(def) == "table" and def.type or nil
    names[#names + 1] = t and (name .. " (" .. tostring(t) .. ")") or name
  end
  table.sort(names)
  return #names > 0 and names or nil
end

local function summarize_endpoints(paths, maxep)
  local names = {}
  for p in pairs(paths) do
    names[#names + 1] = p
  end
  table.sort(names)
  local lines = {}
  for i = 1, math.min(maxep, #names) do
    local p = names[i]
    local methods = {}
    if type(paths[p]) == "table" then
      for m in pairs(paths[p]) do
        if HTTP_METHODS[tostring(m):lower()] then
          methods[#methods + 1] = tostring(m):upper()
        end
      end
    end
    table.sort(methods)
    local prefix = #methods > 0 and (table.concat(methods, ",") .. " ") or ""
    lines[#lines + 1] = prefix .. p
  end
  return #names, lines
end

-- OpenAPI 3.x / Swagger 2.0 specification (JSON parsed, YAML detected).
local function check_spec(resp, maxep)
  if resp.status ~= 200 or not resp.body then
    return nil
  end
  if is_json_body(resp.body) then
    local ok, spec = json.parse(resp.body)
    if not ok or type(spec) ~= "table" then
      return nil
    end
    local version = spec.openapi or spec.swagger
    if not version then
      return nil
    end
    local f = stdnse.output_table()
    f.type = "OpenAPI specification"
    f.status = resp.status
    f.version = tostring(version)
    if type(spec.info) == "table" and type(spec.info.title) == "string" then
      f.title = spec.info.title
    end
    local server = first_server(spec)
    if server then
      f.server = server
    end
    if type(spec.paths) == "table" then
      local total, lines = summarize_endpoints(spec.paths, maxep)
      f.paths_total = total
      if #lines > 0 then
        f.endpoints = lines
      end
    end
    local schemes = auth_schemes(spec)
    if schemes then
      f.auth_schemes = schemes
    end
    return f
  end
  local head = resp.body:sub(1, 2048)
  if head:match("^%s*openapi%s*:") or head:match("\nopenapi%s*:")
    or head:match("^%s*swagger%s*:") or head:match("\nswagger%s*:") then
    local f = stdnse.output_table()
    f.type = "OpenAPI specification (YAML)"
    f.status = resp.status
    return f
  end
  return nil
end

-- Documentation UI by body signature.
local function check_ui(resp)
  if resp.status ~= 200 or not resp.body then
    return nil
  end
  local body = lower(resp.body)
  for _, sig in ipairs(UI_SIGNATURES) do
    if body:find(sig[1], 1, true) then
      local f = stdnse.output_table()
      f.type = sig[2] .. " interface"
      f.status = resp.status
      return f
    end
  end
  return nil
end

-- Generic API root: needs structured content, or an auth challenge.
local function check_generic(resp, bl, note)
  if looks_like_baseline(resp, bl) then
    return nil
  end
  if resp.status == 200 then
    local ct = lower(resp.header["content-type"])
    if ct:find("json", 1, true) or ct:find("xml", 1, true) or is_json_body(resp.body) then
      local f = stdnse.output_table()
      f.type = note or "API endpoint"
      f.status = resp.status
      if ct ~= "" then
        f["content-type"] = ct
      end
      return f
    end
  elseif resp.status == 401 or resp.status == 403 then
    local f = stdnse.output_table()
    f.type = note or "API endpoint"
    f.status = resp.status
    f.note = "exists, requires authentication"
    local auth = resp.header["www-authenticate"]
    if auth then
      f["www-authenticate"] = auth
    end
    return f
  end
  return nil
end

-- One read-only POST: introspection (or {__typename} if disabled by arg).
local function check_graphql(host, port, url, introspect)
  local query
  if introspect then
    query = '{"query":"query { __schema { queryType { name } } }"}'
  else
    query = '{"query":"{ __typename }"}'
  end
  local opts = new_opts()
  opts.header["Content-Type"] = "application/json"
  local resp = http.post(host, port, url, opts, nil, query)
  if not resp or not resp.status or not resp.body then
    return nil
  end
  if not is_json_body(resp.body) then
    return nil
  end
  local ok, data = json.parse(resp.body)
  if not ok or type(data) ~= "table" then
    return nil
  end
  local f = stdnse.output_table()
  f.type = "GraphQL endpoint"
  f.status = resp.status
  local d = data.data
  if type(d) == "table" and type(d.__schema) == "table" then
    f.introspection = "enabled"
    local qt = d.__schema.queryType
    if type(qt) == "table" and type(qt.name) == "string" then
      f.query_type = qt.name
    end
    return f
  end
  if type(d) == "table" and d.__typename then
    f.note = "responds to queries"
    return f
  end
  if data.errors ~= nil then
    f.introspection = introspect and "disabled or restricted" or "not tested"
    return f
  end
  return nil
end

local function classify(resp, entry, bl, maxep)
  local kind = entry.kind
  if kind == "spec" or kind == "auto" then
    local f = check_spec(resp, maxep)
    if f then
      return f, true
    end
  end
  if kind == "ui" or kind == "auto" then
    local f = check_ui(resp)
    if f then
      return f, false
    end
  end
  if kind == "generic" or kind == "auto" then
    return check_generic(resp, bl, entry.note), false
  end
  return nil, false
end

action = function(host, port)
  local basepath = stdnse.get_script_args("api-discovery.basepath") or ""
  basepath = (tostring(basepath):gsub("/+$", ""))
  if basepath ~= "" and basepath:sub(1, 1) ~= "/" then
    basepath = "/" .. basepath
  end
  local maxep = tonumber(stdnse.get_script_args("api-discovery.maxendpoints")) or 10
  local introspect = tostring(stdnse.get_script_args("api-discovery.introspection") or "true"):lower() ~= "false"

  -- Candidate list: defaults plus user-supplied paths (deduplicated).
  local candidates, known = {}, {}
  for _, c in ipairs(CANDIDATES) do
    candidates[#candidates + 1] = c
    known[c.path] = true
  end
  local extra = stdnse.get_script_args("api-discovery.paths")
  if extra then
    for raw in tostring(extra):gmatch("[^,%s]+") do
      local p = raw
      if p:sub(1, 1) ~= "/" then
        p = "/" .. p
      end
      if not known[p] then
        candidates[#candidates + 1] = {path = p, kind = "auto"}
        known[p] = true
      end
    end
  end

  -- Learn how the server answers unknown URLs.
  local bl = http.get(host, port, basepath .. random_path(), new_opts())
  if not bl or not bl.status then
    stdnse.debug1("no response from %s:%d, skipping", host.ip, port.number)
    return nil
  end

  local findings = stdnse.output_table()
  local count = 0
  local seen_specs = {}

  for _, entry in ipairs(candidates) do
    local url = basepath .. entry.path
    local finding

    if entry.kind == "graphql" then
      finding = check_graphql(host, port, url, introspect)
    else
      local resp = http.get(host, port, url, new_opts())
      if resp and resp.status then
        local is_spec
        finding, is_spec = classify(resp, entry, bl, maxep)
        if finding and is_spec and resp.body then
          if seen_specs[resp.body] then
            finding.duplicate_of = seen_specs[resp.body]
          else
            seen_specs[resp.body] = url
          end
        end
      end
    end

    if finding then
      findings[url] = finding
      count = count + 1
    end
  end

  if count == 0 then
    return nil
  end

  local out = stdnse.output_table()
  out.paths_checked = #candidates
  out.findings = findings
  return out
end
