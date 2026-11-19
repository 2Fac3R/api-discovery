# api-discovery.nse

An [Nmap Scripting Engine](https://nmap.org/book/nse.html) script that looks for exposed API documentation and API entry points on web servers.

It probes a list of well-known paths and **validates the content** of each response, so a generic `200 OK` page is not reported as a finding.

> **Use only on systems you own or are explicitly authorized to test.**

## What it detects

| Kind | Examples | What is reported |
|---|---|---|
| OpenAPI / Swagger specs | `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/v3/api-docs` | JSON specs are parsed: version, title, server URL, number of paths, a sample of endpoints with methods, declared auth schemes. YAML specs are detected only. |
| Documentation UIs | `/swagger-ui.html`, `/docs`, `/redoc`, `/graphiql` | Swagger UI, ReDoc, RapiDoc or GraphiQL, identified by page content |
| GraphQL | `/graphql`, `/api/graphql`, `/v1/graphql` | Whether introspection is enabled and the query type name |
| API roots | `/api`, `/api/v1`, `/api/v2`, `/actuator` | Structured (JSON/XML) responses, or `401`/`403` reported as "exists, requires authentication" |

To reduce false positives, the script first requests a random path to learn how the server answers unknown URLs, and ignores responses that look the same.

## Requests it sends

- `GET` requests to the candidate paths (about 26 by default).
- One `POST` per GraphQL path with a read-only query:
  `query { __schema { queryType { name } } }` (or `{ __typename }` if introspection is disabled via argument).
- Redirects are **not** followed.

Categories: `safe`, `discovery`.

## Installation

```bash
# Copy next to the other scripts and refresh the script database
sudo cp api-discovery.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

The scripts folder may differ on your system (for example, a Homebrew install on macOS). You can also run the script without installing it by passing its path: `--script ./api-discovery.nse`.

## Usage

```bash
# Basic
nmap -p80,443,8080 --script api-discovery <target>

# Application served under a path prefix
nmap --script api-discovery --script-args 'api-discovery.basepath=/app' <target>

# Extra paths to check
nmap --script api-discovery \
  --script-args 'api-discovery.paths=/internal/docs,/v4/api-docs' <target>

# Do not send the introspection query (sends { __typename } instead)
nmap --script api-discovery --script-args 'api-discovery.introspection=false' <target>

# Combine arguments
nmap -p80,443 --script api-discovery \
  --script-args 'api-discovery.basepath=/app,api-discovery.maxendpoints=25' <target>

# Save results (XML keeps the structured output)
nmap -p80,443,8080 --script api-discovery -oA api-scan <target>
```

## Script arguments

| Argument | Default | Description |
|---|---|---|
| `api-discovery.paths` | none | Comma-separated extra paths. Each is tested automatically as spec, UI or API root. |
| `api-discovery.basepath` | none | Prefix added to every path (for example `/app`). |
| `api-discovery.maxendpoints` | `10` | Maximum number of endpoints listed per spec. |
| `api-discovery.introspection` | `true` | Set to `false` to send a trivial `{ __typename }` query instead of the introspection query. |

Standard `http.*` library arguments (such as `http.useragent`) also apply.

## Example output

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
| api-discovery:
|   paths_checked: 27
|   findings:
|     /openapi.json:
|       type: OpenAPI specification
|       status: 200
|       version: 3.0.1
|       title: Pet Store API
|       paths_total: 14
|       endpoints:
|         GET /pets
|         GET,POST /users
|       auth_schemes:
|         bearerAuth (http)
|     /graphql:
|       type: GraphQL endpoint
|       status: 200
|       introspection: enabled
|_      query_type: Query
```

If nothing is found, the script prints no output for that port.

## Customizing

- **Add default paths:** edit the `CANDIDATES` table near the top of the script. Each entry has a `path` and a `kind` (`spec`, `ui`, `graphql` or `generic`; `generic` entries can also carry a `note`).
- **Add UI signatures:** edit `UI_SIGNATURES` (lowercase text found in the page body, plus a display name).
- **Duplicate specs:** if several paths return identical content, later ones show `duplicate_of` pointing to the first.

## Limitations

- Only paths in the built-in list or in `api-discovery.paths` are checked; it does not crawl or fuzz.
- YAML specs are detected but not parsed.
- Redirects are not followed, so a docs page that redirects to a login will not be reported.
- Servers that return different bodies for every unknown URL can still produce noise on the generic API-root checks.
- Introspection results only show the query type name, not the full schema.

## Author and license

Author: [2Fac3R](https://github.com/2Fac3R)
License: same as Nmap, see <https://nmap.org/book/man-legal.html>.
