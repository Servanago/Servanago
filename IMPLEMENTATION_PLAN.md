# Coraza WAF integration (branch `coraza-waf`)

Embed `coraza-caddy` (`http.handlers.waf`, Apache-2.0) per site: OWASP CRS v4 preset
via `load_owasp_crs`, optional per-site admin SecLang directives. Ships as
`SecRuleEngine DetectionOnly` so enabling a site never blocks anything until the
admin flips it. `caddygeoip` stays (Coraza's @geoLookup is a stub).

Rendered handler JSON:

    {"handler":"waf","load_owasp_crs":true,"directives":"SecRuleEngine DetectionOnly\n..."}

## Stage 1: Store — migration + Site fields
**Goal**: `010_waf.sql` adds `sites.waf` (CHECK '', 'crs', 'custom') and
`sites.waf_directives`; `Site.Waf`/`Site.WafDirectives` wired through siteCols,
scanSite, CreateSite, UpdateSite.
**Success Criteria**: new store tests read/write the fields; migrations stay
idempotent; user_version 10.
**Tests**: store round-trip (create/update reflect fields), `TestMigrationsIdempotent` bumped.
**Status**: In Progress

## Stage 2: Renderer — `waf` handler in caddycfg
**Goal**: `internal/caddywaf` package (imports the coraza-caddy module for
registration; preset/`Options.Waf` helpers). caddycfg renders the `waf` handler
after geo/gate, before the upstream, when `Site.Waf != ""`. `Options.Waf`,
`Options.WafDirectives`.
**Success Criteria**: golden JSON shows the handler; integration test against real
Caddy: enabled site with CRS in DetectionOnly answers normally and logs the
violations; disabled sites render unchanged. All golden/positional test literals
updated.
**Tests**: `render_test.go` goldens, `render_integration_test.go` (real Caddy, CRS compile).
**Status**: Not Started

## Stage 3: Validator — directives allowlist + compile check
**Goal**: per-site custom SecLang tails are validated before they reach SQLite/Caddy:
`coraza.NewWAF` compile + allowlist scan rejecting directives and operators that touch
host state (Include of paths, file-based operators, SecAuditLog* writers, SecDataDir).
**Success Criteria**: rejects bad/ban-listed directives with "why"; accepts CRS-safe
tuning (`SecRuleRemoveById`, `SecRuleEngine On`...).
**Tests**: table tests with `want` substrings; guard mutated red once.
**Status**: Not Started

## Stage 4: Site form + MCP
**Goal**: siteedit fieldset (preset select + directives textarea), `parseSiteForm`
fills/validates; `formOf` gains `waf`/`waf_directives` so MCP sees them
(snippets lesson); MCP get_site shows them.
**Success Criteria**: form round-trips, MCP update preserves both fields, hint text plain.
**Tests**: web table tests, MCP test per `TestMCPSnippets` pattern, hint test green.
**Status**: Not Started

## Stage 5: Docs + gate
**Goal**: docs/sites.md, docs/mcp.md, llms.txt, README feature line, ROADMAP M10 line,
SKILL.md "since 0.21.0"; NOTICE for Apache deps; full `make check` green; delete this file.
**Status**: Not Started