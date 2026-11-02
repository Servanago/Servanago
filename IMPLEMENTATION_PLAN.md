# M12: preset profiles, events, exclusions, rules browser, rate limit

Design: `claudedocs/design_waf_m12.md` (settled 2026-11-02, Brian's six answers + engine-mode flag). UI truth: `docs/WAF-UI-MOCK.html`, `docs/RATELILMITING_UI_MOCK.html` — class-for-class, no deviation. Reference lookups go through context7 (coraza v3 API).

## Stage 0: Owned module (swap coraza-caddy out) + spike
**Goal**: `internal/caddywaf` implements `http.handlers.waf` itself (same id, same JSON: `directives`, `load_owasp_crs`); provisions `coraza.WAF` from the CRS-rootfs config, pools identical configs across reloads; port the interceptor and request glue; coraza-caddy leaves go.mod. Spike: `SecRuleRemoveById` on a retired CRS id — accepted or rejected (pins the CRS-bump rule).
**Success Criteria**: integration tests pass with real Caddy: CRS loads, traversal 403 when engine On, DetectionOnly serves, streaming/hijack behave; render tests unchanged.
**Tests**: module_test.go (provision, pool reuse, block, pass), render_integration_test.go (existing three WAF tests green without coraza-caddy import).
**Status**: In Progress

## Stage 1: Engine mode + rate limit (migration 011, all objects)
**Goal**: migration `011_waf_events.sql` once for the whole milestone (sites rebuild: `waf_mode`, `rl_requests/window/paths` + `waf_exclusions`, `waf_events` tables; drops the 010 CHECK). Preset drops its SecRuleEngine line; renderer composes it last from `waf_mode`. `wafval` drops SecRuleEngine from the allowed set. Rate limiter: fixed window per (client IP, optional path), bounded keys, 429, cleanup goroutine owned by the module. UI: WAF tab gains the engine-mode select and the rate-limit fieldset (mock class-for-class); MCP `waf_mode`/`rl_*` fields.
**Tests**: 011 idempotence + user_version 10; renderer goldens (mode line last, rl handler when set); wafval rejection table (SecRuleEngine ban); ratelimit unit tests (window expiry, path keys, bounded table); web tests for the two controls; MCP field round-trip.
**Status**: Complete

## Stage 2: Events
**Goal**: module callback → buffered channel → capped `waf_events` writer (trim past 10k, drop-on-full). WAF tab Events section: per-rule aggregates (rule, category, count, last seen, example path) + newest matches with Narrow/Disable buttons per mock.
**Tests**: writer caps and trims; callback captures rule id/message/phase/verdict; integration: a DetectionOnly match lands a detect row, engine On lands deny.
**Status**: Not Started

## Stage 3: Exclusions + category boxes
**Goal**: `waf_exclusions` rows (remove/narrow + target + note + added_by/at); renderer appends rows as directives; WAF-tab exclusions rows + add form + category checkbox set (per-tag remove rows); remove = undo, re-apply.
**Tests**: rows render per kind; narrow target validation (`!VAR:key` form); category tick → tag rows; undo re-renders; spike decision applied (retired-id handling).
**Status**: Not Started

## Stage 4: Profiles
**Goal**: `profiles.go` presets: `php`, `wordpress`, `shop`, `goapi`, `node` (each = preset + code-constant tail); Ruleset select gains them; shipped tail shown read-only; custom switch keeps editing; renderer validates profile names from the table, not the CHECK.
**Tests**: each profile compiles with CRS (wafval on Preset+profile tail); renderer goldens; MCP `waf` schema values.
**Status**: Not Started

## Stage 5: Rules browser
**Goal**: read-only parse of the embedded CRS FS at startup (rule file → ids, messages, pages per crs-tag): `/sites/{id}/waf/rules` list + per-file detail per mock.
**Tests**: parse counts match the module's files; page renders complete (save/`</table>` completeness lesson).
**Status**: Not Started

## Stage 6: Docs + gate
**Goal**: docs/sites.md WAF section, docs/mcp.md, llms.txt, README line, ROADMAP M12 → Done, SKILL.md since-version, NOTICE (already); full `make check`; delete this file.
**Status**: Not Started