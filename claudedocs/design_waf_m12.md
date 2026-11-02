# Design: WAF M12 — preset profiles, events, rules browser, category boxes, rate limit

Requirements settled 2026-11-02 with Brian (six AskUserQuestion answers, this session). Companions recorded in ROADMAP M12 and memory `todo-waf-preset-profiles`.

## Decisions (Brian's, this session)

1. **Scope**: preset profiles + events + rules browser + category exclusion boxes + rate limiting, all in M12.
2. **Profiles (5)**: `php` (generic PHP/MySQL), `wordpress` (PHP + the WP-standard exclusions), `shop` (ecommerce PHP: checkout/address FP exclusions), `goapi` (clean PL1), `node` (JSON bodies; 920/921 tuned). Plus the existing `crs` (raw preset) and `custom` (preset + hand-written tail).
3. **Click on an event row = both buttons**: *disable rule* (rows-level `SecRuleRemoveById`) and *narrow rule* (`SecRuleUpdateTargetById <id> "<!TARGET>"` chosen per prompt). Hand-written tails stay available.
4. **Events**: one row per matched rule with the verdict (deny / detect-only); capped ~10k like the audit log; per-site list + per-rule aggregates drive the tuning loop.
5. **Rate limiting**: per-IP fixed window, N requests/window, optional path scoping (one path per line), in-memory, like caddy-waf's model.
6. **CRS updates**: every release bumps the pinned CRS (no Settings pin, no LTS default); release notes call it out.
7. **Engine mode per site** (Brian's flag, same day, after mock review): every preset/profile/`custom`
   site picks the engine mode from the Ruleset section — **Detection only** (default) or **Blocking**.
   A new `sites.waf_mode` (`''` = detect, `detect`, `block`) is the single owner of the
   `SecRuleEngine` line: the renderer emits exactly one `SecRuleEngine` directive, last in the
   composed tail, so the profile and the admin tail can never fight over it. `wafval` drops
   `SecRuleEngine` from the allowed set: a tail containing it errors with "the engine mode is the
   Ruleset setting, not a directive". Verdict labels on event rows follow the mode.

Architecture decisions below are mine (Claude), listed so they can be argued.

## Architecture: own the module wrapper (swap `coraza-caddy` out)

The events flow needs the Coraza engine's violation callback; only an owned
`coraza.WAF` build can route it to the panel. coraza-caddy v2.6.2 is a thin wrapper
(3.7k LOC Apache-2.0: config, interceptor, logger). Plan: **`internal/caddywaf` grows
the handler implementation itself** (copy the interceptor/http glue essence — same
Apache license, NOTICE already credits), registers **the same module id
`http.handlers.waf` and the same JSON shape** (`directives`, `load_owasp_crs`), and
coraza-caddy leaves go.mod (keep `coraza/v3` + the CRS modules direct).

Why keep the id and shape: bee has deployed sites whose `sites.waf` values render the
`waf` handler today. A same-id, same-JSON reimplementation means **no config or DB
churn** — Caddy constructs the Servanago module instead of coraza-caddy's. What the
owned build adds: `WithErrorCallback` → event channel, plus whatever M12 needs (event
ids in responses). Risks: interceptor fidelity (websocket + flush + streaming) — the
coraza-caddy tests port wholesale as the coverage baseline; go-ftw conformance stays in
upstream, not ours.

**Schema check conflict**: `sites.waf` carries a CHECK `IN ('', 'crs', 'custom')` from
migration 010. Profiles need more values. SQLite can't alter a CHECK: migration `011`
rebuilds `sites` without that one CHECK (keep `country_mode`'s), validating presets in
the app layer (`wafval`/`caddywaf`) instead.

## Data model — migration `011_waf_events.sql`

The migration rebuilds `sites` once (SQLite cannot alter a CHECK): it drops the
`sites.waf` value-set CHECK (profiles need more values; the app layer validates now) and
adds the engine/rate-limit columns:

```sql
ALTER TABLE sites ADD COLUMN waf_mode   TEXT    NOT NULL DEFAULT '' CHECK (waf_mode IN ('', 'detect', 'block'));
ALTER TABLE sites ADD COLUMN rl_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN rl_window   TEXT    NOT NULL DEFAULT '';          -- '' | "1m" | "5m" | "1h"
ALTER TABLE sites ADD COLUMN rl_paths    TEXT    NOT NULL DEFAULT '';          -- one path per line; '' = all

CREATE TABLE waf_exclusions (
  site_id   INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL CHECK (kind IN ('remove', 'narrow')),
  rule_id   TEXT NOT NULL,                                   -- CRS id as text (942100)
  target    TEXT NOT NULL DEFAULT '',                        -- only for narrow: "!ARGS:checkout"
  note      TEXT NOT NULL DEFAULT '',                        -- why (the event's one-line reason)
  added_by  TEXT NOT NULL, added_at INTEGER NOT NULL,
  PRIMARY KEY (site_id, kind, rule_id, target)
);
CREATE TABLE waf_events (
  id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  rule_id TEXT NOT NULL, message TEXT NOT NULL, phase INTEGER NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('deny', 'detect')),
  host TEXT NOT NULL, path TEXT NOT NULL, client TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT ''
);
-- capped at 10k by the writer (delete oldest beyond), indexed per site for the tab:
CREATE INDEX waf_events_site ON waf_events(site_id, ts DESC);
CREATE INDEX waf_events_rule ON waf_events(site_id, rule_id);
```

Renderer: the composed tail is preset → profile exclusions (or the admin's
`waf_directives`) → exclusion rows → **the one `SecRuleEngine` line from `waf_mode` last** —
`SecRuleRemoveById <id>` per remove-row, `SecRuleUpdateTargetById <id> "<target>"` per
narrow-row; profiles resolve to a code-constant directives tail (`internal/caddywaf/profiles.go`),
not stored text, so a CRS bump can retune profiles per release. The shipped `Preset` drops
its `SecRuleEngine DetectionOnly` line (mode is owned and appended last), so the composed
tail carries exactly one `SecRuleEngine` directive; a pre-M12 stored tail that still names
one is simply overridden by the mode line (SecLang's last-wins), and the next save of that
tail moves it out of storage entirely (`SecRuleEngine` leaves the allowed set). `sites.waf`
values: `''`, `crs`, `custom`, `php`, `wordpress`, `shop`, `goapi`, `node`.

Events writer: the engine's callback fires per matched rule; the module pushes
`WafEvent` structs onto a buffered channel; one background goroutine in the same
process writes batches to `waf_events` (drop-on-full: tuning data, never block the
request path) and trims past 10k. Startup reads nothing from it (data is a log, not
desired state). Aggregate query: `rule_id, count(*), max(ts)` grouped — the list view's
"Pinned rules" table.

## UI (WAF tab gets three sections; routes stay unchanged)

- **Ruleset** (exists): presets select gains the five profile options and keeps
  custom; profile = preset + generated tail (read-only textarea showing what ships,
  no editing — switch to `custom` to edit). An **Engine mode** select sits under it:
  *Log only (detection)* (default) and *Block*, owned by `waf_mode`; the state chip
  and the events' verdicts follow it.
- **Exclusions**: add/remove rows (like gate grants): from events (buttons) or by id
  on the form (`kind`, `rule_id`, `target`, note). List shows added-by/at. A profile
  preset's own exclusions are part of the profile, NOT excluded rows — the rows list
  only what the admin chose.
- **Events**: newest-first list (rule id + message, path, verdict badge, time,
  "disable"/"narrow" buttons per row), plus the per-rule aggregate above it. Rate
  limit fieldset at the bottom of the tab (requests, window select, paths textarea).
- **Rules browser**: read-only page at `/sites/{id}/waf/rules` (tab sub-page):
  CRS files with their rule ids, messages, tags; server-side parse of the embedded FS
  once at startup, cached in memory. Category boxes row (per `crs/`-tag checkbox →
  a `remove` exclusion row per tag) sits inside the exclusions section.

## Rate limiter: `internal/caddywaf/ratelimit.go` (in-module)

Fixed window per (client IP [, path-key]), bounded key table (1M like caddy-waf),
cleanup goroutine owned by the module, `429` on limit. Client IP: Caddy's
`client_ip` var (same trust model as the geo handler). Rendered only when
`rl_requests > 0`; per-path keys only match the admin's path list. One in-process
counter set (Caddy is one process) — no cross-server state, no unit, no helper.

## MCP

- `waf` gains the profile values in the schema text; `waf_mode` (`detect` | `block`;
  `""` = detect) rides beside it on `create_site`/`update_site` and in `get_site`,
  which additionally returns `rl_requests` / `rl_window` / `rl_paths`.
- Exclusions/events get NO new tools now (avoid tool-regex churn; UI-first like
  the country rule was). If wanted later, follow the scan-tools pattern.
- `formOf` overlays: `rl_*` join like any field; `waf_exclusions` NOT in formOf —
  rows keep the snippets lesson: absent form fields must not clear rows.

## Spike (Stage 0, before anything)

1. `SecRuleRemoveById` on a retired CRS id: engine accepts or rejects? (Known:
   `SecRuleUpdateTargetById` on a missing id **rejects** — "rule not found".) Outcomes:
   rejects → exclusions of retired ids must be pruned by the CRS bump path (reconcile
   pass listing current CRS ids per release); accepts → rows go silent, UI greys them
   out against the current ruleset.
2. Port the coraza-caddy tests: engine builds with CRS inside the Servanago module
   and a request pipeline matches coraza-caddy's behavior (streaming, hijack, flush).

## Slices (build plan)

0. Spike + module swap (owned `internal/caddywaf` handler, coraza-caddy out of go.mod,
   integration tests port). Gate: real-Caddy test with CRS passing as today.
1. Rate limiter (fields in `wafval`-adjacent validator + renderer + store cols + UI
   fieldset + MCP fields). Independent of events.
2. Events: migration, module callback → writer, capped store, WAF-tab events section.
3. Exclusions: rows table + rows UI on WAF tab + renderer appends + undo. Category
   boxes = tag-kind rows.
4. Profiles: `profiles.go` presets + form options + docs.
5. Rules browser read page.
6. Docs set + full gate.

Not in M12: per-rule WAF metrics endpoint, custom block pages, cross-server WAF state,
event/exclusion MCP tools, CRS plugins bundle (bot detection), host-managed rule files.