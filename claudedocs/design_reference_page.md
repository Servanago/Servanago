# Design: Reference page (`/reference`), one-pass implementation

Requirements: see the brainstorm (cards/list, filters, sorts, notes, MCP notes). This file is the build plan.
Everything reuses existing paths; new code is one migration, one handler, one template, one static JS file, one pure function.

## 1. Data (migration `003_site_notes.sql`)

```sql
ALTER TABLE sites ADD COLUMN notes TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 10000);
ALTER TABLE sites ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
UPDATE sites SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now');
```

- `ALTER ... ADD COLUMN ... CHECK` is valid in SQLite when the default satisfies it (it does).
- Bump `user_version` in `TestMigrationsIdempotent` (currently 2 -> 3). Back up the v1 DB before deploying (`servanago.db.pre-0.6.0`).
- `store.Site` gets `Notes string`, `UpdatedAt string` (RFC3339 UTC; sorts as text).
- `siteCols`/`scanSite`: append `notes, updated_at`.
- `CreateSite`: insert `notes` and `updated_at = now` (Go `time.Now().UTC().Format(time.RFC3339)`; tests can pass a fixed clock if the store has one, otherwise assert "non-empty").
- `UpdateSite`: `notes=?, updated_at=?` in the same UPDATE. `set_site_enabled` goes through `UpdateSite`, so enable/disable bumps it too (intended).
- Do not add a separate notes-only store method: every write goes through the apply path anyway.

## 2. Edit form and MCP

- `readSiteForm` (`web/siteform.go`): `notes` = `strings.ReplaceAll(strings.TrimSpace(v.Get("notes")), "\r\n", "\n")`; reject `utf8.RuneCountInString > 10000` with `fail`-style error "notes: at most 10,000 characters". The DB CHECK counts characters too, so the two agree.
- `updateSite` handler: `readSiteForm` already feeds `UpdateSite`; keep `UpdatedAt` out of the form.
- `siteedit.html`: a `<textarea name="notes" maxlength="10000" rows="5">` in the existing Advanced `<details>` (add a hint in `help.go`: `help_test.go` fails on undefined hints).
- `formOf` (`web/mcp.go`): `v.Set("notes", cur.Notes)`. This is the line that stops an MCP `update_site` clearing notes.
- `siteArgs`/`overlay`: add `Notes *string` (pointer so "" can clear and omitted keeps), `if a.Notes != nil { v.Set("notes", *a.Notes) }`. No new MCP tool: `update_site {id, notes}` already changes only what is passed, and audits as "mcp token".
- `siteView`/`viewOf`: add `Notes string \`json:"notes,omitempty"\``, `UpdatedAt string \`json:"updated_at"\`` so `get_site`/`list_sites` read them.

## 3. Handler `GET /reference` (new `web/reference.go`)

Route: `mux.Handle("GET /reference", s.protected(s.referencePage))` next to `/snippets`. Nav: add `<li><a href="/reference">Reference</a></li>` after Dashboard in `layout.html`.

```
referencePage:
  rows  := s.siteRows(r)                       // existing: DNS, upstream probe, cert, in parallel
  units := unit panels for runtime rows         // probe.Parallel, 3s ctx each (see below)
  for each row -> refView{siteRow, Unit *unitPanel, RootErr string, Health string, Issues []string, Updated}
  render "reference"
```

- Reuse `siteRows` -> `buildRows` as is. It does not cover unit state or folder readability, so the page adds exactly those two:
  - Unit: `s.unitPanelFor(r, rt)` returns the state plus 30 journal lines per site. Too heavy for N sites. Add a small sibling `unitState(ctx, rt) (state string, err error)` that only calls `helper.ActionUnitStatus`, and have `unitPanelFor` keep its own code (do not refactor it). Run it inside `probe.Parallel` with a 3 s timeout. A dead helper socket fails fast.
  - Folder: `config.StaticRootReadable(rt.WebRoot())` for `Kind != "proxy"` and not (static with SiteUser), exactly the condition in `siteEditPage` (`siteform.go:707`). Cheap and local.
- If every runtime unit call failed, set `HelperDown` and show one banner "Status unavailable: the helper is not answering". Those sites still get Health "issue" (user's decision: unknown counts), reason "status unavailable".

### Health (pure function, table-tested)

```go
// healthOf: "disabled" | "issue" | "ok"; issues names each reason.
func healthOf(r siteRow, unit string, unitErr error, rootErr error) (string, []string)
```
Rules, in order:
1. `!r.Enabled` -> `disabled`, no issues.
2. Issues: `r.Upstream == "down"`; `r.Cert.State` is error or expired (look at the `probe.State*` constants; pending is not an issue); `r.DNSState()` is `error` or `conflict`; `rootErr != nil`; runtime kind and `unitErr != nil` -> "status unavailable"; runtime kind and unit state not `active (running)` or socket-active for cgi -> "unit <state>".
3. `len(issues) > 0` -> `issue`, else `ok`.

Test it with a table: one row per rule plus a disabled site with a down upstream (stays `disabled`). Assert the reason string (`want` substring), not just the verdict.

## 4. Template `templates/reference.html`

One DOM; the view is a CSS class, so cards and list never disagree.

```
<section id="ref" class="view-cards">           // JS sets view-list
  controls: search input, selects (kind, status, user, php), "issues only" checkbox, sort select, view radio, count, clear
  <nav class="az"> links to #slug for every site </nav>
  {{range .Rows}}
  <article id="{{.Slug}}" class="site {{.Health}}" data-name data-kind data-health data-user data-php data-updated data-text>
    <header>  <a href="/sites/{{.ID}}">{{.Host}}</a> kind badge, health badge, target, user, php, dns   </header>
    <div class="detail"> full config dl, status, issues list, snippets, DNS rows, <pre class="notes">{{.Notes}}</pre> </div>
  </article>
  {{end}}
</section>
```

- `data-text` = lowercase "hostnames slug kind" for the search; all values go through `html/template` attribute escaping.
- Notes: `<pre class="notes">` with `white-space: pre-wrap` in `servanago.css`, clamped to about 6 lines in cards (`max-height` plus `<details>` "Show all" only if over 600 characters, decided in Go, no JS).
- Cards: `.detail` always visible. List: `.view-list article` is a grid row (name, kind, health, target, user, PHP, DNS columns); `.detail` hidden until the article has `[data-open]`, toggled by clicking the header (not the edit link). It is a CSS grid with `role="table"` / `row` / `cell`, not a real `<table>`, because rows must expand. That is the one deviation from "compact table".
- Disabled sites: `.site.disabled { opacity: .6 }` and a "Disabled" badge. Do not use opacity alone for state (text badge present).
- `{{with .Rows}}` skips the whole block on an empty slice; bind `{{$rows := .Rows}}` and render an empty-state message.
- No JS: all articles visible, A-Z (server order), cards.

## 5. `static/reference.js` (about 60 lines, plain, no build)

- On load read `location.search` (`q, kind, status, issue, user, php, sort, view`), validate against whitelists (unknown -> default), apply, and write back with `history.replaceState` on every change.
- Filter: toggle `article.hidden` from `data-*` (AND of all). `issue` = `data-health` is `issue`. Count text "N of M sites".
- Sort: reorder the articles with `appendChild` by `name | kind,name | health (issue first),name | updated desc`. `data-updated` is the RFC3339 string, so string compare works.
- View: set `#ref` class `view-cards`/`view-list`.
- Never put a query value into `innerHTML`; only into `input.value`/`select.value` after whitelist check.
- Load it like `auth.js`: `<script src="/static/reference.js" defer>`.

## 6. Tests (failing first)

| Layer | Test |
|---|---|
| store | migration 003 applies on a copy of a v2 DB; `user_version` 3; notes over 10,000 rejected by CHECK; `UpdateSite` changes `updated_at`, an untouched site keeps its value |
| web | `/reference` signed out -> login redirect; 3 sites of different kinds -> 3 articles with `href="/sites/{id}"`; basic-auth hash never in body; `<script>` in notes is escaped; 10,001-char note rejected from the form; disabled site is present and labelled; helper down -> 200 plus banner; `?sort=bogus&kind=<script>` still 200 and the string never appears unescaped |
| web | `healthOf` table test (see 3), with a mutation check (`if false &&`) on the unknown-counts-as-issue rule |
| mcp | `update_site {id, notes}` sets notes and audits; `update_site` without notes keeps them (extend the `TestMCPSnippets` pattern); `get_site` returns notes |
| e2e | `e2e/tests/reference.spec.ts`: filter by kind, issues-only, sort, switch to list and reload (`?view=list` restored), expand a row. Unique hostnames under `*.static.example.test`; scope locators to the card |

## 7. Order of work (one pass, each step green before the next)

1. Migration + store fields + `TestMigrationsIdempotent` bump + store tests.
2. Form field, `formOf`, `overlay`, `siteView` + web/MCP tests.
3. `healthOf` + `unitState` + test.
4. `referencePage`, route, nav, template, CSS + web tests.
5. `reference.js` + Playwright spec.
6. `make check` (see CLAUDE.md for the env flags), then help text, ROADMAP line, version bump at release time only.

## 8. Risks and decisions

- Unit-state calls make the page as slow as the slowest helper call (3 s cap, run in parallel). If this proves slow on v1, cache the result for a few seconds; do not build the cache now.
- Unknown counts as an issue, so a stopped helper flags every supervised site. The banner names the single cause.
- `updated_at` for existing sites is the migration time; "Recently changed" is only meaningful after the next save of each site. State this in the page hint.
- Saving a site from the edit form (or an MCP notes change) goes through the normal apply path, so a notes edit reloads Caddy and re-applies the runtime unit. Accepted; a notes-only fast path would be a second write path to keep correct.
- Pure CSS view switching means the list "table" is a grid; if a real `<table>` is required later, the expandable row has to become a second `<tr>`.
