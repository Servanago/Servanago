# Design: named Caddy snippets per site (one-pass implementation)

Requirements settled in the brainstorm: admin-defined Caddyfile snippets, allowlisted directives, attached per site, run
after the access chain and before the site handler, `/.well-known/*` bypasses them, new Snippets page, no seeds, MCP
tools, `servanago import` reads snippets. `dotfile404` is unchanged.

## 1. Data (first real migration)

`internal/store/migrations/002_snippets.sql` (the runner already applies `NNN_` files once via `PRAGMA user_version`):

```sql
CREATE TABLE snippets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE CHECK (name GLOB '[a-z]*' AND length(name) BETWEEN 2 AND 40),
  body       TEXT NOT NULL,                 -- Caddyfile directives, as the admin wrote them
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE site_snippets (
  site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  snippet_id INTEGER NOT NULL REFERENCES snippets(id) ON DELETE RESTRICT,
  pos        INTEGER NOT NULL,
  PRIMARY KEY (site_id, snippet_id)
);
```

Live v1 DB migrates on start; take the usual `servanago.db.pre-<ver>` copy before the upgrade. Tell the user this is the
first `002`. Fresh installs get both files, so e2e/unit DBs need no change.

Store (`internal/store`, new `snippets.go`; mirror `hostnames`/`setHostnames`):
- `type Snippet struct{ ID int64; Name, Body string }`
- `ListSnippets`, `GetSnippetByName`, `CreateSnippet`, `UpdateSnippet(id, body)`, `DeleteSnippet(id)`.
- `Site.Snippets []string` (names in attach order). `ListSites`/`GetSite` fill it from one extra query keyed by site id;
  `CreateSite`/`UpdateSite` call `setSnippets(ctx, siteID, names)` inside the existing tx (delete + insert with `pos`).
- `SnippetUsers(ctx, id) []string` (primary hostnames) for the delete refusal.

## 2. Adapter and validation: `internal/caddycfg/snippet.go`

One function used by render, the web save path, MCP and import:

`AdaptSnippet(body string) ([]any, error)` returns the route list to splice.

Steps:
1. **Tokenize** with `caddyfile.Tokenize` (package `caddyconfig/caddyfile`). Reject, naming the token: the `import`
   directive, any token containing `{$`, `{%`, `{env.` or `{file.` (parse-time file/env reads), and unbalanced braces
   (depth below zero or non-zero at the end), so a body cannot close the wrapper and open its own site block. Cap body
   length (16 KiB) and line count.
2. **Wrap** as `:80 {\n<body>\n}` and run the registered `caddyfile` adapter (`caddyconfig.GetAdapter("caddyfile")`;
   `modules/standard` already links it). `:80` carries no host matcher. Adapter warnings are errors.
3. **Extract** exactly one server from `apps.http.servers`, no other app, no `listen` surprises; take its `routes`.
4. **Allowlist on the JSON**, recursive over every `handle` entry including `subroute`: allowed handlers are
   `static_response` (respond, redir), `error`, `headers` (header, request_header), `encode`, `request_body`,
   `subroute`, `vars`. Anything else fails with `directive X is not allowed in a snippet`. Checking the adapted handler
   names rather than text is what makes `handle`, `reverse_proxy`, `file_server`, `root`, `basic_auth`, `forward_auth`,
   `php_fastcgi`, `tls`, `redir`-less bypasses impossible. Matchers are unrestricted (they only select).
5. Return the routes, JSON-decoded, ready to embed.

Determinism: no network, no filesystem after step 1's rejections. Output is stable for the golden tests.

Name rule: `config.ValidateSnippetName`, `^[a-z][a-z0-9_-]{1,39}$` (slugs forbid `_`, so not reused).

## 3. Render (`internal/caddycfg/render.go`)

- `Render` adapts each used snippet once into `map[string][]any` (name to routes); `State` gains `Snippets []store.Snippet`
  (`apply.render` lists them next to domains and sites). An adapt error returns from `Render`, so `Mutate` rolls back and
  startup falls to last-known-good/bootstrap as for any bad row.
- `siteHandler(host, r, snippetRoutes)`. When the site has snippets, after the gate, allowlist and basic auth entries and
  before `m{"handle": handlers}`, append one route:

```go
m{"match": []any{m{"not": []any{m{"path": []any{"/.well-known/*"}}}}},
  "handle": []any{m{"handler": "subroute", "routes": snippetRoutes}}}
```

  `snippetRoutes` is the concatenation of the site's snippets in `pos` order. A terminal snippet route (the 404) ends
  the request; an unmatched one falls through the nested list to the outer chain; `encode` wraps what follows. The
  early return `len(handlers)==1 && no gate/allowlist/basic` must also require no snippets.
- Result: `/.well-known/*` never sees snippets (so it is also not compressed), everything else does.

## 4. Web UI

- `internal/web/snippets.go` + `templates/snippets.html`, nav link "Snippets" in `layout.html`, add `"snippets"` to the
  template list in `web.go:87`, routes beside the domains ones:
  `GET /snippets`, `POST /snippets`, `PUT /snippets/{id}`, `DELETE /snippets/{id}`, all `s.protected`.
- Handlers follow `domains.go`: validate (`ValidateSnippetName`, `AdaptSnippet`) then `Apply.Mutate` so Caddy's own
  rejection rolls back; `failErr`/`userError`; `s.audit(r, "snippet.created|updated|deleted", name)`; 204 +
  `HX-Redirect`. Re-auth on save and delete, like other sensitive actions.
- Delete of an attached snippet: `userError{409, "Used by: a.example.com, ... Detach it first."}` from `SnippetUsers`.
- Page text: allowed directives list, and the fixed note "`/.well-known/*` always bypasses snippets". Hints in
  `help.go` (`help_test.go` fails on undefined hints; no word "docker").
- Site form (`siteedit.html` near `extra_routes`): a checkbox list `snippets` (all snippets by name; order = tick order
  is not kept, so attach order is alphabetical by name; document this). `siteform.go` reads `v["snippets"]`, requires
  each to exist, sets `Site.Snippets`; add `base.Snippets = in.Snippets` to the overlay block at `siteform.go:392`.
- **`formOf` (`mcp.go:124`) must set `v["snippets"] = cur.Snippets`**, or MCP `update_site` clears them.

Ordering decision: attach order is alphabetical, not user-chosen. Simplest and deterministic; `pos` column stays only
so a later explicit order needs no migration. (If you want drag/ordered attach, say so; it adds UI, not schema.)

## 5. MCP (`internal/web/mcp.go`)

`list_snippets` (read-only, bodies included), `create_snippet{name,body}`, `update_snippet{name,body}`,
`delete_snippet{name}`, run through the same handlers via `mcpRun` and audited as the MCP actor. `siteArgs` gains
`Snippets []string` (`snippets`, "replace the site's attached snippets; omit to keep"); `overlay` sets `v["snippets"]`
only when non-nil.

## 6. Import (`internal/caddyfile` + `cmd/servanago/import.go`)

- Reader: at depth 0 a line `(name) {` starts a raw capture of lines until its matching `}` (existing brace-depth
  convention: a line ending `{` opens, a lone `}` closes); stored as `Snippet{Name, Body}`. At depth 1 inside a site
  block, `import NAME` appends to `Site.Imports`; `encode` keeps being ignored.
- `Parse` returns `(sites, snippets, skipped)`; update `import.go` and `import_test.go` call sites.
- Importer, before sites: for each snippet run `AdaptSnippet`; on failure print `skip snippet NAME: reason`; if the name
  exists with a different body print a conflict and do not overwrite; otherwise create it (not in dry run). For each
  site, attach the imported names that are usable; for an unusable one print `warn HOST: snippet NAME not attached`.
  Reruns stay safe (existing snippet with the same body is reused).

## 7. Tests (written first, per slice)

1. `caddycfg/snippet_test.go` table: your exact `block_sensitive` text adapts; `encode gzip zstd` adapts; rejections
   assert why: `reverse_proxy`, `file_server`, `root`, `basic_auth`, `import /etc/x`, `{file.x}`, `{env.X}`, `{$X}`,
   stray `}` / `:443 {` injection, oversize body. Mutate the allowlist guard once to see red.
2. Spike first: print the adapter's JSON for `block_sensitive` and `compress` and check the extraction assumptions
   (one server, route shape, `terminal` flag on the `respond` route). Adjust step 3 of section 2 to the real shape.
3. `render_test.go` goldens (`-update`): proxy site and static site with both snippets, a site with gate plus snippets
   (order gate, snippets, handler), a site with none (unchanged golden). Walk decoded JSON, never `strings.Index`.
4. `render_integration_test.go`: through in-process Caddy against an `httptest` upstream: `/composer.lock` and `/.env`
   return 404, `/index.html` reaches the upstream, `/.well-known/security.txt` reaches the upstream, `Accept-Encoding:
   zstd` returns `Content-Encoding: zstd`.
5. Store: migration applies on a v1-shaped DB; attach/detach; delete restricted; site delete cascades.
6. Web: CRUD with re-auth, rejected body leaves DB unchanged, delete refusal text, site-form attach, MCP
   `update_site` keeps snippets (guards the `formOf` omission), new MCP tools. Fresh `X-Forwarded-For` per sign-in.
7. Import: Caddyfile with your snippet plus `import block_sensitive` creates snippet and attachment; bad snippet reported.
8. e2e: Snippets page create, attach to a site, edit, delete refusal. Unique names per spec.

## 8. One-pass order

Branch off `main`, then: migration + store, `AdaptSnippet` spike and tests, render + goldens + integration, web page and
site form, `formOf` + MCP, import, help text/README/ROADMAP line, `make check` (single run, env flags from CLAUDE.md),
fast-forward `main`. Do not deploy; the v1 upgrade needs the `.pre-<ver>` DB copy and is a separate ask.

## 9. Risks

- Adapter output shape is assumed; the spike (test 2) is the first thing to run, and may change step 3 of section 2.
- `terminal` inside the nested subroute ends the whole request (intended for the 404); verified by the integration test.
- Regex cost is per request per matcher; negligible, but a pathological admin regex is admin-owned.
- Snippet edits reload every site that uses them; a Caddy rejection rolls the DB back (existing `Mutate` behaviour).
