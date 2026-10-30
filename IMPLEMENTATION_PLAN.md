## Stage 1: Site view shell + tab routes (server-rendered)
**Goal**: `/sites/{id}/<tab>` pages (dns, ssl, scan, backups, mail, snippets, runtime, gate, routes, countries) sharing a tab rail with Settings. `/sites/{id}` keeps the full editor (compat for MCP, e2e, bookmarks) plus the rail. Existing per-site actions (dns resync/takeover, scans, backup saves, gate grants/test, delete) accept a `back` field so they land on the calling tab.
**Success Criteria**: every tab renders 200 for a real site with its facts; unknown tab 404s; unknown site 404s; back-field changes redirect targets only.
**Tests**: TestSiteTabsRender (all 10 tabs, markers per tab), TestSiteTabRailLinks (settings page + each tab), TestSiteTabUnknownAndMissingSite, TestBackRedirectOfActions (dns resync + gate grant + backup site save).
**Status**: Complete

## Stage 2: Scoped saves, gate family + form split
**Goal**: gate (mode + mail block) and access (allowlist, basic auth) save from their tabs via `POST /sites/{id}/gate` and `/sites/{id}/access`; those fields move out of the big editor; readSiteForm stops clearing what its form no longer carries; grants/test answer in place or redirect to the gate tab.
**Success Criteria**: PUT with absent moved sections preserves stored values; each scoped save validates like the editor, audits, and re-renders Caddy.
**Tests**: TestPutPreservesAccessSections, TestGateScopedSave, TestAccessScopedSave, TestMailScopedSave; editor/gatemail/controls unit tests updated to the tabs.
**Status**: Complete

## Stage 3: Scoped saves, content family
**Goal**: snippets (`POST /sites/{id}/snippets`), routes+tuning (`/routes`, incl. tls_skip_verify/stream/max_body), countries (`/geo`), DNS record-IP overrides (`/dns-ip`); fields move out of the editor; snippets sentinel so a zero-checked save clears rather than preserves.
**Success Criteria**: same rules as Stage 2 per endpoint; the editor form is Basics + notes + save on edit.
**Tests**: TestSnippetsScopedSave, TestRoutesScopedSave, TestGeoScopedSave, TestDNSIpScopedSave; MCP snippets detach via the empty sentinel.
**Status**: Complete

## Stage 4: Runtime actions + dashboard status chip
**Goal**: Runtime tab start/stop/restart (`POST /sites/{id}/runtime/<do>` through the helper, audited, disabled-state kept consistent); dashboard site rows gain a backup-age chip (per-site from LastRuns).
**Success Criteria**: unit state pill flips after actions in helper-fake tests; dashboard shows backup age when backups are on.
**Tests**: TestRuntimeTabActsOnTheUnit, TestDashboardRowCarriesBackupAge.
**Status**: Complete

## Stage 5: Docs, help hints, full gate
**Goal**: help.go hints for every new control; docs/sites.md + llms.txt describe the site view; `make check` green; fast-forward main.
**Success Criteria**: hint tests pass; no doc drift; the gate passes on bee.
**Tests**: TestEveryHintIsPlainNonEmptyText, TestHelpTextIsNotContainerSpecific + full gate.
**Status**: In Progress