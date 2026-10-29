# Design: Country (GeoIP) blocking

Requirements: `claudedocs/requirements_next_features.md` §1 (settled 2026-10-28): per-site rule + WebUI rule, deny or allow mode, MaxMind GeoLite2-Country, blocked answer 403.

**Changed on 2026-10-29 with Brian:** geoipupdate 6.1.0 (MaxMind's official updater, systemd timer enabled) runs on bee, and v1 installs it at deploy — ServanaGo builds **no downloader and stores no MaxMind credentials**. It reads a `.mmdb` path (`/var/lib/GeoIP/GeoLite2-Country.mmdb`, refreshed by geoipupdate's timer twice a week). Help text points admins at `apt install geoipupdate` + their GeoIP.conf.

## Data model — migration `007_geoip.sql`

```sql
ALTER TABLE sites ADD COLUMN country_mode TEXT NOT NULL DEFAULT '' CHECK (country_mode IN ('', 'deny', 'allow'));
ALTER TABLE sites ADD COLUMN countries TEXT NOT NULL DEFAULT '';            -- space/CSV of ISO-3166-1 alpha-2
ALTER TABLE settings ADD COLUMN geo_db TEXT NOT NULL DEFAULT '';            -- path to GeoLite2-Country.mmdb; empty = geo off
ALTER TABLE settings ADD COLUMN webui_mode TEXT NOT NULL DEFAULT '' CHECK (webui_mode IN ('', 'deny', 'allow'));
ALTER TABLE settings ADD COLUMN webui_countries TEXT NOT NULL DEFAULT '';
```

Validation: mode values from a select, codes `[A-Z]{2}` and non-empty when a mode is set (an empty list under a mode is a user error, not a policy).

## `internal/geoip`

```go
type DB struct{ ... }
func New() *DB
func (d *DB) Use(path string)                    // sets the file; the reader reopens on mtime change (stat per lookup, one syscall)
func (d *DB) Lookup(ip netip.Addr) (country string, err error)
func Blocked(mode, countries, country string) bool // pure: deny = country in list (unknown allowed); allow = country not in list (unknown blocked); no mode = never blocked
```

- Reader: `github.com/oschwald/geoip2-golang` (MIT). Private/loopback/CGNAT addresses return `""` (not in GeoLite2) — callers treat private+loopback as **bypass**: ServanaGo's geo rules are internet-facing; a home LAN, a tailnet and the panel's own local clients are never geo-blocked.
- The mmdb file is only opened when a lookup happens; a missing file = every lookup unknown (deny rules then still pass until the file appears — the settings banner says so).
- Live test (`TestLiveGeoIP`): runs against `/var/lib/GeoIP/GeoLite2-Country.mmdb` when present (bee, v1), skipped elsewhere; unit tests use the decision function + a stub `Lookup` (no mmdb file needed).

## Caddy module `servanago_geoip` (in-tree, like `servanago_gate`)

`internal/caddygeoip`: module `http.handlers.servanago_geoip`; JSON per site: `{mode, countries}` pinned at render time (same philosophy as the gate's config), reader shared globally:

```go
// Service installed app-side before caddy.Load; nil service = fail open (allow).
Install(&geoip.Service{DB: <the panel's geoip.DB>})
```

- `ServeHTTP`: bypass `/.well-known/*` (ACME, app well-knowns — Let's Encrypt validates from anywhere). Client IP: `r.RemoteAddr`; when the peer is inside Cloudflare's published ranges (records can be proxied through the DNS CRUD view) the **`CF-Connecting-IP`** header is the client — Cloudflare sets it itself so a visitor cannot spoof it; the ~22 published ranges sit in a fixed list (`ponytail:` refresh when Cloudflare announces new ranges).
- Lookup + `geoip.Blocked(mode, countries, country)`; blocked → 403 `static_response`-style body, once, plain text. Unknown country: deny = pass, allow = block. Errors (no db): pass, logged.
- The gate handler chain keeps its order relative to ALLOWED traffic: geo sits **first** in the subroute chain, before the gate — a blocked country never sees a gate form or a session. The `ml.` host's early-return branch becomes a two-handler subroute `[geo?, gate]` when the site has a geo rule.

## Render wiring (`internal/caddycfg`)

- `Options` gains nothing; the site's geo rule renders from the site row's own fields (`CountryMode`, `Countries`) inside `siteHandler`: prepend the geo route to `sub` (and the ml/gate branches) when set. The `len(handlers)==1` fast path must also consider geo.
- Golden JSON updated where a geo rule changes routes; route order asserts walk the decoded JSON (existing rule).

## Panel (WebUI) enforcement

- One middleware in `Server.Handler()` before the mux: `s.geoGuard(http.Handler)`. Loopback/direct-private remote = pass, `clientIP()` (the authn XFF logic) resolves the client when Caddy proxies.
- Mode/list from the settings row, cached like `cfErr` (atomic.Value set at start and by the settings save — no per-request settings query).
- /mcp inherits the guard (it is panel surface; loopback relays pass by the loopback rule).

## Site form + MCP

- Site edit page, Access area: a `details.feature` block "Country filter" (closed until used): mode select (Off / Deny these / Allow only these) + one text input of space/CSV codes. `parseGeo` in `siteform.go`, validator in `internal/config` (`ValidateCountryList`).
- `store.Site` gains `CountryMode`, `Countries`; `formOf` must include both (`update_site` fields), the site edit form posts them; `get_site` returns both. No new MCP tools — `update_site` carries it (regex untouched); skills note "since 0.14.0".

## Auditing

`settings.geoip` on save (what the smtp/scan saves do); site saves already audit. Blocked requests are not audited (a Caddy static_response at line rate; the Caddy access log holds them).

## Tests

- Pure decision table: mode × list × country, unknown handling (the guard test rule: every row asserts why).
- geoip.DB live test (skip when no mmdb) + Use/reopen-on-mtime test (touch a copy and assert a second lookup sees the swap — no sleeps: mtime from the swap itself).
- caddycfg golden + order asserts: geo route first, ml host wrapped, fast path handled.
- caddy integration (real Caddy): site with a deny rule, stubbed Service lookup → 403 for matches, pass for others; allowlist mode blocked for a missing country; `.well-known/acme-challenge/x` passes under a deny rule.
- Panel guard: middleware unit tests (XFF via loopback, direct private, settings cache).
- Site form + formOf/get_site round-trips (the MCP field-omission gotcha).

## Docs to update (repo rule)

`docs/sites.md` + `docs/mcp.md` (update_site fields), `llms.txt` (feature line + env notes), README bullet, ROADMAP M10 line for `update_site`, `skills/servanago-sites/SKILL.md` ("since 0.14.0"), help hints (`geo_db`, `webui_countries`, `country_mode`, `country_codes`) + a Help section.

## Stages

1. **Store + config**: `007_geoip.sql`, site/settings fields, `ValidateCountryList`, `parseGeo`, formOf/get_site, settings save route + tests. **Complete** (cb36ebe).
2. **geoip package**: DB + decision + live test + reopen test. **Complete** (same commit; `TestLiveGeoIP` and `TestGeoGuardBlocksPublicClients` run against bee's real mmdb).
3. **Caddy module + render**: caddygeoip, siteHandler branches, integration tests, goldens. **Complete** (de341a7: ServeHTTP hammered directly + `TestGeoRouteLoads` loads real Caddy).
4. **Panel guard + docs + gate**: middleware, settings fieldset + hints, docs, `make check`, ff main. **Complete** (626ef03, 25f664e). First gate run: exit=2 — the one failing e2e (dns.spec delete-dialog) passed alone and in the rerun (exit=0, 40 passed), the known full-run flake; not a slice cause.