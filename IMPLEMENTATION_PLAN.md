# M2: site model (static, proxy)

Decisions (settled in discussion):
- A hostname is a free FQDN validated by `internal/config`. Its domain is the longest-suffix match in `domains` and may be null (HTTP-01, no DNS sync).
- `domains` becomes optional Cloudflare context (`zone_id`, default IPs, `cert_mode`).
- A site has an immutable slug (`^[a-z][a-z0-9-]{1,31}$`), a kind (`static` | `proxy`) and one or more hostnames, one primary.
- Static root: an admin-supplied absolute path. `EvalSymlinks` must resolve it to an existing directory. Denied roots: `DATA_DIR`, `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/`. `/home` is allowed (existing `public_html` directories). Optional `SERVANAGO_STATIC_ROOTS` (colon-separated) restricts roots to those prefixes. Directory listing off; dotfiles not served.
- The servanago user needs execute on the home directory and read on the root. ServanaGo never changes permissions; the site page reports readable/not readable.
- M3 must not set `ProtectHome=yes` on the control-plane unit.
- The gate is keyed to the site id now; per-hostname keying stays in the late gate milestone.

## Stage 0: rename route -> site (mechanical)
**Goal**: `routes` table, `store.Route`, `RouteID`, handlers, templates and e2e names become `sites` / `Site` / `SiteID`; add `slug` and `kind` (`proxy` only). No behaviour change.
**Success Criteria**: `make check` green; no `route` identifier left except Caddy's own route concept.
**Tests**: existing suite, renamed; new store tests for slug validation and uniqueness.
**Status**: Rename Complete (scripted, user-approved exception). Slug and kind columns not started; they move to Stage 1.
Note: the `/sites/new` quick form stays; the full form is `/sites/new/full` and `POST /sites/full`, merged in Stage 4.

## Stage 1: hostnames first-class
**Goal**: `site_hostnames(site_id, hostname UNIQUE, is_primary)`; `domain_id` and `subdomain` leave `sites`; `store` resolves a hostname's domain by longest suffix; `config.ValidateHostname` accepts any multi-label FQDN.
**Success Criteria**: a site can have several hostnames; a hostname with no matching domain is valid; co.uk style names work.
**Tests**: store (suffix match, uniqueness, primary), config validator table (rejects `.local`, `.internal`, `.home.arpa`, IP literals).
**Status**: Complete. Also adds immutable `slug` (derived from the first hostname, unique) and `kind` (`proxy`). `config.ValidateDomain` already accepts any multi-label FQDN, so there is no separate `ValidateHostname`. The renderer, DNS sync, import and handlers read the primary hostname and resolve its domain by suffix; a hostname with no domain still errors in the renderer (Stage 2 lifts that) and is skipped by DNS sync. The full form still takes domain + subdomain and joins them (Stage 4 replaces that).

## Stage 2: renderer rewrite
**Goal**: `caddycfg.Render` takes sites and hostnames and dispatches on kind; one Caddy route per site matching all its hostnames; certificate policies per host when the domain is null or HTTP-01.
**Success Criteria**: proxy goldens unchanged in content; new goldens for multi-hostname and no-domain sites.
**Tests**: golden JSON, real-Caddy integration for HTTP-01 per host.
**Status**: Complete for hostnames and certificates. Deviation: one Caddy route per hostname (same handler chain), not one route matching all of them, because the gate handler pins the host it runs for. A hostname under no domain gets its own HTTP-01 policy even with Cloudflare on; names the wildcard cannot cover (apex, deeper labels) get their own certificate. Dispatch on kind arrives with Stage 3.

## Stage 3: static kind
**Goal**: `static` sites served by `file_server` from a validated root, sharing the allowlist, basic auth and gate chain.
**Success Criteria**: root validator enforces the rules above; listing off; unreadable root reported, not crashed on.
**Tests**: validator table plus fuzz (traversal, symlink escape, NUL), golden, integration against a temp directory including a 0750 parent.
**Status**: Complete at the config, store, renderer and dashboard-row level; the form and handlers that create a static site arrive in Stage 4. `kind` takes `proxy|static`; `static_root` and nullable upstream columns with a CHECK keeping the two shapes apart. `config.ValidateStaticRoot` resolves symlinks first, denies the trees above, and applies `SERVANAGO_STATIC_ROOTS`; `config.StaticRootReadable` is for the site page. Dotfiles are blocked by request path (`(^|/)\.` returns 404) rather than file_server's `hide`, which also matched a dot-directory in the root's own location. Static sites are never dialed by the upstream sweep.

## Stage 4: UI
**Goal**: site page with kind, hostnames add/remove/primary, static root field; domains editable (zone, IPs, cert mode); Add site accepts a free hostname. The site page also takes Caretakarr's edit-form redesign (commit `913c22d`): h1 naming the site with its cert/DNS/backend chips; fieldsets Address, Backend, "Who can open this site" (magic link + allowlist + basic auth), Advanced in a `<details>`; "Saved and applied" inline on edit (documented exception to 204 + `HX-Redirect`); rename notice about the old DNS record; shared `deletedlg.html` for dashboard rows and the edit page; hint ids with `aria-describedby`.
**Success Criteria**: single-label restriction and no-zone-lookup gap gone; help text defined for every new hint.
**Tests**: web handler tests, `help_test`, Playwright specs in both projects.
**Status**: Complete. One site form at `/sites/new` (create) and `/sites/{id}` (edit); `/sites/new/full`, `POST /sites/full` and the quick form are gone. Hostnames textarea (one per line, first is primary) replaces domain + subdomain; kind select shows the proxy fields or the folder; a hostname with no domain is served (Cloudflare "no zone" falls back to none, any other Cloudflare error still refuses). Edit page follows the Caretakarr redesign (`913c22d`): header with status chips, grouped fieldsets, Advanced `<details>`, hint ids with `aria-describedby`, rename notice, shared `deletedlg.html`, and save answers 200 "Saved and applied." in place (the one handler outside the 204 + `HX-Redirect` contract). Domains page edits zone, default IPs and certificate mode (`PUT /domains/{id}`). Fixed on the way: editing a gated site read the gate mode before the access controls set it, so saving an ACL site emptied its grants.

## Stage 5: DNS per hostname
**Goal**: `dns_records` keyed `(hostname, family)`; Cloudflare sync runs per hostname using its matching domain's zone and IPs; hostnames without a domain are skipped.
**Success Criteria**: adding or removing a hostname creates or removes its A/AAAA rows with the existing owned/adopt/conflict/take-over rules.
**Tests**: dnssync with the cftest fake, web DNS state tests, e2e in the `cloudflare` project.
**Status**: Not started
