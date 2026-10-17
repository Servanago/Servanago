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
**Status**: Not started

## Stage 2: renderer rewrite
**Goal**: `caddycfg.Render` takes sites and hostnames and dispatches on kind; one Caddy route per site matching all its hostnames; certificate policies per host when the domain is null or HTTP-01.
**Success Criteria**: proxy goldens unchanged in content; new goldens for multi-hostname and no-domain sites.
**Tests**: golden JSON, real-Caddy integration for HTTP-01 per host.
**Status**: Not started

## Stage 3: static kind
**Goal**: `static` sites served by `file_server` from a validated root, sharing the allowlist, basic auth and gate chain.
**Success Criteria**: root validator enforces the rules above; listing off; unreadable root reported, not crashed on.
**Tests**: validator table plus fuzz (traversal, symlink escape, NUL), golden, integration against a temp directory including a 0750 parent.
**Status**: Not started

## Stage 4: UI
**Goal**: site page with kind, hostnames add/remove/primary, static root field; domains editable (zone, IPs, cert mode); Add site accepts a free hostname.
**Success Criteria**: single-label restriction and no-zone-lookup gap gone; help text defined for every new hint.
**Tests**: web handler tests, `help_test`, Playwright specs in both projects.
**Status**: Not started

## Stage 5: DNS per hostname
**Goal**: `dns_records` keyed `(hostname, family)`; Cloudflare sync runs per hostname using its matching domain's zone and IPs; hostnames without a domain are skipped.
**Success Criteria**: adding or removing a hostname creates or removes its A/AAAA rows with the existing owned/adopt/conflict/take-over rules.
**Tests**: dnssync with the cftest fake, web DNS state tests, e2e in the `cloudflare` project.
**Status**: Not started
