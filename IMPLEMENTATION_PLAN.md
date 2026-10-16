# M1: decouple Cloudflare

Goal: ServanaGo works for any public hostname with no Cloudflare account. Cloudflare DNS-01 and A-record sync stay as an optional feature. Baseline for every stage: `go test -race`, lint and e2e (27 specs) green on `main` after M0.

Status of this plan: stages and criteria are a first cut; Stage 2 has an open design question (below) that must be answered before it starts.

## Stage 1: Cloudflare becomes optional
**Goal**: Start, serve and manage sites with `CLOUDFLARE_API_TOKEN` unset.
**Success Criteria**:
- `config.Load` no longer requires `CLOUDFLARE_API_TOKEN`; `SERVANAGO_HOST_IP` is required only when DNS sync is on. A set token is still validated (the format check that otherwise makes Caddy's config unloadable stays)
- `cfdns`, `dnssync` and the token check are constructed only when a token is set; with none, `web.Deps.CF`/`DNS` are nil and every handler tolerates that
- With no token the UI hides the Cloudflare banner, DNS columns and record actions, the UI-host DNS card and the checklist items about the token and DNS; Add site skips zone lookup
- Scope correction found while building: the baseline derives a route's domain from a Cloudflare zone lookup. Without one, a domain must be added by hand on the Domains page, Add site matches the hostname to it (single label below it, as before), and wildcard certificates are unavailable (domains are per host). First-class hostnames are the M2 site model
- The renderer's no-DNS rule is global and implied by the token: no token means `Options.HTTP01` (default ACME challenges, no `challenges`, wildcard domains render per host). Every option for the Stage 2 question agrees on that, so it ships here
- `servanago import` needs Cloudflare and refuses to run without a token, before touching anything
**Tests**: config table tests (token unset ok; set-but-malformed still rejected; host IP required only with a token); web tests with nil `CF`/`DNS` for dashboard, domains, add site, route create/toggle/delete and the DNS endpoints (404); renderer goldens for HTTP-01; a real-Caddy test that the no-challenge ACME config loads and a dead CA surfaces in the log ring; e2e project `nocf` (second server started without a token: add domain, add site, no DNS UI, unknown-domain hint).
**Status**: Complete. Notes:
- Changed existing tests for the new spec: the "all missing" config row no longer lists the token or host IP, and the checklist test now expects the UI-address certificate item without a host card (the DNS item still needs one)
- The multi-label message in Add site still talks about wildcard certificates; it is only accurate with Cloudflare. Left for M2, which replaces the rule
- Verified: `go test -race`, lint, e2e 29/29 (27 + 2 new)

## Stage 2: HTTP-01 / TLS-ALPN default issuer
**Goal**: Certificates for public hostnames with no DNS provider. Partly delivered in Stage 1: with no token the renderer already uses default challenges (`Options.HTTP01`), and domains already store an empty `zone_id` (no migration needed; the column is NOT NULL and an empty string is allowed). What remains is choosing DNS-01 versus HTTP-01 when a token exists.
**Success Criteria**:
- `caddycfg` renders the DNS-01 issuer only where selected (see open question) and HTTP-01 elsewhere, per domain rather than from the token alone
- Golden files for: DNS-01 wildcard, DNS-01 per host, HTTP-01 beside DNS-01 in one config
**Decision (user, M1)**: the choice is global: DNS-01 whenever a token is set, HTTP-01/TLS-ALPN otherwise. That is exactly what Stage 1 shipped, so there is nothing left to build here. A per-domain `challenge` field was offered and declined; revisit if a host behind a firewall and a public host must share one install.
**Tests**: covered in Stage 1 (HTTP-01 goldens, real-Caddy load test) and by the existing DNS-01 goldens.
**Status**: Complete (delivered by Stage 1; no further work)

## Stage 3: Public addresses and names
**Goal**: Stop rejecting what a hosting manager must accept.
**Success Criteria**:
- `ValidateLANIP` becomes `ValidateIP`: any usable IPv4 accepted (LAN, CGNAT, public); loopback, unspecified, "this network", multicast, broadcast, link-local and reserved are refused
- IPv6 (user decision: dual-stack): `ValidateIP6` accepts global unicast and unique-local addresses. `SERVANAGO_HOST_IP6`, `domains.default_ip6` and `routes.record_ip6` are optional AAAA targets beside the IPv4 ones; the IPv4 address stays required, so there is no IPv6-only site
- Migration `006`: the two columns, and `dns_records` / `ui_dns_record` rebuilt keyed by (route, family) with existing rows kept as A
- `cfdns` and `dnssync` handle both families with independent owned / adopt / conflict state; clearing an IPv6 address deletes an owned AAAA and only drops the row of an adopted one; take-over covers both; deleting a route offers to remove both
- Dashboard: one badge per record; UI-host card, checklist and delete dialog are family-aware; IPv6 fields show only with Cloudflare configured
- Hostname rules unchanged (`.local`, `.internal`, `.home.arpa`, IP literals still rejected); upstream hosts may be public or IPv6 literals (rendered bracketed); IPv6 allowlist CIDRs accepted
- Help text, README, llms.txt, `.env.example`, DESIGN §16 and the "LAN only" warning updated
**Tests**: table tests for every address class in both families; store tests incl. a real v5 -> v6 upgrade with data; `cfdns` and `dnssync` tests (create, adopt, conflict, take-over, clear, host) for AAAA; web tests for the forms, handlers, dashboard badges, delete and host card; renderer golden for an IPv6 upstream and allowlist; probe address test; e2e dual-stack spec; the mock Cloudflare server now understands record types.
**Status**: Complete. Notes:
- Changed existing tests for the new spec: public IPv4 accepted (the old "public IP rejected" cases), the migration version is 6, and DNS store calls take a family
- Known gap: a domain added without Cloudflare has an empty default IP; if a token is added later its A record is not created and the dashboard cannot edit the domain. Domains have no edit page yet (M2)
- Known gap: no dual-stack for `servanago import` beyond copying `SERVANAGO_HOST_IP6` onto new domains

## Stage 4: Docs and gate
**Goal**: Docs describe optional Cloudflare; the whole suite passes.
**Success Criteria**: README config table marks Cloudflare variables optional and groups them; ROADMAP M1 marked Done; `make check` green on a clean clone; plan file deleted.
**Tests**: `make check`.
**Status**: Not Started
