# M1: decouple Cloudflare

Goal: ServanaGo works for any public hostname with no Cloudflare account. Cloudflare DNS-01 and A-record sync stay as an optional feature. Baseline for every stage: `go test -race`, lint and e2e (27 specs) green on `main` after M0.

Status of this plan: stages and criteria are a first cut; Stage 2 has an open design question (below) that must be answered before it starts.

## Stage 1: Cloudflare becomes optional
**Goal**: Start, serve and manage sites with `CLOUDFLARE_API_TOKEN` unset.
**Success Criteria**:
- `config.Load` no longer requires `CLOUDFLARE_API_TOKEN`; `SERVANAGO_HOST_IP` is required only when DNS sync is on. A set token is still validated (the format check that otherwise makes Caddy's config unloadable stays)
- `cfdns`, `dnssync` and the token check are constructed only when a token is set; with none, `web.Deps.CF`/`DNS` are nil and every handler tolerates that
- With no token the UI hides the Cloudflare banner, DNS columns and record actions, the UI-host DNS card and the checklist items about the token and DNS; Add site skips zone lookup and domain-to-zone matching
**Tests**: config table tests (token unset ok; set-but-malformed still rejected; host IP required only with a token); web tests with nil `CF`/`DNS` for dashboard, add site, route edit and delete; e2e run started without a token (new project in the Playwright config).
**Status**: Not Started

## Stage 2: HTTP-01 / TLS-ALPN default issuer
**Goal**: Certificates for public hostnames with no DNS provider.
**Success Criteria**:
- `caddycfg` renders an ACME issuer with no `challenges.dns` by default; the DNS-01 issuer is rendered only where selected (see open question)
- Golden files for: default HTTP-01, DNS-01 wildcard, DNS-01 per host, mixed domains
- Domains no longer need a Cloudflare zone ID (migration `006` relaxes `domains.zone_id` to nullable or empty-allowed)
**Open question (needs a decision before this stage)**: how is DNS-01 chosen when a token exists? Options: (a) per domain, a `challenge` field next to `cert_mode`; (b) global, DNS-01 whenever a token is set; (c) per domain, but only wildcard mode implies DNS-01 and per-host implies HTTP-01. Recommendation: (a) with default HTTP-01, since a token existing says nothing about whether a host is reachable from the internet.
**Tests**: golden renders; integration test applying the default issuer against the in-process Caddy with the internal CA; migration test from a v5 DB with data.
**Status**: Not Started

## Stage 3: Public addresses and names
**Goal**: Stop rejecting what a hosting manager must accept.
**Success Criteria**:
- `ValidateLANIP` becomes `ValidateIP`: any valid IPv4 accepted (LAN, CGNAT, public); IPv6 stays rejected until a stage adds AAAA support; loopback, unspecified, multicast and link-local stay rejected
- Hostname rules unchanged (`.local`, `.internal`, `.home.arpa`, IP literals still rejected); upstream hosts may be public
- Help text, README, DESIGN §16 and the "LAN only" warning updated
**Tests**: table tests for every address class; web tests for domain, route and UI-host IP fields; the e2e "public IPs are rejected" spec is replaced, not deleted: it asserts the new rule (public accepted, loopback rejected).
**Status**: Not Started

## Stage 4: Docs and gate
**Goal**: Docs describe optional Cloudflare; the whole suite passes.
**Success Criteria**: README config table marks Cloudflare variables optional and groups them; ROADMAP M1 marked Done; `make check` green on a clean clone; plan file deleted.
**Tests**: `make check`.
**Status**: Not Started
