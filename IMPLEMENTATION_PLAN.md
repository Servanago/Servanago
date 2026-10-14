# Implementation Plan

Source: `docs/DESIGN.md`, `docs/REQUIREMENTS.md`. Loop rules: `CLAUDE.md`. Each slice: red test, green, refactor, `make check`, commit, mark Complete. Delete this file when all slices are Complete.

Dependencies between slices: 0 → 1 → 2 → 3 → 4; 5 needs 1 and 4; 6 needs 3, 4, 5; 7 needs 5 and 6; 8 needs 6; 9 needs 6; 10 needs 6; 11 needs 3; 12 needs all.

## Slice 0: Spike and project scaffold
**Goal**: Prove embedded Caddy works as designed; create the repo skeleton and the `make` targets `CLAUDE.md` names.
**Success Criteria**:
- `git init -b main`, author `Brian Tafoya <btafoya@briantafoya.com>`, `.gitignore` (includes `.env`, `data/`), MIT `LICENSE`, `NOTICE`, `go.mod` for `github.com/caretakarr/caretakarr` with latest stable Caddy, `caddy-dns/cloudflare`, `cloudflare-go/v7`, `modernc.org/sqlite`.
- `Makefile` with `test`, `lint`, `e2e`, `check`, `build`, `docker`; `.golangci.yml`.
- Confirmed against the pinned Caddy: `admin.disabled` + `admin.config.persist=false` field names; custom log writer module loads and survives two reloads (`DESIGN.md` §9).
- `codegraph init -i` run once Go code exists.
**Tests**:
- Integration (kept as the harness for later slices): `Load` a static JSON on high ports with the `internal` issuer, request a route via an `httptest` upstream, assert 200.
- Same test: second `Load` with a changed route, assert new route live; `Load` with invalid JSON, assert error and old route still live.
- Log writer: lines reach `Sink` before and after two reloads.
- Websocket upgrade through `reverse_proxy` passes.
**Status**: Complete

## Slice 1: Config and store
**Goal**: Env parsing and SQLite persistence with migrations.
**Success Criteria**:
- `internal/config` parses `CLOUDFLARE_API_TOKEN`, `CARETAKARR_HOST` and `ACME_EMAIL` (both required; email validated with `net/mail`), `ADMIN_PASSWORD`, `ACME_STAGING`, `ACME_PROPAGATION_DELAY`, `ACME_PROPAGATION_TIMEOUT` (optional), `ACME_RESOLVERS` (default `1.1.1.1,8.8.8.8`), `UI_LISTEN`, `DATA_DIR`; fails fast with named missing vars.
- `internal/store` opens WAL SQLite with `foreign_keys`, applies embedded migrations via `PRAGMA user_version`, schema per `DESIGN.md` §4 (including `cert_mode`).
- Domain-name validator rejects `.local`, `.internal`, `.home.arpa`, IP literals.
**Tests**: table-driven env cases (missing `ACME_EMAIL` errors naming it; `not-an-email` errors; `Name <a@b.co>` form rejected, bare address only); durations parse or error; migration applies on empty DB and is idempotent; unique `(domain_id, subdomain)`, port CHECK, `cert_mode` CHECK, FK restrict on domain delete; CRUD round trips; validator table.
**Status**: Complete

## Slice 2: Caddy config renderer
**Goal**: Pure `caddycfg.Render(State, Options) ([]byte, error)`.
**Success Criteria**:
- Every ACME issuer carries `"email"` from `Options.Email`; render errors if it is empty.
- Empty state yields bootstrap config (UI route, UI cert policy, admin disabled, persist false, storage path, log writer).
- Routes render with allowlist, basic auth, scheme/skip-verify, disabled → 503.
- `wildcard` and `per_host` policies; propagation fields emitted only when set; token only as `{env.CLOUDFLARE_API_TOKEN}`; staging CA set from option; deterministic ordering.
**Tests**: golden JSON asserts `email` on every issuer; empty-email render errors; golden JSON for bootstrap, one route, disabled, allowlist, basic auth, https upstream with skip-verify, staging vs prod, wildcard vs per_host, delay/timeout set vs unset, the `banking.example.com` → `192.168.25.165:8766` homelab case; determinism (render twice, byte-equal); no literal token in output.
**Status**: Complete

## Slice 3: Apply service
**Goal**: The one path that changes config: mutex, tx, render, `caddy.Load`, commit/rollback; startup load with bootstrap fallback.
**Success Criteria**: Mutation callback runs inside a tx; Caddy rejection rolls back the DB and leaves the old config live; startup with corrupt state loads bootstrap-only and exposes the error for a banner.
**Tests** (integration, serial, real in-process Caddy, high ports, `internal` issuer, `httptest` upstream): valid mutation makes route live; invalid mutation rolls back and old route still serves; corrupt row at startup yields bootstrap config + error; same-state apply is a no-op; `caddy.Stop()` in cleanup.
**Status**: Complete

## Slice 4: Web skeleton, auth, CSRF
**Goal**: Server-rendered shell reachable through Caddy at `CARETAKARR_HOST`.
**Success Criteria**: Loopback UI server; templates + vendored Pico/htmx via `embed.FS`; layout and empty dashboard; optional login (signed per-boot cookie, `HttpOnly`/`Secure`/`SameSite=Strict`), per-IP throttle, CSRF rule (non-GET needs `HX-Request` and matching `Origin`); no `ADMIN_PASSWORD` → open, `WARN` log and red banner; client IP from `X-Forwarded-For` only from loopback peer.
**Tests**: handler tests for login success/fail/throttle, protected route redirects, CSRF rejects, open mode banner, XFF trusted only from loopback; e2e (Playwright): login flow and dashboard load.
**Status**: Not Started

## Slice 5: Domains and Cloudflare zone lookup
**Goal**: Add and remove domains validated against the token.
**Success Criteria**: Add domain resolves `zone_id` via `cloudflare-go/v7` (`Zones.List`), stores `default_ip`, `cert_mode`; startup token verify with UI banner on failure; delete blocked while routes exist; each add/remove goes through the apply service.
**Tests**: `cfdns` against `httptest` + `option.WithBaseURL` (zone found, not found, bad token, API error text surfaced); handler tests for validation (`.local` rejected, bad IP); e2e: add domain, see it listed.
**Status**: Not Started

## Slice 6: Routes and presets
**Goal**: Create, edit, delete routes; presets; end-to-end proxying.
**Success Criteria**: Preset list (Sonarr 8989, Radarr 7878, Lidarr 8686, Readarr 8787, Prowlarr 9696, Bazarr 6767, Overseerr 5055, Jellyseerr 5055, qBittorrent 8080, SABnzbd 8080, Tautulli 8181, Plex 32400, Jellyfin 8096, Emby 8096) fills subdomain and port; routes validated (subdomain label, port, host); each change goes through apply; a request to `sub.domain` reaches the upstream.
**Tests**: preset table; validation table; apply integration with two routes on one domain; handler tests; e2e: add route from preset, toggles appear.
**Status**: Not Started

## Slice 7: DNS record sync
**Goal**: A-record lifecycle per `DESIGN.md` §7.
**Success Criteria**: Create with `proxied=false` and comment; adopt identical existing record (`owned=0`); `conflict` on different content (no write) with "Take over" action; update only owned; delete only owned, confirmation text says which; per-route `record_ip` override; Resync button; DNS failure does not revert the route and shows `error` with retry.
**Tests** (`httptest` Cloudflare): create, adopt, conflict, take over, owned delete, adopted never deleted, IP change updates, API error sets `error` state, idempotent resync; e2e: route add shows synced, delete shows confirm.
**Status**: Not Started

## Slice 8: Route controls
**Goal**: Enable/disable, CIDR allowlist, per-route basic auth.
**Success Criteria**: Toggle swaps route to 503 and back; allowlist validates CIDRs and returns 403 outside; basic auth stores bcrypt hash only, password never returned to the UI.
**Tests** (integration with real Caddy): disabled → 503; allowed vs blocked source (via configured range including/excluding loopback) → 200/403; wrong/right basic auth → 401/200; hash never rendered into pages; e2e: toggle and edit controls.
**Status**: Not Started

## Slice 9: Probes and status UI
**Goal**: Upstream health and cert state on the dashboard.
**Success Criteria**: 30s TCP dial per enabled route (in memory); loopback TLS probe per route host reads `NotAfter` and issuer; `/status` fragment polled every 10s with states up/down, cert issued/pending/error with expiry, DNS state.
**Tests**: TCP probe against open/closed listener; TLS probe against the in-process Caddy with `internal` issuer; state mapping table; e2e: status badges render.
**Status**: Not Started

## Slice 10: Docker discovery (opt-in)
**Goal**: List containers from the Docker socket when mounted.
**Success Criteria**: `GET /containers/json` over unix socket via stdlib; panel hidden when the socket is absent; pre-fills route with container name and a private port; UI note on shared networks.
**Tests**: fake unix-socket server returning canned JSON; absent socket hides panel; parse edge cases (no ports, multiple ports, multiple names); e2e skipped without socket.
**Status**: Not Started

## Slice 11: Caddy log ring buffer and Logs page
**Goal**: Show Caddy and ACME log lines in the UI.
**Success Criteria**: Writer module from slice 0 productionized; ring of 1000 entries (`ts`, `level`, `logger`, `msg`, `error`); non-blocking `Write`; Logs page with level filter polled by htmx.
**Tests**: ring overflow drops oldest; concurrent writes under `-race`; JSON line parsing incl. malformed line; level filter; integration: forced ACME failure shows an error entry; e2e: Logs page renders.
**Status**: Not Started

## Slice 12: Packaging, CI, docs
**Goal**: Shippable image and repo.
**Success Criteria**: Multi-stage `Dockerfile` (`CGO_ENABLED=0`, `distroless/static:nonroot`); `docker-compose.yml` (volume `./data:/data`, ports 80, 443, 443/udp, `.env`, commented socket mount) and `docker-compose.dev.yml` (`ACME_STAGING=true`); GitHub Actions: `make check`, multi-arch image to `ghcr.io/caretakarr/caretakarr` on tag; `README.md` with quickstart, token permissions, `.env.example`, `UI_LISTEN` recovery warning, Docker socket warning, volume permissions (UID 65532); `NOTICE` credits Caddy and caddy-dns/cloudflare.
**Tests**: image builds; container starts with a test `.env` and serves the UI on bootstrap config; `make check` passes in CI; secrets scan on the diff finds none.
**Status**: Not Started
