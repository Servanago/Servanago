# Design: Corvus-inspired protection, observability and proxy extras (target 0.21.0)

Status: design v2, 2026-11-25. Requirements settled; analysis corrections and ponytail cuts applied. Not implemented.
Related: `requirements_corvus_features.md` (what and why), `analysis_corvus_design.md` (findings A/B/C against existing code, tags below), `docs/ROADMAP.md` M13.
Code reviewed with codegraph: `caddycfg.siteHandler`, `caddygeoip`, `caddygate`, `caddywaf` (owned Coraza module, in-process rate limit, `waf_events`), `caddylog.Ring`, `probe.Monitor`, `web` layout, migrations 001–012 (user_version 12). Corvus reference: `gateway/lua/corvus/{rules,waitroom,underattack,challenge}.lua`, `control/internal/{live,autoban,underattack,alerts}`.

One branch, one release, built in the order of section 16. Every internal commit passes `make check`.

## 1. Principles

- Same shape as geoip/gate: the rendered JSON pins what SQLite said at render time; **runtime state lives in an app-side registry installed before `caddy.Load`** (`caddygeoip.Install` pattern, `cmd/servanago/main.go:104,147`). Site saves re-provision modules on every apply, so counters, bans, queue lines and under-attack state must NOT live inside module structs.
- Registry keys use the **site slug**, never the rowid (SQLite reuses rowids).
- Renderers stay pure and golden-tested; new inputs go in `store.Site` (new 1:1 tables) and `caddycfg.Options`, never in positional `State` literals.
- Fail open: a missing or broken registry service never takes a site down.
- No new third-party Go dependency. No Redis, no Node build, **no new JavaScript beyond the PoW page** (live views are htmx polling, section 12).
- Tags **[A-n]/[B-n]/[C-n]** point at `analysis_corvus_design.md`; **[P]** marks a cut from the ponytail review (2026-11-25).

## 2. Request flow (per site subroute)

Final layer order. Differs from the requirements doc on purpose: **under-attack leads the gate** (the gate's form can send mail; a flood is challenged before it reaches that).

```
observer ─▶ ban ─▶ geo ─▶ waf(+rate limit) ─▶ under-attack ─▶ gate / allowlist-403
        ─▶ basic auth ─▶ x402 ─▶ queue ─▶ snippets ─▶ site handler
```

| # | Handler id | Role | Short-circuits with |
|---|---|---|---|
| 0 | `servanago_traffic` | observer: records status/bytes/latency/outcome after the chain returns, feeds ban counters | never |
| 1 | `servanago_ban` | registry lookup by client key | 403 plain, outcome `banned` |
| 2 | `servanago_geoip` | existing | existing |
| 3 | `waf` | existing; sets var `sg_waf_flagged` when a rule matched, outcome `ratelimited` on its 429 | existing |
| 4 | `servanago_challenge` | PoW or Turnstile page, verify endpoint, pass cookie | 403 page, outcome `challenged` |
| 5 | `servanago_gate` / allowlist 403 / basic auth | existing | existing |
| 6 | `servanago_x402` | 402 + payment verify/settle | 402, outcome `payment` |
| 7 | `servanago_queue` | waiting room | waiting page, outcome `queued` |
| 8 | snippets, handler | existing | |

**[A1] Client IP.** `caddycfg.Render` adds to `srv0`: `trusted_proxies` = `{source: static, ranges: <Cloudflare ranges>}` (moved from `caddygeoip.cloudflareRanges` into `internal/clientip` as the single list) and `client_ip_headers: ["CF-Connecting-IP"]`. Caddy's `client_ip` var is then the real visitor for Cloudflare peers and the socket peer for everyone else (a forged header from another peer is ignored). Every layer, the WAF rate limiter/events and the observer read `client_ip`. **The allowlist and gate matchers switch from `remote_ip` to `client_ip`** (decided; behavior change for Cloudflare-proxied sites: allowlists now match visitors, not edge nodes; direct sites unchanged; release-note it). Golden JSON updates once; real-Caddy tests: Cloudflare-range peer with header → header IP, other peer with header → peer IP.

Allowlisted addresses are never banned and skip layers 4, 6, 7 via the same `not client_ip` matcher the gate uses. Panel-owned paths bypass every new layer: `/.well-known/*` (ACME), `/__servanago/*` (challenge verify, queue status).

**[B3] Unknown hosts.** `Render` appends one catch-all route after all host routes: observer (slug `""`, outcome `unknown_host`) → ban → `static_response` 404, empty body. Counted in traffic; feeds auto-ban only when `guard_settings.ban_unknown_host = 1` (default 0). ACME HTTP-01 and port-80 redirects are Caddy automatic-HTTPS routes and are unaffected (verified by the real-Caddy ACME-staging test). Disabled sites keep their 503 and stay unobserved **[B4]**. The `ml.` host route gets observer + ban only.

Outcome travels from layers to the observer via `caddyhttp.SetVar(ctx, "sg_outcome", ...)` (pass, blocked, banned, challenged, queued, payment, ratelimited, unknown_host).

`siteHandler`'s fast path (`caddycfg/render.go:279`) must include `r.Guard.Any()`, or a site with only a new layer renders unprotected. A table test proves every layer flag defeats it.

## 3. Packages **[P]**

```
internal/clientip      CloudflareRanges; Of(r) reads Caddy's `client_ip` var and applies geoip's skip rules (loopback, private, CGNAT, link-local); caddygeoip and caddywaf delegate. Key(addr): IPv4 or IPv6 /64.
internal/guard         registry + traffic collector, ban engine, challenge, queue, x402 client, one file per concern; Install/Current; owns the goroutines (flush, evaluator, prune)
internal/trafficdb     [A2] own SQLite file <DATA_DIR>/traffic.db
internal/alerts        destinations, senders, bounded queue
internal/turnstile     [B5] siteverify call extracted from web/turnstile.go, takes (action, hostname)
internal/caddyguard    the five Caddy modules (traffic, ban, challenge, queue, x402)
internal/web           traffic.go, bans.go, alerts.go, queue.go, mcp_guard.go, checkconn.go
```

x402 uses an in-house client (build requirements, read payment header, POST `/verify` and `/settle`), not the Go SDK, whose EVM dependency tree is unchecked (`go list -deps` before reconsidering). Contract tests use a fake facilitator; an opt-in live test targets `https://x402.org/facilitator` (Base Sepolia).

## 4. Data model: migration `013_guard.sql` (user_version 13)

Rules: new migration only; never edit 001–012; bump `TestMigrationsIdempotent`, `store_test.go:41` (`v != 12`), `repair_test.go:122`, `migrate_test.go:60` **[C5]**; `migrate()` already runs rebuilds with FK off.

New 1:1 tables instead of widening `sites` (the positional `siteCols`/Scan/INSERT/UPDATE lists stay untouched): `store.Site.Guard` and `store.Site.Page` load with one extra query per site list.

```sql
CREATE TABLE site_guard (
  site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  ban_on          INTEGER NOT NULL DEFAULT 0,
  ua_mode         TEXT NOT NULL DEFAULT '' CHECK (ua_mode IN ('', 'on', 'auto')),
  ch_kind         TEXT NOT NULL DEFAULT 'pow' CHECK (ch_kind IN ('pow', 'turnstile')),
  ch_difficulty   TEXT NOT NULL DEFAULT 'medium' CHECK (ch_difficulty IN ('low', 'medium', 'high')),
  ch_ttl_min      INTEGER NOT NULL DEFAULT 60,        -- pass cookie is always bound to the client address
  ua_auto_rps     INTEGER NOT NULL DEFAULT 0,         -- auto trigger; 0 = never
  ua_cooldown_min INTEGER NOT NULL DEFAULT 10,
  q_on            INTEGER NOT NULL DEFAULT 0,
  q_capacity      INTEGER NOT NULL DEFAULT 100,
  q_active_ttl_s  INTEGER NOT NULL DEFAULT 300,
  q_max_queue     INTEGER NOT NULL DEFAULT 5000,
  backends        TEXT NOT NULL DEFAULT ''            -- proxy sites: extra "host:port" backends, one per line (extra_routes/allowlist precedent)
);

CREATE TABLE site_x402 (            -- zero or more routes per site
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  path TEXT NOT NULL,               -- prefix, e.g. /api/  (clean, validated)
  price TEXT NOT NULL,              -- decimal USD string, "0.001"
  mode TEXT NOT NULL CHECK (mode IN ('all', 'bots')),
  grant_kind TEXT NOT NULL CHECK (grant_kind IN ('request', 'token')),
  token_ttl_s INTEGER NOT NULL DEFAULT 600,
  UNIQUE (site_id, path)
);

CREATE TABLE site_page (            -- kind 'page': maintenance / coming-soon / parked page, or a redirect
  site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  status INTEGER NOT NULL DEFAULT 503,
  title TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '',   -- the one built-in template
  html TEXT NOT NULL DEFAULT '',    -- custom page, <= 64 KB, overrides title/message
  target TEXT NOT NULL DEFAULT '',  -- status 301/302/303/307/308 + target = redirect
  keep_path INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE bans (                 -- active and recently expired; expired rows kept 7 days so the next ban escalates
  client TEXT PRIMARY KEY,          -- clientip.Key
  site_slug TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL CHECK (source IN ('auto', 'manual')),
  level INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL DEFAULT '',  -- "21 responses in 60s: 403x14 429x7"
  created_at INTEGER NOT NULL, until INTEGER NOT NULL, created_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE guard_settings (       -- single row id=1, seeded like settings
  id INTEGER PRIMARY KEY CHECK (id = 1),
  ban_codes TEXT NOT NULL DEFAULT '401 403 429',     -- [B2] 404 opt-in; WAF rate-limit 429s (outcome 'ratelimited') never count
  ban_unknown_host INTEGER NOT NULL DEFAULT 0,       -- [B3]
  ban_threshold INTEGER NOT NULL DEFAULT 20, ban_window_s INTEGER NOT NULL DEFAULT 60,
  ban_steps_min TEXT NOT NULL DEFAULT '15 60 1440',  -- escalation durations
  ban_exempt TEXT NOT NULL DEFAULT '',               -- CIDRs, one per line
  log_days INTEGER NOT NULL DEFAULT 7, rollup_days INTEGER NOT NULL DEFAULT 90,
  ua_list TEXT NOT NULL DEFAULT 'GPTBot ClaudeBot CCBot PerplexityBot Bytespider Amazonbot Google-Extended',
  x402_facilitator TEXT NOT NULL DEFAULT '', x402_network TEXT NOT NULL DEFAULT 'eip155:8453',
  x402_pay_to TEXT NOT NULL DEFAULT '',
  x402_api_key_sealed TEXT NOT NULL DEFAULT ''       -- optional facilitator bearer, secretbox-sealed
);
INSERT INTO guard_settings (id) VALUES (1);

CREATE TABLE alert_dests (          -- every enabled destination gets every event
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('slack', 'discord', 'webhook', 'email')),   -- slack = Slack/Mattermost-compatible {"text"}
  target_sealed TEXT NOT NULL,      -- URL or address, sealed (URLs carry secrets)
  secret_sealed TEXT NOT NULL DEFAULT '',   -- webhook HMAC key
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE site_alert_dests (     -- per-site override: rows present = only these destinations for that site
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  dest_id INTEGER NOT NULL REFERENCES alert_dests(id) ON DELETE CASCADE,
  PRIMARY KEY (site_id, dest_id)
);
```

**[A2] `traffic.db`** (`internal/trafficdb`; same pragmas as the main store: WAL, `busy_timeout(5000)`; opened at startup before the registry; never backed up or copied at upgrade). **[P]** Disposable data needs no migration list: `CREATE TABLE IF NOT EXISTS` at open; on a schema mismatch (stored `user_version` differs) drop and recreate the file. Open failure degrades traffic features only; the panel and every site keep running.

```sql
CREATE TABLE traffic_rollup (       -- per site per minute; site_slug, not id
  site_slug TEXT NOT NULL, minute INTEGER NOT NULL,
  req INTEGER NOT NULL, s2 INTEGER NOT NULL, s3 INTEGER NOT NULL, s4 INTEGER NOT NULL, s5 INTEGER NOT NULL,
  blocked INTEGER NOT NULL, challenged INTEGER NOT NULL, queued INTEGER NOT NULL, banned INTEGER NOT NULL, paid INTEGER NOT NULL,
  ratelimited INTEGER NOT NULL, unknown_host INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  lat TEXT NOT NULL,                -- JSON array of bucket counts (20 log buckets, ms)
  PRIMARY KEY (site_slug, minute)
) WITHOUT ROWID;
CREATE TABLE request_log (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, site_slug TEXT NOT NULL, host TEXT NOT NULL,
  client TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,   -- path only, query dropped (secrets)
  status INTEGER NOT NULL, ms INTEGER NOT NULL, bytes INTEGER NOT NULL,
  outcome TEXT NOT NULL, ua TEXT NOT NULL DEFAULT '', ref_origin TEXT NOT NULL DEFAULT '',
  err TEXT NOT NULL DEFAULT ''      -- raw Caddy error text of a failed upstream (502/504 diagnosis), truncated 200
);
CREATE INDEX request_log_site_ts ON request_log(site_slug, ts DESC);
CREATE INDEX request_log_client ON request_log(client, ts DESC);
```

`sites.kind` CHECK must allow `page`, so the migration **rebuilds `sites`** as 011 did: copy all columns, keep the cross-column CHECKs (one new OR clause for kind `page`: no upstream, no static_root, no commands, `site_user = ''`, `public_dir = ''`), re-create indexes, rely on `migrate()`'s FK-off wrapper. Rehearse through a real Store on a copy of bee's DB (not the sqlite3 CLI). `TestMigrationRebuildKeepsChildRows` extended for the new child tables. Confirm `repairLegacy`'s kind-CHECK regexp (matches `'cgi'` only) still passes **[C4]**.

Deleting a site cascades the config tables; a hook in `deleteSite` prunes that slug's rows in traffic.db. Bans are IP data and stay.

## 5. Traffic collector (`internal/guard`)

**[A4] Observer writer.** Built on `caddyhttp.ResponseWriterWrapper` (keeps `Unwrap`, `Flush`, `Hijack`, `ReadFrom`); counts bytes and captures the first status, buffers nothing. Required tests: WebSocket upgrade through the observer, a flushed streaming response (`Stream` sites), status captured when `next` returns a `HandlerError`. Build step 2 starts with a half-day spike against Caddy's native access log (`servers.srv0.logs` + custom writer module + `sg_outcome` field); the observer stays unless the log route is cleaner. `caddywaf/serve.go` gets two one-line edits (set `sg_outcome=ratelimited`, set `sg_waf_flagged`), each with a test.

Per request, in the observer, after `next` returns:
1. `site := reg.Site(slug)` (pointer resolved at Provision).
2. Atomics only: request, status class, bytes, outcome counter, latency bucket.
3. Ban feed: `if (site.ban_on || unknown host && ban_unknown_host) && status in codes && outcome not in {banned, challenged, queued, payment, ratelimited}` then `bans.Observe(clientKey, slug, status)`. Defaults **[B2]**: codes `401 403 429`, 20 per 60 s; 404 is opt-in because pages with missing assets would ban normal visitors (UI help text says so).
4. Request log: non-blocking send to a bounded channel (10k); full = drop and count `log_dropped` (shown in UI). One writer goroutine batches inserts every 2 s in one tx, mirroring `caddywaf/events.go` (chan, drop-and-count) **[C1]**. Path without query; UA truncated 200; referrer origin only; `err` set from the error `next` returned.

Rollup: a 1 s ticker snapshots counters into a ring of the last 15 min (what the live views read); each minute boundary writes one `traffic_rollup` row per active site. Windowing swaps an epoch pointer, not read-and-zero. Percentiles: 20 log-spaced buckets (1, 2, 3, 5, 8, 12, 20, 30, 50, 80, 120, 200, 300, 500, 800, 1.2k, 2k, 5k, 10k, >10k ms), linear interpolation inside the bucket, summed across minutes for ranges. No unique-IP counts **[P]**.

Retention: hourly prune: `request_log` older than `log_days` and beyond a fixed 200k rows per site (delete oldest), rollups older than `rollup_days`.

Deferred **[P]**: SSE stream and `/metrics` (Prometheus). Add when asked; the registry already holds every number.

## 6. Auto-ban (`internal/guard`)

- Counters: 256 shards of `map[key]*bucket`, key = `clientKey|slug`; fixed window; total entries capped (100k); expired entries dropped on touch and by a 30 s sweeper; at cap, new keys are not counted (fail open).
- Trip: count ≥ threshold in window → level = (existing row for this client not older than 7 days after `until`) level + 1, else 1, clamped to `ban_steps_min`; `until = now + step`; upsert `bans`, add to the in-memory `sync.Map`, audit `ban.created` (actor `system`), alert `ban` (≥ N bans in 5 min sends one summary).
- Check (`servanago_ban`): `sync.Map` lookup, no SQLite on the hot path. Startup loads unexpired bans. Hourly prune of `bans` rows expired > 7 days.
- Never banned: unparsable/private/loopback peers (`clientip.Of` false), `ban_exempt` CIDRs, site allowlist addresses, panel paths, Cloudflare peers without the header. A manual ban of the requester's own address is refused.
- UI `/bans`: active list (client, site, level, reason, until, source), manual ban (single address or /64), unban. Mutations audited (`ban.create`, `ban.delete`).
- Responses answered by the challenge, queue, ban and x402 layers are not counted (outcome filter above), so waiting visitors never ban themselves.

## 7. Under-attack and challenge (`internal/guard`)

State per site (registry, atomic): `forced` (ua_mode on), `autoUntil`.
**[P]** Evaluator (1 s tick, only `ua_mode=auto` sites): requests per second over the last 10 s ≥ `ua_auto_rps` → `autoUntil = now + cooldown`, extended while it holds; transitions emit alert `underattack` on/off and audit `underattack.auto-on|off` (system). No block-share trigger, no automatic difficulty raise.

Decision (pure function, unit-tested like Corvus `underattack.decide`): off / exempt (allowlist, `/.well-known/`, `/__servanago/`, ban-exempt CIDR) / pass (valid cookie) / challenge.

PoW:
- Page → 403 `text/html`, `Cache-Control: no-store`, `X-Robots-Tag: noindex`, `X-ServanaGo-Challenge: pow`. Body embeds `{salt, bits, ts, sig}`, `sig = HMAC(key, slug|clientKey|salt|bits|ts)`; inline JS (~60 lines, Web Worker via Blob) finds `counter` with `SHA-256(salt|counter)` having `bits` leading zero bits, POSTs `/__servanago/challenge` with `{salt,bits,ts,sig,counter,return}`. Bits: low 14, medium 16, high 18 (calibrate on real phones before release: target 0.5–1 s medium; a knob, not a promise).
- Verify: constant-time sig check, `ts` age ≤ 120 s, hash check, `return` must be a path (open-redirect guard), then `Set-Cookie: sg_pass=<exp>.<site>.<clientKey hash>.<mac>` (HttpOnly, Secure, SameSite=Lax, host-only, TTL `ch_ttl_min`), 303 to `return`. **[P]** No single-use salt set: replaying a solved puzzle only yields another pass cookie.
- No-JS / curl: the 403 body says JavaScript is required; never 5xx. Challenge answers count as `challenged`, not `blocked`.
- **[B6]** Keys: HKDF-SHA256 over `SERVANAGO_SECRET_KEY` (the gate's pattern, `caddygate/gate.go:336`) with labels `challenge-pass`, `challenge-pow`, `queue-sid`, `queue-adm`, `x402-token`; never the secretbox key itself. No secret key = random per-process keys (passes, queue cookies, x402 tokens reset on restart; documented).
- Turnstile: page renders the widget with `TURNSTILE_SITE_KEY`; the verifier is the extracted `internal/turnstile` called with `action="challenge"` and the request host **[B5]** (the panel keeps `action="login"`, its tests unchanged); success issues the same pass cookie. **Constraint**: the Turnstile widget must allow the site's hostnames. The site form warns when `ch_kind=turnstile` and Turnstile is unconfigured; Cloudflare-side hostnames are documented, not detectable.

## 8. Access queue (`internal/guard`)

Room per site slug in the registry, created on first use, survives reloads, resized live.
**[P]** Simplified: no token bucket, no per-IP new-entry limit, no per-session poll budget, no leave endpoint.
- State: `active map[sid]lastSeen`, FIFO `queue` with `seen map[sid]position`, one mutex per room.
- Cookies (HMAC): `sg_q` = signed sid (24 h), `sg_adm` = signed `sid.iat` (`q_active_ttl_s`). Fast path: valid `sg_adm` younger than 30 s → pass, no room access. Older: heartbeat re-registers in `active` without a capacity check (**token holders are never blocked**, so a restart does not eject admitted visitors).
- First visit: no `sg_q` → set cookie and 302 back (HTML) or 503 + `Retry-After: 1` (non-HTML); no server state created, so a cookie-less flood cannot fill the queue. With `sg_q`: capacity free and nobody waiting → admit; else enqueue unless `q_max_queue` reached → 503 busy page.
- Waiting page: embedded HTML (English), polls `GET /__servanago/queue/status` every 3 s, reloads on admit. A visitor who leaves expires by TTL.
- Admission ticker (1 s): promote from the head while `len(active) < capacity`; sweep expired actives (> `q_active_ttl_s`) and stale queue entries (fixed 15 min).
- Emergency release: `POST /sites/{id}/queue/release` sets `releasedUntil = now+10 min` (everyone admitted), audits `queue.release`; MCP `set_queue_release`.
- Corvus fail-open/closed does not exist (no external store). Memory bound: queue ≤ `q_max_queue` × ~100 B; token-holder re-registrations capped at 50k.

## 9. x402 paywall (`internal/guard`, `caddyguard.x402`)

Scope per route row (`site_x402`); longest-prefix match wins. **[P]** Wallet is global only. Global: facilitator URL (required to enable), network (default `eip155:8453` Base; `eip155:84532` Base Sepolia for dev), `pay_to`, optional sealed facilitator bearer. Asset: USDC on the chosen network (fixed table: Base and Base Sepolia contract addresses). **Verify the addresses and the exact requirement/header names against the spec (`/x402-foundation/x402`) at implementation; moderate confidence on v2 header names `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`.**

1. Route matches and `mode` requires payment (`all`, or `bots` when a bot signal holds): no payment header → `402` with the requirements header (+ JSON body), `no-store`, outcome `payment`. Not counted by auto-ban.
2. Header present → decode; check scheme/network/amount/payTo/resource against **our** computed requirements (never the client's); **claim the payment nonce atomically before verify** (a concurrent second request with the same payload gets 402: closes the verify-then-settle double-spend window); POST facilitator `/verify` (5 s).
3. Valid → serve through `next`; status < 400 → POST `/settle`, attach `PAYMENT-RESPONSE`. Settle failure after serving is logged + alerted (content already sent; same accepted risk as the SDK middleware); the nonce stays claimed.
4. `grant=token`: after a settled payment also set `sg_x402` (HMAC `site|route|exp`) as cookie and `X-ServanaGo-Access` header; requests carrying a valid token skip payment until `token_ttl_s`. No request-count limit **[P]**.
5. Facilitator unreachable/5xx: **fail closed, 503** (`Retry-After: 5`), alert `x402` (folded). Never serve paid content unverified.

Bot signals for `mode=bots` (any): UA matches `ua_list` (case-insensitive substring); no valid `sg_pass` **and the site has a challenge configured** (otherwise the signal is off and the form says so); `sg_waf_flagged` set by the WAF module.
Never 402: `/.well-known/*`, `/__servanago/*`, allowlisted addresses. Wallet validated `0x` + 40 hex (checksum not enforced). Price: decimal string, 1–18 digits, > 0, converted with `math/big` (never float). Docs say plainly: payments are real money once mainnet is set; defaults ship on Base Sepolia.

## 10. Alerts (`internal/alerts`)

- `Notify(event)`: dedupe key `kind|site`, 5 min cooldown; **[P]** one goroutine drains a bounded queue (256), 5 s timeout, no retries; failure is logged (never the target) and counted.
- Destinations **[P]**: `slack` (Slack and Mattermost take the same `{"text"}`), `discord` (`{"content"}`), `webhook` (JSON + `X-ServanaGo-Signature: sha256=HMAC(secret, body)` + timestamp header), `email` (existing `smtpx` + Settings SMTP). Telegram and Teams only when asked.
- Safety: https required for webhooks; the dialer refuses loopback, link-local and private ranges after resolution; redirects off. Targets and secrets sealed (`secretbox`), write-only in the UI, never logged.
- Routing: a site with `site_alert_dests` rows uses only those; none → all enabled destinations. Events: `underattack` (on/off), `ban` (burst), `queue` (full), `backend` (down/up), `x402` (facilitator down, settle failure).
- Page `/alerts` (list, add, enable, test-send button, delete; edit = delete and add); per-site picker in the site form; audit `alert.*`.
- Certificate-problem alerts dropped: nothing in the code base emits them today.

## 11. Proxy extras

- **Multi-backend + failover** (kind `proxy` only): `siteHandler` default case builds `upstreams` from the site row plus `site_guard.backends` lines, with `load_balancing` `{selection_policy: round_robin, try_duration: 3s, try_interval: 250ms}` and passive health `{fail_duration: 30s, max_fails: 1, unhealthy_status: [502,503,504]}`. One scheme/TLS setting per site. Backend up/down alerts **[B7]**: extend `probe.Monitor` (it already sweeps `HasUpstream` sites with `probe.TCP`, state keyed by site ID guarded by address): probe the extra backends too (state key slug+addr), call `alerts.Notify` only on up→down / down→up transitions.
- **Page and redirect hosts [P]** (one kind `page`): renders `extraRoutes` first (path routes keep proxying), then `static_response`. Status 301/302/303/307/308 with `target` = redirect (`Location` = target, plus `{http.request.uri}` when `keep_path`); any other status = a page from the one built-in template (`title`, `message`) or `html` (≤ 64 KB, admin-authored, served as-is, never interpolated with request data). Target validated by `config` (http/https URL, public hostname, no userinfo, no control chars, not the site's own hostname). All protection layers still apply. The existing disabled-site 503 is unchanged.
- **Check connection**: `POST /sites/check` (htmx, nothing saved): scheme/host/port/skip-verify from the form (and each extra backend); stages DNS lookup → TCP dial via `probe.TCP` (3 s) → TLS handshake if https (cert errors reported, skip-verify honored); returns the failing stage and a fix hint. MCP `run_upstream_check`. "Why 502/504": the site page lists its last 10 `request_log` rows with `err != ''` (raw text, **[P]** no classification).
- **[A3] Kind blast radius** (read 2026-11-25; each needs an explicit `page` decision): `store/models.go:109,115,223`; `web/siteform.go:54,147-151,169-196,305,472-480,523,575,794,846,863`; `web/runtime.go:69-110,172`; `web/health.go:42-49`; `web/reference.go:80,147`; `web/siteview.go:497`; `web/mcp.go:245`; `helper/runtime.go:239-462` (no unit); `probe.upstreamAddr`/`Sweep` (skipped via `HasUpstream`); DNS sync and backup (no files). **Guard test** `TestEveryKindHandled`: kinds parsed from the migration CHECK each have a case in `siteHandler`, `parseSiteForm`, `health`, `reference`, `siteview`. `servanago import` unchanged.

## 12. Panel UI (htmx + templates, no new JavaScript) **[P]**

- Nav: **Traffic**, **Bans**, **Alerts**. The dashboard cards are static.
- Live views are htmx polling: a fragment with `hx-get="/traffic/snapshot?site=…" hx-trigger="every 2s"` re-renders req/s, status split, p50/p95/p99, blocked/challenged/queued counts, active bans, queue active/waiting, under-attack state. Sparklines and bars are **server-rendered inline SVG** from the 15-minute ring (Go template helper). Cost per poll is a ring read; nothing runs with no page open.
- `/traffic`: site selector (All / each), range (live, 1 h, 24 h, 7 d, 90 d from rollups), request-log table with filters (site, status, outcome, client, path contains, time) as server-rendered rows; live tail = polling for rows with `id` greater than the last shown; CSV export honoring the filter (streamed, 100k row cap; JSON when asked).
- Site form: a new **Protection** `<details>` section **beside** the existing fields (no regrouping of existing ones, so names, ids, routes, `formOf` and e2e specs keep working): Ban on/off, Under-attack (off/on/auto, rps, challenge kind/difficulty/TTL), Access queue, x402 rows (`hx-post` + `form="none"` inputs per the nested-form rule), backends textarea, alert destination picker. The help text states the layer order from section 2.
- Toggles (under-attack, unban, queue release) are htmx posts answering 204 + `HX-Redirect`/`HX-Trigger`. English only. Light/dark via the existing `--sg-*` tokens.
- `render` already buffers and 500s on template errors: each new page gets the "page completes" assertion (`>Save</button>`, `</form>`); bind `{{$id := .Site.ID}}` before ranges in `siteedit.html`.

## 13. MCP and docs

Reuse existing handlers through `mcpRun`; `formOf` (`internal/web/mcp.go`) gains every new site field (guard row, page row, x402 rows, alert dests) or `update_site` silently resets them (`TestMCPSnippets` precedent: add `TestMCPGuardFields`).

**[P]** Tools (11; verbs already in `toolLike`, no regex change): `get_traffic` (includes queue and ban counts), `list_requests`, `list_bans`, `create_ban`, `delete_ban`, `set_under_attack`, `set_queue_release`, `list_alert_destinations`, `create_alert_destination`, `delete_alert_destination`, `run_upstream_check`. Every name must appear in `skills/servanago-sites/SKILL.md` (`TestAgentSkillsMatchTheMCPTools`). No settings tools: global guard settings are UI only until asked.

Docs updated at release only (shipped-behavior docs would be wrong before): `docs/sites.md`, `docs/mcp.md`, `llms.txt`, README feature line, `docs/ROADMAP.md`, SKILL.md "since 0.21.0", `docs/RELEASING.md` version places (control, build-deb.sh, install.sh, README, docs/install.md, packaging_test.go, plugin.json, llms.txt). NOTICE unchanged (no new dependency).

## 14. Security notes

- Mutations (bans, alerts, x402, queue release) need session + CSRF + audit. Snapshot fragments and exports are session-gated GETs.
- Challenge/queue/x402 cookies are HMAC-signed, host-only, HttpOnly, Secure; constant-time compares; `return` parameters are path-only.
- Request log stores no query strings, cookies or bodies; UA truncated; referrer reduced to origin.
- **[A1]** Today the rendered server has no `trusted_proxies`, so Caddy's `client_ip` is the socket peer and the WAF rate limiter and events key on Cloudflare edge IPs for proxied records (pre-existing bug; also makes `remote_ip` allowlists match edge nodes). Without the fix a ban would hit a Cloudflare node and cut off every visitor behind it. Behind any other proxy the site still sees that proxy's address; out of scope, documented.
- The admin cannot lock themselves out: panel host and loopback peers are never banned or challenged; a manual ban of the requester's own address is refused.
- x402 handles real money: fail closed, claim nonces before verify, compute requirements server-side, ship on testnet, sealed credentials.

## 15. Test plan (CLAUDE.md layers)

- Unit: ban window/escalation/exemptions (table, injected clock); challenge `decide`, PoW verify (valid, wrong counter, expired, bad sig, open-redirect `return`), pass cookie tamper; queue (order, capacity, token holder never blocked, cookie-less flood creates no state, release); percentile math; rollup flush; x402 price→base units, requirement computation, nonce claim race (`-race`), bot signals; alerts dedupe, signature, SSRF dial refusal; `clientip` parity.
- Golden: `caddycfg` JSON per layer and all together; **order test walks decoded JSON** (never `strings.Index`); every layer flag defeats the fast path.
- Integration (real Caddy, serial, `caddy.Stop()`): ban blocks after threshold and survives a re-`Load`; challenge round trip with a Go PoW solver; queue admits in order under a goroutine crowd; x402 against a fake facilitator (402, valid, invalid, facilitator down = 503, settle failure); failover with a dead backend; page and redirect responses; layer order (ban before geo, challenge before gate, x402 after basic auth); Cloudflare-peer client IP; catch-all 404; ACME staging unaffected; WebSocket through the observer.
- Store: migration 013 on `testdata/old001.sql` lineage and a bee-vintage DB; row counts through the rebuild; `foreign_key_check`; traffic.db recreate-on-mismatch and open-failure degrade.
- Fuzz **[P]**: PoW verify inputs and the x402 header decoder only; path/price/wallet/html/redirect validators are table tests.
- Web: pages complete, snapshot fragment renders with zero traffic, CSV export honors filters, MCP tools + `formOf` guards.
- e2e: site form Protection section saves and reloads; under-attack toggle shows the challenge (Chromium solves PoW); unban button; traffic page updates after a request; check-connection result. Passkey-spec flake rule applies.
- Mutation check each guard test once (`if false &&`) to see it red.
- Optional live test (skipped unless env set): x402 testnet facilitator `/supported`.

## 16. Build order inside the single effort

0. **Client IP fix first, own commit**: `trusted_proxies`/`client_ip_headers`, `internal/clientip`, WAF/geoip/allowlist/gate on `client_ip`, golden + real-Caddy tests, release-note text. Independent value (repairs the WAF rate limit).
1. Migration 013 + `internal/trafficdb` + store types + registry skeleton + settings rows + `TestEveryKindHandled`.
2. Observer spike (wrapper vs native access log), then collector, observer module, catch-all, rollups, request log, retention, `/traffic` page with polling snapshot, the signal everything else reads.
3. Ban engine + module + `/bans`.
4. Challenge + under-attack (manual, then auto evaluator).
5. Access queue.
6. Alerts + event wiring from 3–5.
7. Proxy extras (failover, page/redirect kind, check-connection).
8. x402 (WAF vars, facilitator client, module, UI, docs warning).
9. Protection section on the site form, remaining pages polish.
10. MCP tools, docs, skill, version bump to 0.21.0, release notes (dropped: certificate alerts, queue fail modes, Telegram/Teams, SSE, `/metrics`).

Each step: failing test first, `make check` (single run, CLAUDE.md local-machine notes), commit on the feature branch; fast-forward `main` only at the end. Deploy to v1 only when asked, with the standard pre-upgrade DB copy; migration 013 rebuilds `sites`, so rehearse on a bee copy through a real Store first.

## 17. Risks and open implementation checks

| Risk | Mitigation | Confidence |
|---|---|---|
| x402 header names / requirement schema drift | contract tests against spec text; client behind an interface; testnet default | moderate |
| Turnstile hostname restriction breaks per-site challenge | form warning + docs; PoW default | high |
| `sites` rebuild on live data | 011 precedent, FK-off migrate, bee-copy rehearsal, child-row test | high |
| Request-log write volume | batching, 200k-row cap per site, drop counter, separate file | high |
| PoW difficulty calibration | per-site knob; calibrate on real phones | low until measured |
| Resolver disagreement | **[A1]** trusted_proxies rendered, one resolver, parity tests | high |
| Allowlist/gate matcher change alters Cloudflare-proxied sites | release note, golden diff reviewed, direct sites unchanged | moderate (`remote_ip` internals not read) |
| Observer breaks WebSocket/stream | **[A4]** `ResponseWriterWrapper`, WS + flush tests, native-log spike | moderate |
| Catch-all changes unmatched responses / ACME | **[B3]** ACME-staging and port-80 redirect test | moderate |
| traffic.db unavailable | features degrade, panel and sites unaffected, test | high |
| Polling load with many open tabs | ring read only, 2 s, nothing runs with no page open | high |
| Scope size (big-bang) | build order, per-step gate, cut list below | n/a |
| Memory growth under attack | all structures capped, fail open at cap | high |

## 18. Ponytail cuts applied (2026-11-25, approved)

SSE hub + `live.js` → htmx polling and server-rendered SVG; live dashboard strip and request-path diagram; Protection regroup; `/metrics`; unique-IP counts; traffic.db migration list; `ban_history`; `site_guard` 17 → 12 columns (`ch_bind_ip`, `ua_auto_block_pct`, `log_on`, `q_queue_ttl_s`, `q_admit_per_min`, `q_max_new_per_ip` removed; `backends` text added in place of a table); `guard_settings` (`ban_count_ratelimited`, `ban_reset_hours`, per-site log cap setting); auto-raise difficulty and single-use salt; queue token bucket, per-IP limit, poll budget, leave endpoint; x402 per-route `pay_to`, `token_requests`, `description`, facilitator test button; alerts `events` column, retries, worker pool, Mattermost/Teams/Telegram kinds; `page` + `redirect` merged into one kind, three templates → one; `site_backends` table; upstream error classification; check-connection rate limit; seven `internal/guard/*` packages → one; MCP 16 → 11 tools; fuzz targets 6 → 2; JSON export.

Not designed (requirements said no): TCP/UDP streams, OIDC, API tokens, NPM import, signed feeds, admin allowlist, header presets, i18n, in-process x402 facilitator, per-event/threshold alert override, CIDR manual bans.
