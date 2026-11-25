# Analysis: design_corvus_features.md against existing code (2026-11-25)

Status: findings applied to `design_corvus_features.md` v2 (tags A/B/C there) after Brian's four decisions (trusted proxies + `client_ip` allowlist, separate `traffic.db`, observed 404 catch-all, new ban defaults). Related: `requirements_corvus_features.md`, `docs/ROADMAP.md` M13.

Scope: static review, no code changed. Evidence = file:line read this session.

## Verdict
Design holds structurally (same Install/registry shape as geoip/gate, same migration-rebuild precedent as 011). Eight findings need design changes before `/sc:workflow`; two are pre-existing bugs the design would inherit.

## Findings

### A. High

**A1. Client IP is wrong behind Cloudflare today, and the design's fix does not work.**
- `render.go:~137` builds `srv0` with only `listen` and `routes`: no `trusted_proxies`, no `client_ip_headers`.
- Caddy `determineTrustedProxy` (server.go:1453) then sets `client_ip` to the socket peer.
- `caddywaf.clientAddress` (`serve.go:96`) reads exactly that var. The WAF rate limiter (`ratelimit.go:135`), WAF events and the `connector` all key on the Cloudflare edge IP when a record is proxied. The geoip module is the only place with the `CF-Connecting-IP` logic (`caddygeoip.clientOf`).
- Design §14 says `clientip.Of` should "first honor Caddy's `ClientIPVarKey`". That var is always the peer, so the fallback never runs and bans would hit Cloudflare nodes (a self-inflicted outage for every visitor behind that node).
- Fix: render `trusted_proxies` (static Cloudflare ranges, already listed in `caddygeoip.cloudflareRanges`) plus `client_ip_headers: ["CF-Connecting-IP"]` into `srv0`. Then `client_ip` is correct for WAF, ban, challenge, queue and x402 and `clientip.Of` just reads it. Keep geoip's private/CGNAT skip rules in `clientip`. This also repairs the WAF rate limit. Needs a golden-test update and a real-Caddy test with a forged header from a non-Cloudflare peer.
- Same class: the allowlist and gate use the `remote_ip` matcher (`render.go:294`). Behind Cloudflare that matches edge IPs. Pre-existing; design §2 ("skip layers via the gate's `not remote_ip` matcher") copies it. Decide whether to switch to the `client_ip` matcher once trusted proxies exist (behavior change for existing sites; needs Brian's call). Confidence: high on `client_ip`, moderate on `remote_ip` internals (matcher body not read).

**A2. `request_log` and rollups in the main DB will bloat every backup and upgrade copy.**
- Store is one file, WAL, `busy_timeout 5000` (`store.go:43-47`). Upgrades copy it (`servanago.db.pre-<ver>`), `repairLegacy` does `VACUUM INTO`, the backup job snapshots it, event-restore plans snapshot it.
- 200k rows/site × ~250 B ≈ 50 MB/site; ten busy sites ≈ 500 MB copied on each upgrade, plus write contention with `apply` transactions.
- Fix: put `request_log`, `traffic_rollup` (and `ban_history`) in a second file `<DATA_DIR>/traffic.db`, own handle, own tiny migration list, own prune. Main DB keeps only config and `bans`. Loses nothing (history is disposable). Update the design's §4 and the backup/upgrade docs.

**A3. Two new site kinds touch ~25 places the design only gestures at ("grep every Kind").**
Read this session, non-test: `store/models.go:109,115,223`; `web/siteform.go:54,147-151,169-196,305,472-480,523,575,794,846,863`; `web/runtime.go:69-110,172`; `web/health.go:42-49`; `web/reference.go:80,147`; `web/siteview.go:497`; `web/mcp.go:245`; `helper/runtime.go:239-462`; `probe.upstreamAddr`. The `sites` CHECKs also need new OR clauses: the big per-kind CHECK (011 lines 45-60), `site_user`, `public_dir`, `php_*`.
- Cheaper alternative worth one decision: keep kind set unchanged and make `page`/`redirect` a **`sites.kind='static'`-free** representation? Not possible: static requires `static_root`. So the rebuild stands, but the design should list this blast radius explicitly and add a table test "every kind in the CHECK has a case in `siteHandler`, `siteform`, `health`, `reference`, `siteview`" (a missed case today fails silently).

**A4. Observer wrapping the ResponseWriter can break WebSocket, SSE and streaming.**
Proxy sites carry WebSockets and `Stream` (`flush_interval -1`). The observer must embed `caddyhttp.ResponseWriterWrapper` (gives `Unwrap`, `Flush`, `Hijack`, `ReadFrom`) and count bytes without buffering. `caddywaf` already has an interceptor; do not copy it. Add tests: WS upgrade through the observer, a streamed response with `Flush`, status capture when the handler returns an error. Alternative to evaluate in the first spike: Caddy's native access log (`servers.srv0.logs`) with a custom writer module avoids wrapping entirely; cost is getting `sg_outcome`/slug into log fields. Default stays the observer unless the spike shows a clean field path. Confidence: high on the risk, moderate on the alternative.

### B. Medium

**B1. SSE through the panel.** `newUIServer` sets `WriteTimeout: 60s` (`main.go:218`). The panel host is itself proxied by Caddy (`render.go` UIHost route). Needed: `SetWriteDeadline(time.Time{})` per stream (design has it), plus confirm every panel middleware that wraps the writer exposes `Unwrap`/`Flush` (none found in `auth.go`/`web.go` by grep, `security`/`csrf` not read), plus Caddy `reverse_proxy` flushing `text/event-stream` immediately (believed automatic; verify with the e2e). Also the idle timeout (120 s) is fine with a 15 s heartbeat.

**B2. Auto-ban default will ban legitimate visitors.**
Default codes `401 403 404 429`, 10 per 60 s per IP+site. A normal page with several missing assets (404s) or a WAF-blocking CRS false-positive burst (403s, `block` mode) trips it, and 429s from the existing WAF rate limit feed straight into a ban. Corvus keeps this off by default. Design's `ban_on DEFAULT 0` is right; change defaults: codes `401 403 429` (404 opt-in), threshold 20, and exclude responses the WAF rate limiter produced (outcome var `ratelimited`) or make them an explicit choice. State it in the UI help text.

**B3. Unknown-host traffic is invisible and unbanned.**
`Render` emits one route per site hostname plus the panel host, with no catch-all (`render.go:~76-100`). Scanners probing by IP get Caddy's no-route response and never reach the observer, so the most common scan signal feeds nothing. Option for the design: one catch-all route, `servanago_traffic` with slug `""` + `servanago_ban`, answering 404 (or closing), with its own counter "unknown host". Cheap, but it changes what every unmatched request returns, so it needs Brian's yes. Note in design as an explicit decision, not an assumption.

**B4. Disabled sites bypass everything.** `siteHandler` returns the static 503 first (`render.go:204`). No traffic stats, no bans for scanners hitting a disabled site. Acceptable; state it.

**B5. Turnstile reuse is not just "use the existing keys".** `turnstileVerifier.Verify` requires `Action == "login"` and `Hostname == panel host` (`turnstile.go:~96`). Parameterize action/hostname for the challenge; widget hostname allow-list on Cloudflare must include each site (design already flags).

**B6. Key derivation.** Gate derives per-purpose keys with HKDF over `SECRET_KEY` (`gate.go:336`). Challenge/queue/x402 cookies must do the same with distinct info labels, never reuse the secretbox key or each other's.

**B7. probe.Monitor already exists.** Design said "reuse if it fits". It fits with edits: it keys by site ID guarded by address (`probe.go:60-150`), probes only `HasUpstream` sites, one address per site. Needed: probe `site_backends` too, add transition detection (up→down/down→up) to emit alerts, and reuse `probe.TCP` for check-connection. Do not write a second dialer.

### C. Low / consistency

- **C1.** The WAF event writer (`caddywaf/events.go`, chan 4096, cap 10k, `StartEventWriter(sink)`) is the in-repo precedent for the non-blocking batched writer. Design should cite and mirror it (same drop-and-count behavior) rather than reinvent.
- **C2.** `toolLike` regex (`skills_test.go:15`) already includes `check` and `start`; all 16 proposed tool names fit with no change. Good; keep.
- **C3.** Rowid reuse: design keys by slug in registry and rollups. `site_guard`/`site_x402` use `site_id` with `ON DELETE CASCADE`, consistent with `waf_exclusions`.
- **C4.** `repair.go`'s `kindAllowsCGI` regexp only checks `'cgi'` presence; adding kinds does not break it. Confirm with the existing repair tests after the 013 rebuild.
- **C5.** `store_test.go:41` hard-codes `v != 12`; `repair_test.go:122` and `migrate_test.go:60` reference versions. Bump all (design lists two; there are three places).
- **C6.** ml host gets observer + ban only (design §2). Because `siteHandler` branches on `host == r.MLHost()` before the layers, that branch must be edited separately; add to the layer-order golden test.
- **C7.** Alias hosts: each hostname is its own route; passes/cookies are host-only, so a visitor solves the challenge once per hostname. Acceptable; document.
- **C8.** Allowlisted peers skip layers 4-7 per design, but an allowlisted address with `GateMode` empty only ever sees 403 for others. Fine; the skip matters only with gate. Keep the test.

## What the code already confirms (no change)
- Service-install pattern (`caddygeoip.Install`, `caddygate.Install(...)` in `cmd/servanago/main.go:104,147`): guard registry fits.
- 011's rebuild + FK-off `migrate()` is the right precedent for 013.
- Fast-path condition (`render.go:279`) is real and needs `r.Guard.Any()` as designed.
- `siteHandler` is called once per hostname, so observer config must pin slug + host (design does).
- Layer insertion points in `sub` are exactly where the design places them.

## Required design edits (proposal, awaiting your OK)
1. §14/§3: add `trusted_proxies` + `client_ip_headers` rendering; `clientip.Of` reads `client_ip`; test with forged header.
2. §4: move `request_log`, `traffic_rollup`, `ban_history` to `traffic.db`.
3. §11: list every kind touch point; add exhaustive-kind test.
4. §5/§2: observer built on `ResponseWriterWrapper`; WS/flush/error tests; spike native access log first.
5. §6: new ban defaults; `ratelimited` outcome.
6. New §: unknown-host catch-all decision.
7. §7: Turnstile verifier parameterization; HKDF labels for all cookie keys.
8. §10/§11: backend alerts via extended `probe.Monitor`.

## Decisions needed from you
1. Render Cloudflare `trusted_proxies` into srv0 (fixes WAF rate limit and makes bans safe) — and switch allowlist/gate matching to `client_ip`? (behavior change for existing sites)
2. Separate `traffic.db` file for request log and rollups?
3. Add an observed catch-all for unknown hosts (changes unmatched-request response)?
4. Ban defaults: exclude 404 and WAF-rate-limit 429s by default?
