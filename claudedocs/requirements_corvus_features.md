# Requirements: Corvus-inspired features for ServanaGo

Status: requirements settled (brainstorm 2026-11-25). Design: `design_corvus_features.md` (v2, includes the ponytail cuts: where it differs from this file, such as polling instead of SSE, no `/metrics`, fewer alert kinds, one page kind, the design wins). Review: `analysis_corvus_design.md`. Roadmap: `docs/ROADMAP.md` M13. Source: `~/projects/corvus` (OpenResty/Lua/Redis/React), reviewed with codegraph.

## Goal

Bring Corvus's active defense, live observability and proxy conveniences into ServanaGo's native Caddy + SQLite stack, with a live, app-like panel UI. Delivered as ONE combined effort on one branch (user decision: "all the above, not in stages").

Concern recorded: this is a big-bang across Caddy modules, migrations, UI and MCP. Mitigation: internal build order by dependency (traffic signal → ban/under-attack/queue → alerts → UI), `make check` green at each internal commit, one release at the end.

## Settled decisions

| Topic | Decision |
|---|---|
| Scope groups | Active defense, Observability, Proxy extras, live UI |
| Out of scope | TCP/UDP streams (needs caddy-l4 dependency), OIDC SSO, API tokens, NPM import, signed virtual-patch feeds, admin allowlist, header presets (not selected) |
| State | In-memory in the Caddy module for queue line and live counters (lost on restart). Bans and traffic history persisted to SQLite. No Redis. |
| Challenge | Both per site: built-in proof-of-work (default, no third party) and Cloudflare Turnstile (only where Cloudflare is configured) |
| UI | Keep Go templates + htmx + Pico, no Node build step. Add live behavior (SSE + a small vendored JS chart/table layer). No React rewrite. |
| x402 | Per-site paywall option (HTTP 402 pay-per-request). Use cases: BOTH paid API paths and bot/crawler monetization (path scope plus optional bot-only mode). Facilitator: user wants ALL options researched incl. a private wallet (see "x402 facilitator research") |
| Auto-ban | Escalating: 15 min, 1 h, 24 h; default 10 responses of 401/403/404/429 in 60 s per IP and site |
| Non-JS visitors | Plain 403 under challenge (never 5xx) |
| Retention | 7 days raw request log, 90 days per-minute rollups, configurable in Settings |
| Alerts | Global destinations plus optional per-site override |
| Charts | Hand-rolled inline SVG, no chart library |
| Release | One release, 0.21.0 |

## Functional requirements

### F1 Traffic signal and monitor
- Caddy handler/log hook records per request: site, status, latency, bytes, client IP, path, outcome tag (pass, blocked, challenged, queued, banned).
- Per-site and global: req/s, status classes, p50/p95/p99, blocked/queued counts, unique IPs, over selectable ranges.
- Live page updated by SSE; per-site and per-path breakdown.
- Request log: search and CSV/JSON export, retention and rotation settings.
- Prometheus `/metrics` on the panel (token-protected, loopback by default).

### F2 Auto-ban
- Count configured status codes (default 4xx) per client IP and site in a window; over threshold = ban for a duration, with escalation for repeat offenders.
- Exemption CIDRs. Not counted: ACME challenge paths, gate/ml paths, challenge and queue responses, already-banned.
- IPv6 keyed per /64.
- Bans listed in the panel, manual add/remove, audited; survive restart (SQLite).
- Enforced in Caddy before the handler (same place as allowlist/country filter).

### F3 Under-attack mode
- Per site: off / on / auto. Auto turns on when req/s or blocked share exceeds a threshold, off after a cool-down; alerts on both transitions.
- Visitor must pass the challenge (PoW or Turnstile, per-site choice), receives a pass cookie with TTL, optionally IP-bound.
- Exempt: ACME paths, panel/gate endpoints, ban-exempt CIDRs.
- Order relative to existing layers: allowlist/gate/ban, WAF, then under-attack, then rate limit, basic auth, access queue.

### F4 Access queue (waiting room)
- Per site: capacity, admit rate, active TTL, queue TTL, max queue, max new entries per IP per minute, fail mode.
- Signed cookie; first visit sets cookie only (no server state) so cookie-less floods cannot fill the queue.
- Localized waiting page; live active/waiting counts in the UI; emergency release.

### F5 Alerts
- Destinations: Slack, Mattermost, Discord, Teams, Telegram, signed generic webhook; email via the existing Settings SMTP.
- Events: under-attack on/off, ban burst, backend down/up, certificate problems, queue full.
- Secrets sealed with `secretbox`; test-send button; audit entries.

### F6 Proxy extras
- Multi-backend per proxy/node site: round-robin, passive failover (Caddy native), shown in site form.
- Maintenance / coming-soon / parked page: site without upstream serving a chosen status and built-in or custom HTML; custom locations keep proxying.
- Redirect hosts: 301/302/303/307/308, keep-path option, TLS like other hosts.
- Check connection: before saving, test an upstream from the host (DNS, port, TLS) and show why recent 502/504 happened.

### F7 x402 paywall (per site)
- Site or path option: unauthenticated request gets HTTP 402 with payment requirements; on valid payment proof the request proceeds.
- Settings: price, asset/network, receiving wallet, facilitator URL, path scope, bypass for panel/ACME paths.
- Open: facilitator trust, replay protection and settlement verification need design review (see questions).

### F8 Live UI
- Overview dashboard with live stat cards; live tables (bans, queue, requests) without full reload.
- Inline edit and instant feedback on toggles (under-attack, ban/unban, release queue).
- Light/dark kept; i18n NOT required (Corvus has 8 languages; ServanaGo is English).

### F9 MCP and docs
- MCP tools for each mutation and read (bans, under-attack toggle, queue stats, traffic summary, alerts, redirect/maintenance, x402 settings). New verbs must satisfy `TestAgentSkillsMatchTheMCPTools`.
- Update `docs/sites.md`, `docs/mcp.md`, `llms.txt`, README feature line, ROADMAP, `skills/servanago-sites/SKILL.md`.

## Non-functional requirements
- Native host only; no new runtime dependency (no Redis, no Node build, no caddy-l4).
- Hot-path cost: counters are lock-light/sharded; no SQLite write per request (batched flush).
- Memory bounded: capped IP table, capped queue, capped in-memory log ring.
- All schema via new `NNN_*.sql` migrations; self-heal list untouched; bump `TestMigrationsIdempotent`.
- Secrets never logged; client IP trusted from `CF-Connecting-IP` only when peer is a Cloudflare node (existing geoip rule).
- Never ban or challenge the panel's own host, ACME, or loopback admin traffic.
- Tests: pure renderers golden-tested, real-Caddy integration for each handler order (`TestGateWithIPAllowlistIsEitherOr` pattern), fuzz on any new helper input, e2e for UI toggles.
- Production is `v1` with real data: deploy only when asked.

## Acceptance criteria (summary)
1. A client generating N 4xx within the window is banned, blocked at Caddy, visible and removable in the UI, and still banned after restart.
2. Under-attack "on": a request without a pass gets the challenge; solving it admits; ACME and exempt paths unaffected. "auto" flips on at the threshold and back off, with two alerts.
3. Queue: with capacity C, the (C+1)th visitor sees the waiting page and is admitted in order as slots free; cookie-less flood creates no server state.
4. Traffic page shows live req/s and percentiles within 2 s of traffic; export matches the search filter.
5. Site with two backends keeps serving when one dies; maintenance page returns the chosen status; redirect host redirects with path kept as configured.
6. x402 site returns 402 without proof and passes with valid proof; panel and ACME paths never 402.
7. `make check` green; no migration edits to existing files.

## x402 facilitator research (context7, /x402-foundation/x402, /websites/cdp_coinbase_x402; 2026-11-25)

Protocol: server answers 402 with payment requirements; client retries with a signed payload; a facilitator `Verify`s and `Settle`s on-chain (EIP-3009 on EVM, Solana SVM). The seller only needs a receiving address. A Go SDK exists (`github.com/x402-foundation/x402/go/v2`, `x402http.NewHTTPFacilitatorClient{URL}`), so the Caddy handler can reuse it instead of hand-rolling the protocol (new dependency, needs vetting).

| Option | What it is | Cost / trust | Fit |
|---|---|---|---|
| Hosted: CDP (Coinbase) | Base + Solana mainnet, KYT/OFAC checks | 1,000 settlements/month free, then $0.001 each; verify free; needs CDP API key | Most production-ready; third party sees all payments |
| Hosted: free public (PayAI, Dexter, Mogami, Stellar, Celo, Corbits, others) | No or minimal account | Free; varying maturity; you trust their uptime and honesty | Cheap to start; vendor risk |
| Testnet `x402.org/facilitator` | Base Sepolia / Solana Devnet | Free, test funds only | Dev and e2e only |
| Self-hosted, private wallet | Run an open-source facilitator (Mogami Docker, x402-rs, Fireblocks open-source, AlgoVoi self-host) or build `Verify`/`Settle` in-process with ServanaGo's own hot wallet paying gas | No third party, no per-tx fee; YOU hold a funded key (gas), run an RPC endpoint, handle nonce/replay, reorgs and key custody | Max control; highest risk and work. Key must be sealed like other secrets, never logged |
| Fireblocks facilitator | Settlement from a Fireblocks vault; keys never leave it | Enterprise custody cost | Only if already a Fireblocks user |

Notes: the receiving wallet (`payTo`) can always be the user's own private wallet whatever facilitator is used; the facilitator only submits transactions, it does not hold the funds. "Private wallet" therefore has two meanings: (a) own receiving address with a hosted facilitator (low risk), (b) own facilitator with a gas-paying hot key (high risk). Recommendation to settle at design time: build the handler against a configurable facilitator URL (works for every row above), ship (a) first, treat in-process self-verification as an optional later mode.

## Answers to former open questions (2026-11-25)
- x402 facilitator: configurable facilitator URL plus the admin's own `payTo` wallet. No in-process facilitator, no hot key in ServanaGo (deferred).
- x402 network/asset: USDC on Base only (mainnet `eip155:8453`; Base Sepolia for dev/e2e).
- x402 bot-only mode identifies a bot by ANY of: admin-editable user-agent list, no challenge pass, WAF/Coraza anomaly signal. Cloudflare bot score not used.
- x402 payment grant: per-route choice, either one request per payment (nonce recorded to block replay) or a short-lived signed access token (N minutes or M requests).
- PoW default difficulty: medium (~0.5-1 s on a phone), per-site low/medium/high; auto under-attack may raise it.
- Protection UI: one ordered "Protection" section per site form listing every layer (allowlist, country, gate, ban, WAF, under-attack, rate limit, basic auth, x402, access queue); existing field names and routes unchanged.
- Alert override: per site, destinations only; events and thresholds stay global.

## Open questions (remaining)
None blocking. Design-time checks: vet the x402 Go SDK dependency (license, size, maintenance) versus a minimal in-house verify/settle client; confirm the layer order with real-Caddy tests.

## Next step
`/sc:design` for the Caddy module layout, SQLite schema and SSE transport, once the open questions are answered.
