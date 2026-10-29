# Next features (brainstorm, 2026-10-28)

Recorded as given, one at a time. Not settled yet; questions below drive each toward a `requirements_*` spec. Nothing designed or scheduled.

## 1. Country blocking (optional)
Settled with Brian 2026-10-28:
- Scope: each site gets its own optional country rule (site form), plus one global rule covering everything else including the WebUI.
- Modes: per scope, the admin picks denylist (block these countries) or allowlist (allow only these). Denylist default = feature off, empty list.
- Geo source: MaxMind GeoLite2-Country read from a local `.mmdb` path — **no downloader, no stored MaxMind credentials**: geoipupdate 6.1.0 (`geoipupdate.timer`) runs on bee and comes with the v1 deploy instructions (`apt install geoipupdate`, license key in `/etc/GeoIP.conf`), so ServanaGo only reads the file it keeps fresh. Changed with Brian 2026-10-29, supersedes the planned auto-download + sealed account key.
- Open design details (I decide during design): blocked response shape (403 default), allowlist semantics for unknown countries (not on the list = blocked), where the GeoIP check sits relative to the gate/allowlist/bypass routes, and how the mmdb reader handles Caddy-embedded traffic.

## 2. Postmark webhook handler → LMTP, per domain, own UI (optional)
Adapted from the gopmstall plan (`~/projects/gopmstall`, a separate sidecar project for Postmark + Stalwart; its `REQUIREMENTS.md`/`ARCHITECTURE.md` are the reference for the bridge design). gopmstall stays a separate repo.

Settled with Brian 2026-10-28:
- Servanago stays a bridge only: external mail server on the LMTP end, no mailbox store, no IMAP/JMAP.
- Full provisioning per domain (gopmstall FR1/FR5): with the admin's Postmark account token, Servanago creates/adopts the Postmark server + domain, sets webhook URLs and RawEmail, and writes MX/SPF/DKIM/Return-Path through the DNS CRUD feature (feature 3), then verification-watches. Provisioning must look for existing Postmark domains/servers first, warn they exist, and update only on explicit approval.
- Takeover scope: inbound webhook → LMTP (FR2, raw payload, dedupe on Postmark MessageID + recipient, per-recipient LMTP result mapping) plus the events endpoint with bounce DSN rebuild and event store (FR4). Outbound relay management for the mail server (FR3) stays out.
- LMTP target: one global endpoint in Settings (host:port, optional STARTTLS/auth), overridable per domain.
- UI: an ops dashboard Mail page — webhook URL + per-domain credential shown once, Postmark verification states, DNS record states, last inbound time, per-domain counters (received/delivered/deduped/rejected/fallbacks), recent deliveries and events; domain row links into the DNS CRUD view.
- Postmark docs reference: https://postmarkapp.com/llms.txt
- Design details later: webhook endpoint serving under Caddy (basic auth per domain, hashed credentials — gopmstall FR2 security notes), payload size limit, spam handling per Postmark verdict, DSN sender `MAILER-DAEMON@<domain>`.

## 3. Cloudflare DNS management with full CRUD
Today Servanago writes only its own records (A/AAAA per hostname via dnssync, TXT for DNS-01, the 0.7.0 ml. records). This adds arbitrary-managed DNS CRUD through the Cloudflare API with a UI. The production token is account-owned with Zone:Read + DNS:Edit; a failed token leaves stale `_acme-challenge` TXT rows.

Settled with Brian 2026-10-28:
- Build order: DNS CRUD first (wizard and mail features build on it).
- Zones: all token-visible zones, not just ones matching `domains` rows.
- Fully independent view: Servanago-managed rows get no edit restrictions. A "managed" badge is information only — reconcile keeps owning its rows, so an edit to an A/AAAA/ml. row is rewritten or re-added at the next site save / startup. Accepted as-is; no reconcile changes.
- Per repo convention (assumed unless Brian says otherwise): new page + matching MCP tools, every mutation audited, delete behind `hx-confirm`. Writable types: the common eight (A, AAAA, CNAME, TXT, MX, SRV, CAA, NS), per Brian 2026-10-28; exotic types are listed read-only. Record editor exposes the attributes Cloudflare returns (TTL, proxied, comment).

## 4. Domain on-boarding wizard (parked until 1–3 ship)
Composes existing features step by step; invents none. Step list (Brian picked all of these):
1. Site + hostname + DNS records (A/AAAA, proxied flag, via DNS CRUD) + TLS mode choice.
2. Zone adopt/check + optional Postmark enrollment (server, SPF/DKIM/MX records, verification-watch) via the mail feature's provisioning.
3. Gate + access (magic-link gate, IP allowlist, Turnstile, snippets, site user) as wizard steps.
4. Runtime selection (php/node/frankenphp/static/proxy, version, install/build/start commands) with pre-flight runtime checks before anything is created.

All steps optional per site. Design starts after 1–3 land.

## 5. Site virus scanning (added 2026-10-28)
Build order: after DNS CRUD, before country blocking. Settled with Brian 2026-10-28:
- Engine: ClamAV via its clamd Unix socket (daemon owns signature updates); Servanago never installs or updates ClamAV itself, matching the runtimes-are-detected rule.
- Triggers, all three: on-demand scan per site (site page + MCP tool), a scheduled sweep (daily, time configurable) over enabled sites, and a scan pass inside the site-backup flow recorded in the backup manifest.
- Scope: the served webroot only — static/PHP/FrankenPHP doc root plus the site user's `public_dir` when present. Node proxy sites without a doc root are skipped.
- On a hit: quarantine — move the infected file into a quarantine dir under `DATA_DIR` (nothing else in the tree is touched), with one admin click to restore or ignore, audited.
- Notify on hits: ntfy POST at priority `urgent` (one Settings row: server URL + topic + optional access token) and email through the existing Settings SMTP row (v1 may point that at Postmark's SMTP).
- Results surface on a scan page (hits, sweep history), site-page badge, MCP tools, audit log; per repo convention.
- I-assumed-during-design details: clamd socket path configurable with the Debian default, max scan file sizes left to clamd's own config, no per-site scan toggle (sites scan whenever the scanner is configured).