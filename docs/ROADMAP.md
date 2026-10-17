# ServanaGo roadmap

ServanaGo is becoming a lightweight, self-hosted web runtime manager: a Go control plane with a web UI, one embedded Caddy ingress, SQLite state and systemd supervision for application processes. It is not a hosting control panel: no billing, resellers, database admin, container orchestration or CI/CD platform.

Today (after M1) the code is still the inherited baseline in shape: a single-process Caddy front end that publishes reverse-proxy routes under domains you add, with optional Cloudflare integration (DNS-01 certificates and A/AAAA records). Everything marked Next or Planned in the table is not shipped.

## Decisions

- **No data migrations yet.** The app has no deployed data, so the schema lives in a single `001_init.sql` that is edited in place, with no upgrade paths or compatibility shims. Numbered migrations (`002`+) start with the first release that has data worth keeping.
- **Native host only.** Debian 12+ and Ubuntu 22.04+ with systemd >= 252. No container image in v1.
- **TLS.** HTTP-01 / TLS-ALPN by default; Cloudflare DNS-01 stays as an optional issuer (wildcards, firewalled hosts).
- **Admins.** Multiple, all equal. TOTP, backup codes and passkeys become per user.
- **Magic-link site gate and Turnstile** are kept. The gate is re-keyed from route to site and hostname.
- **Runtimes are detected, never installed.** ServanaGo reports installed PHP-FPM and Node.js versions and shows the install command; the admin runs it.
- **One Caddy ingress** for every site. systemd supervises application processes. Caddy does not install or supervise runtimes.
- **Static roots may be under `/home`.** Existing `public_html` directories must work, so the root is an admin-supplied absolute path (denylist for `DATA_DIR`, `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/`; optional `SERVANAGO_STATIC_ROOTS` allowlist). The control-plane unit therefore must not set `ProtectHome=yes` (M3). M4 later moves managed sites to `/srv/servanago/sites`.
- **Unprivileged UI.** The web UI never runs as root. Privileged work goes through a small root helper (the same binary, a `helper` subcommand) on a Unix socket, authenticated with `SO_PEERCRED`, accepting a closed set of typed actions. It takes no free-form strings and re-validates every input: slugs `^[a-z][a-z0-9-]{1,31}$`, paths confined under managed roots after `EvalSymlinks`, unit names built only as `servanago-<slug>.service`, unit and pool files written from the helper's own templates.
- **Build and install commands** run as the site's unprivileged user, never root.
- Unix-user separation is **not** a sandbox for mutually untrusted tenants. ServanaGo does not claim multi-tenant security.

## Layout (target)

| Path | Contents |
|---|---|
| `/etc/servanago/` | environment file, helper policy |
| `/var/lib/servanago/` | SQLite database, Caddy storage |
| `/var/log/servanago/` | logs (service logs stay in journald) |
| `/srv/servanago/sites/<slug>/` | `public/`, `app/`, `logs/` per site |
| `/run/servanago/<slug>.sock` | per-site sockets, mode 0660 |
| `servanago-<slug>.service` | one systemd unit per managed application |

## Apply path (target)

validate spec (runtime provider) -> write SQLite in a transaction -> helper writes and verifies host artifacts (`systemd-analyze verify`, `php-fpm -t`) and starts services -> render full Caddy JSON -> `caddy.Load` -> commit. Any failure rolls back the database and restores last-known-good host files. SQLite is the desired state; a reconciler converges the host to it at startup. Services start before the Caddy load, so the worst case is a brief 502, never a route to nothing.

## Milestones

| # | Milestone | Status |
|---|---|---|
| M0 | Fork and rebrand: rename, brand and dark theme, remove Docker discovery, presets and container packaging, docs | Done |
| M1 | Decouple Cloudflare: optional token, HTTP-01 / TLS-ALPN default, public IPv4 and IPv6 (dual-stack) record targets, one initial schema | Done |
| M2 | Site model (static, proxy) and renderer rewrite, golden tests | Done |
| M2.5 | Multi-admin: users table, per-user TOTP, backup codes and passkeys, `reset` per user, audit actor | Done |
| M3 | Native packaging: systemd unit for the control plane, `.deb`, install script, directory layout above, `DATA_DIR` default | Done |
| M4 | Privileged helper: socket, peer credentials, typed actions, input fuzzing | Done |
| M5 | Apply v2: reconciler, last-known-good restore, audit events, service status and journald logs in the UI | Planned |
| M6 | Node.js provider: dedicated user, sandboxed unit, port or socket allocation, explicit install/build/start commands, health check | Planned |
| M7 | PHP-FPM provider: per-site pool and socket, `php_fastcgi` JSON expansion, multiple installed versions | Planned |
| M8 | Hardening: privilege boundaries, paths, sockets, secrets, crash and interrupted-update tests, backup and restore docs | Planned |
| M9+ | Gate re-keyed to sites; FrankenPHP; CGI/FastCGI; Ruby, Python, Go services | Deferred |

## Explicitly deferred

Multi-tenant isolation claims, deployment releases and rollback, Git integration, database administration, a plugin marketplace, installing runtimes from the UI, RPM-family distributions.

## Known gaps carried from the baseline

- IPv6 is dual-stack only: an AAAA record needs the IPv4 A record beside it, so an IPv6-only site is not supported. `CLOUDFLARE_API_TOKEN` is optional: without it a domain is added by hand and certificates are per host over HTTP-01.
- Hostnames are free FQDNs (M2). Without Cloudflare there is no zone lookup, so a hostname that matches no domain added by hand simply has none: it is served with its own HTTP-01 certificate and gets no DNS record.
- The mark is shipped as processed PNGs; a traced vector replaces them later (`docs/brand/README.md`).
- Form field borders are about 1.7:1 against the page; WCAG 1.4.11 asks for 3:1.
