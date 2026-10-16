# ServanaGo roadmap

ServanaGo is becoming a lightweight, self-hosted web runtime manager: a Go control plane with a web UI, one embedded Caddy ingress, SQLite state and systemd supervision for application processes. It is not a hosting control panel: no billing, resellers, database admin, container orchestration or CI/CD platform.

Today (after M0) the code is the inherited baseline: a single-process Caddy front end that publishes reverse-proxy routes under Cloudflare-managed domains. Everything below the "Done" line is planned, not shipped.

## Decisions

- **Native host only.** Debian 12+ and Ubuntu 22.04+ with systemd >= 252. No container image in v1.
- **TLS.** HTTP-01 / TLS-ALPN by default; Cloudflare DNS-01 stays as an optional issuer (wildcards, firewalled hosts).
- **Admins.** Multiple, all equal. TOTP, backup codes and passkeys become per user.
- **Magic-link site gate and Turnstile** are kept. The gate is re-keyed from route to site and hostname.
- **Runtimes are detected, never installed.** ServanaGo reports installed PHP-FPM and Node.js versions and shows the install command; the admin runs it.
- **One Caddy ingress** for every site. systemd supervises application processes. Caddy does not install or supervise runtimes.
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
| M1 | Decouple Cloudflare: optional token, HTTP-01 / TLS-ALPN default, public hostnames and IPs, DNS sync behind a flag | Next |
| M2 | Site model (static, proxy) and renderer rewrite, golden tests | Planned |
| M2.5 | Multi-admin: users table, per-user TOTP, backup codes and passkeys, `reset` per user, audit actor | Planned |
| M3 | Native packaging: systemd unit for the control plane, `.deb`, install script, directory layout above, `DATA_DIR` default | Planned |
| M4 | Privileged helper: socket, peer credentials, typed actions, input fuzzing | Planned |
| M5 | Apply v2: reconciler, last-known-good restore, audit events, service status and journald logs in the UI | Planned |
| M6 | Node.js provider: dedicated user, sandboxed unit, port or socket allocation, explicit install/build/start commands, health check | Planned |
| M7 | PHP-FPM provider: per-site pool and socket, `php_fastcgi` JSON expansion, multiple installed versions | Planned |
| M8 | Hardening: privilege boundaries, paths, sockets, secrets, crash and interrupted-update tests, backup and restore docs | Planned |
| M9+ | Gate re-keyed to sites; FrankenPHP; CGI/FastCGI; Ruby, Python, Go services | Deferred |

## Explicitly deferred

Multi-tenant isolation claims, deployment releases and rollback, Git integration, database administration, a plugin marketplace, installing runtimes from the UI, RPM-family distributions.

## Known gaps carried from the baseline

- Every published address must currently be private IPv4 or CGNAT (lifted in M1). `CLOUDFLARE_API_TOKEN` is already optional: without it a domain is added by hand and certificates are per host over HTTP-01.
- Without Cloudflare there is no zone lookup, so a site must be a single label under a domain added by hand; hostnames become first-class in M2.
- `DATA_DIR` defaults to `/data`, a container path (changed in M3).
- The mark is shipped as processed PNGs; a traced vector replaces them later (`docs/brand/README.md`).
- Form field borders are about 1.7:1 against the page; WCAG 1.4.11 asks for 3:1.
