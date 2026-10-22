# ServanaGo — Requirements

Status: current as of v0.5.1 plus the spec-panel hardening branch. This file replaces the baseline inherited from Caretakarr (route model, private-IP-only records, mandatory Cloudflare, `/data`). Scope, milestones and per-milestone notes are in [`ROADMAP.md`](ROADMAP.md); mechanisms are in [`DESIGN.md`](DESIGN.md). License: MIT.

Each requirement has an ID. A test, a spec, or a manual check that cites the ID proves it; "Verified" says how far that has gone.

## Goal

One native Linux host publishes several kinds of web sites (reverse proxy, static, Node.js, PHP-FPM, FrankenPHP, FastCGI, CGI) behind one embedded Caddy, with valid HTTPS, managed from a web UI. SQLite is the desired state. It is not a hosting control panel and makes no multi-tenant security claim.

## Actors

- **Administrator**: an equal member of the `users` table. Signs in to the UI, MCP clients act with a server-wide token.
- **Visitor**: a browser reaching a hosted site; may be gated by a magic link.
- **Control plane**: the unprivileged `servanago` process (UI, Caddy, SQLite).
- **Helper**: the root `servanago-helper` process, reachable only over a Unix socket.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SERVANAGO_HOST` | required | hostname of the UI |
| `ACME_EMAIL` | required | Let's Encrypt contact, a bare address |
| `DATA_DIR` | `/var/lib/servanago` | SQLite, Caddy storage, last-known-good config |
| `UI_LISTEN` | `127.0.0.1:8080` | local UI listener |
| `HTTP_PORT` / `HTTPS_PORT` | 80 / 443 | Caddy |
| `SERVANAGO_HOST_IP`, `SERVANAGO_HOST_IP6` | unset | public record targets (dual-stack) |
| `CLOUDFLARE_API_TOKEN` | unset | optional: DNS records and DNS-01 certificates |
| `ADMIN_USER`, `ADMIN_PASSWORD` | `admin`, unset | create the first administrator when none exists |
| `REQUIRE_2FA` | true | `false` opts out |
| `SERVANAGO_STATIC_ROOTS` | unset | optional colon-separated allowlist for static roots |
| `SERVANAGO_SECRET_KEY` | unset | seals SMTP password and TOTP seeds |
| `SERVANAGO_MCP_TOKEN` | unset | enables `/mcp`; at least 32 characters |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET` | unset | optional Turnstile on sign-in |
| `ACME_ISSUER`, `ACME_STAGING`, `ACME_RESOLVERS`, `ACME_PROPAGATION_*` | see code | certificate tuning |

## Functional requirements

### Sites and ingress

- **FR-1 Site kinds.** A site has one or more free FQDN hostnames and one kind: `proxy`, `static`, `node`, `php`, `frankenphp`, `fastcgi`, `cgi`. Hostnames ending in `.local`, `.internal`, `.home.arpa` and IP literals are refused.
- **FR-2 Apply path.** Every change: validate, write SQLite in a transaction, render the full Caddy JSON, `caddy.Load`, commit. If Caddy rejects the config, the previous config stays live and the database change is rolled back. Caddy is never changed piecemeal.
- **FR-3 Startup.** If the stored config fails to load, the last-known-good file is loaded; failing that, a bootstrap-only config. A banner shows the reason. The process never crash-loops on bad rows.
- **FR-4 Runtime units.** For node, php, frankenphp, cgi and static-with-user sites, the helper installs the user and the systemd unit after the database commit. A failure is reported to the administrator and recorded in the audit log; the stored site stays as desired state.
- **FR-5 Startup reconcile.** At startup every runtime site's user and unit are applied again from SQLite, so a unit lost with the host or a save made while the helper was down converges without another save. A failure for one site is logged and does not stop the others.
- **FR-6 Per-site controls.** Enable/disable, CIDR allowlist, basic auth, magic-link gate, attached Caddyfile snippets (handler allowlist; `/.well-known/*` bypasses them).
- **FR-7 Certificates and DNS.** HTTP-01/TLS-ALPN by default. With a Cloudflare token: DNS-01 and A/AAAA records per hostname. An AAAA record needs its A record.

### Administration

- **FR-8 Authentication.** Username and password (bcrypt), session cookie tied to user and epoch (removal, password change and second-factor reset end that user's sessions), 5 attempts per client address per 15 minutes. Optional TOTP, backup codes, passkeys; Turnstile optional.
- **FR-9 Open mode.** While no administrator exists the UI is open, but only to a client on this machine. A request whose client address is not loopback (`X-Forwarded-For` is honoured only from a loopback peer) gets 403 with instructions to create the first administrator locally.
- **FR-10 Audit.** Every mutating action writes an audit row naming the actor (`user`, `mcp token`, or `system`).
- **FR-11 MCP.** Off unless `SERVANAGO_MCP_TOKEN` is set. Writes run the UI's own handlers, so the same validation applies.

### PHP

- **FR-12 PHP from source.** Builds are fetched by checksum and signature, compiled in sandboxed units, and installed root-owned under `/opt/servanago/php`. Sites follow a branch label (`8.4`) or pin an exact build (`8.4.27-1`).

## Security requirements

- **SR-1 Helper boundary.** The helper accepts only root or the `servanago` uid (`SO_PEERCRED`), one request per connection, a closed set of typed actions, strict JSON, at most 64 KiB.
- **SR-2 Helper input.** The helper re-validates everything and does not rely on the web layer: slug `^[a-z][a-z0-9-]{1,31}$`; roots clean, absolute, free of whitespace and `% $ \ " '`; roots under `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/boot`, `/var/lib/servanago`, `/run/servanago` and `/` itself are refused; unit and pool files come from the helper's templates only.
- **SR-3 Helper liveness.** A peer must send its request within 10 seconds. Actions for the same slug run one at a time. Every external command (`systemctl`, `useradd`, `systemd-analyze`, `php-fpm -t`, `journalctl`) is killed after 60 seconds.
- **SR-4 Named users.** A site may run as an existing user only if its uid is 1000 to 65533, it is in none of root, sudo, wheel, admin, adm, docker, lxd, and the site folder is inside its home after symlink resolution. `root`, `servanago` and `sg-*` are reserved.
- **SR-5 Executed binaries.** A binary a unit runs (FrankenPHP, fcgiwrap, php-fpm, the helper itself) must be root-owned and not group or world writable.
- **SR-6 Files.** Site files are never chowned or chmodded, except directories the helper creates in a home it just created.
- **SR-7 Secrets.** Operator secrets come from the environment or root-owned files, never SQLite or logs. SMTP passwords and TOTP seeds are sealed; site environment values are sealed and write-only.
- **SR-8 No isolation claim.** Unix-user separation is not a sandbox for mutually untrusted tenants, and no document may claim multi-tenant security. Anyone who controls the UI session can run a shell command as any eligible user (SR-4) through a node site's start command.

## Non-functional requirements

- **NFR-1 Platform.** Debian 12+ or Ubuntu 22.04+, systemd 252 or later, amd64/arm64, one static binary, packaged as a `.deb`.
- **NFR-2 Persistence.** All state is one SQLite file plus Caddy storage under `DATA_DIR`. Schema changes are numbered migrations applied at start; `001` and `002` are never edited.
- **NFR-3 Footprint.** Idle memory under 100 MB; cold start to serving under 5 seconds with existing certificates (targets, not measured in CI).
- **NFR-4 Logging.** Structured `slog`. No codes, seeds or tokens are logged.
- **NFR-5 Licensing.** `LICENSE` is MIT; `NOTICE` credits Caddy and the other Apache, BSD and MIT dependencies.

## Acceptance scenarios

- *FR-5.* **Given** a stored node site whose unit file was deleted, **when** `servanago` starts, **then** the helper receives `user-add`, `unit-install` and `unit-start` for that site, and a static site without a user receives none.
- *FR-9.* **Given** no administrator, **when** a request arrives with `X-Forwarded-For: 203.0.113.9`, **then** the answer is 403; **when** it arrives from `127.0.0.1` without that header, **then** it is 200.
- *SR-2.* **Given** `unit-install` with root `/etc/servanago`, **then** the answer is an error containing "off limits" and no file is written.
- *SR-3.* **Given** a peer that connects and sends nothing, **then** the helper answers with a read error and closes within the timeout. **Given** four concurrent `unit-start` calls for one slug, **then** at most one runs at a time.
- *FR-2.* **Given** a site whose rendered config Caddy rejects, **then** the previous config is live, the site row is unchanged, and an audit row `config.rejected` exists.

## Verification status

Covered by tests: FR-2, FR-3, FR-5, FR-9, SR-1 to SR-5, helper fuzzing of unit-file injection.

Not yet run against a real host: serve-static, static-with-user units, dotted user names, the PHP helper actions and job units, fcgiwrap, FR-12 end to end on a fresh install. Treat these as unverified until a host run is recorded in `ROADMAP.md`.

## Open questions

1. Should the first-administrator guard (FR-9) offer a one-time setup token for installs managed only over a public hostname?
2. Should a failed reconcile (FR-5) leave a visible per-site state rather than a log line?
3. Should the helper own `DATA_DIR` instead of hard-coding `/var/lib/servanago` in SR-2?
