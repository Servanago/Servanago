# Workflow: install Servanago 0.2.0 on production `v1`

Target: `ssh v1` (user `linuxuser`, passwordless sudo), Ubuntu 24.04.5, systemd 255, x86_64.
Panel host `v1.tafoyaventures.com`, TLS via Cloudflare DNS-01, ACME email btafoya@briantafoya.com.
IPv4 149.28.240.213, IPv6 2001:19f0:6400:219c:5400:6ff:fee9:cad9. Admin `btafoya`, generated password.
Firewall: 443/tcp only (user decision). Scope: core, then PHP from source after core is verified.

## Resolved design risk

The panel host needs no manual DNS record. With `CLOUDFLARE_API_TOKEN` and `SERVANAGO_HOST_IP` set,
`cmd/servanago/main.go:135` hands the host to dnssync, which creates the A/AAAA at startup.
`ADMIN_USER` + `ADMIN_PASSWORD` in the env file create the first admin on first start, then are ignored.
Consequence: the admin password is briefly in `/etc/servanago/servanago.env` (root:servanago 0640); remove it after first login.
The zone for `tafoyaventures.com` must be visible to the token (else set `SERVANAGO_HOST_ZONE`).

## Phase 0: preflight (local, read-only)
1. `git -C . branch --show-current`, `git status`, confirm HEAD == release commit for 0.2.0 (bcd4cfc). verify: `bin/servanago_0.2.0_amd64.deb` was built from it; if unsure, `make deb` (gate not needed to deploy, but note it).
2. `sha256sum bin/servanago_0.2.0_amd64.deb`. verify: hash recorded.
3. `echo ${CLOUDFLARE_API_TOKEN:+set}` prints `set` (never print the value).
4. `dig +short v1.tafoyaventures.com` (info only; record is created by the app).
Checkpoint: stop if token unset.

## Phase 1: host prep (v1, sudo)
1. `sudo ufw allow 443/tcp` (user chose no 80). verify: `sudo ufw status` shows 443 v4+v6, 22 intact.
2. Do not install anything else yet.
Checkpoint: ssh session still works.

## Phase 2: package install
1. `scp bin/servanago_0.2.0_amd64.deb v1:/tmp/`. verify: remote `sha256sum` matches Phase 0.
2. `sudo apt-get install -y /tmp/servanago_0.2.0_amd64.deb`. verify: user `servanago` exists, `/var/lib/servanago` 0750, units `servanago` and `servanago-helper` enabled, not started.
3. Read `/etc/servanago/servanago.env` (template) before editing.
Checkpoint: if apt pulls unexpected dependencies, stop and report.

## Phase 3: configuration (secrets never in chat/logs)
Write the env file on v1 via ssh stdin, keeping root:servanago 0640:
- `SERVANAGO_HOST=v1.tafoyaventures.com`
- `ACME_EMAIL=btafoya@briantafoya.com`
- `SERVANAGO_HOST_IP=149.28.240.213`, `SERVANAGO_HOST_IP6=2001:19f0:6400:219c:5400:6ff:fee9:cad9`
- `CLOUDFLARE_API_TOKEN` piped from the local env var (no echo, no `set -x`)
- `SERVANAGO_SECRET_KEY=$(openssl rand -hex 32)` generated on v1
- `ADMIN_USER=btafoya`, `ADMIN_PASSWORD=$(openssl rand -base64 18)` generated on v1; shown to the user once, via a final-answer line only
- Keep `ACME_PROPAGATION_DELAY=2m` / `TIMEOUT=10m`
- Optional, ask first: `REQUIRE_2FA=true` (needs the secret key), `SERVANAGO_MCP_TOKEN`
verify: `sudo stat -c '%a %U:%G' /etc/servanago/servanago.env` = `640 root:servanago`; `sudo grep -c . ` of the file only, never cat it.

## Phase 4: first start
1. `sudo systemctl start servanago-helper servanago`.
2. verify: `systemctl is-active` both = active; `journalctl -u servanago -n 50` shows "servanago started" and no config error; no secret in the log.
3. verify DNS: `dig +short A/AAAA v1.tafoyaventures.com @1.1.1.1` returns the two IPs (allow 2-5 min).
4. verify cert: `curl -sSI https://v1.tafoyaventures.com` valid chain (DNS-01 can take up to 10m). If it fails, set `ACME_STAGING=true` only to diagnose, then revert.
5. Login in browser as `btafoya`; open Settings and the host checklist.
6. Remove `ADMIN_PASSWORD` from the env file (Edit via ssh), `systemctl restart servanago`, relogin.
Checkpoint (gate for Phase 5): HTTPS login works, cert valid, DNS correct. Stop and report on any failure; max 3 attempts per issue.

## Phase 5: PHP from source (after Phase 4 passes)
1. Show the exact apt list, then `sudo apt-get install -y gcc g++ make pkg-config perl cmake gnupg xz-utils tar autoconf automake libtool m4 bison flex` (user approved these).
   Note: Phase 0 of the local compile used bison/flex stubs for PostgreSQL 18; real packages should work.
2. Open `/php`, start one build (smallest branch, e.g. the newest 8.4). verify: job units run, `/opt/servanago/php/<ver>-<n>` and `/var/lib/servanago-build/current` appear, logs captured.
3. These helper actions and job units have never run on a real host: on failure capture the journal lines, do not patch on production.
4. Optional smoke: create a `php` site on the build and fetch it.
Checkpoint: record outcome; build failures become issues, not hotfixes.

## Phase 6: wrap-up
1. `sudo ss -ltnp | grep -E ':(80|443|8081|8080)\b'` shows only expected listeners (UI on 127.0.0.1:8080, Caddy on 443).
2. `sudo ufw status` unchanged beyond 443.
3. Save memory: install outcome, findings. No secrets.
4. Rollback: `sudo systemctl disable --now servanago servanago-helper`, `sudo apt-get remove servanago` (data in `/var/lib/servanago` kept; purge only on request), `sudo ufw delete allow 443/tcp`.

## Risks
- Ubuntu 24.04 is in range; first real-host run of helper actions: expect bugs.
- DNS-01 propagation can exceed the delay; Cloudflare zone not visible to token causes host DNS failure (set `SERVANAGO_HOST_ZONE`).
- 443-only: HTTP-01 and the plain-HTTP redirect are unavailable by design.
- Password in the env file between Phase 3 and Phase 4.6.
