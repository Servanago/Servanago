# Install and first run

## Package install

Debian 12+ or Ubuntu 22.04+ with systemd. One deb installs the binary, a `servanago` system user, `/etc/servanago/servanago.env`, the `servanago.service` unit, `/var/lib/servanago` (`DATA_DIR`) and `/var/log/servanago`.

```sh
make deb                                    # bin/servanago_0.20.4_amd64.deb
sudo apt-get install ./bin/servanago_0.20.4_amd64.deb
```

Or all of it with nothing but this checkout: `sudo packaging/install.sh`.

The unit is enabled but not started. Fill in the env file first (`SERVANAGO_HOST`, `ACME_EMAIL`, `ADMIN_PASSWORD`; see [Configuration](configuration.md)), then `systemctl start servanago`.

- The env file is a conffile: dpkg keeps your edits across upgrades.
- Database changes apply on start. A database from before 0.5.0 that lacks the PHP and site-user columns is repaired first: ServanaGo writes `servanago.db.pre-repair` (readable by its owner only), adds the missing columns, and records `schema.repaired` on the Audit page. A database older than the 0.2.0 schema is refused with a "not repairable" error and left untouched.
- Logs go to journald (`journalctl -u servanago`).
- Removing the package stops and disables the unit. Purging it also removes the `servanago` user but keeps `/var/lib/servanago` until you delete it.

The deb also installs `servanago-helper.service`, a root daemon. The control plane asks it (over a Unix socket, as the `servanago` user) to do privileged work: per-site systemd units, system users and php-fpm pools, and the PHP builds and per-user PHP defaults. It takes a closed set of typed actions only. The PHP page needs it; when you run ServanaGo from source without it, that page says so.

## Updating

From 0.19.0 on, a release upgrades itself. ServanaGo checks GitHub once a week for a newer signed release (turn this off with `SERVANAGO_UPDATE_CHECK=false`). Three ways to install it:

- **Updates page** (menu): shows the running and the latest version, then **Upgrade to X** after your password. A release that changes the database or is marked breaking also asks you to tick that you read the release notes.
- **Command line**: `sudo servanago update` (or `--check` to only look, `--yes` to skip the question).
- **MCP**: `check_update`, then `start_upgrade` (see [MCP](mcp.md)).

The upgrade downloads the signed package, copies the database to `servanago.db.pre-<version>`, installs the package, restarts both services and waits up to a minute for the panel to answer. If it does not, the previous version and the database copy are put back. Sites keep running; the panel is unavailable for about a minute. The Audit page records `update.start` and then `update.completed`, `update.rolledback`, `update.failed` or `update.needs_hands`.

It refuses when a PHP build or a backup is running, when you run a build from source, and when the release is not newer. If the rollback fails too, the services stay stopped and `/var/lib/servanago-update/NEEDS_HANDS.txt` lists the commands to run. Older than 0.19.0, or no network: download the package yourself, compare its sha256 and install it with `sudo dpkg --force-confold -i`, as in [Releasing](RELEASING.md).

## Before you start

- Ports 80 and 443 must be free on the host. Another web server (nginx, Apache, the distro `frankenphp` service) on them stops ServanaGo from binding: disable it first.
- The panel's own listener (`UI_LISTEN`, default `127.0.0.1:8080`) must be free too. Caddy proxies to it, so keep it on loopback and on a port nothing else uses (`sudo ss -ltnp | grep -E ':(80|443|8080) '`).
- `SERVANAGO_HOST_IP` (only used with a Cloudflare token) is the address the panel hostname points at. A private address such as `192.168.x.x` works but makes the panel reachable from your network only. For Let's Encrypt over HTTP-01 (no Cloudflare) the host needs a public address with 80 and 443 forwarded to it.
- `ADMIN_PASSWORD` creates the first administrator once; later changes go through the Users page. `ADMIN_USER` defaults to `admin`.

## Start and check

```sh
sudo systemctl enable --now servanago-helper servanago
systemctl is-active servanago-helper servanago     # both: active
journalctl -u servanago -n 50 --no-pager
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/login      # 200 (use your UI_LISTEN)
```

Troubleshooting:

| Symptom | Cause and fix |
|---|---|
| `Start request repeated too quickly`, service `failed` | systemd gave up after repeated crashes. Fix the cause from the journal, then `sudo systemctl reset-failed servanago && sudo systemctl start servanago`. |
| `listen tcp 127.0.0.1:8080: bind: address already in use` | Another program holds the panel port. Set `UI_LISTEN=127.0.0.1:<free port>` in the env file. Keep a single `UI_LISTEN` line. |
| Certificate not issued | The hostname must resolve to this server (HTTP-01) or the Cloudflare token must have `Zone:Read` and `DNS:Edit` (DNS-01). Set `ACME_STAGING=true` while testing. |
| PHP page says the helper is missing | `sudo systemctl start servanago-helper`. |

## Run from source

For development or a try-out without the package (there is no container image). ServanaGo reads its configuration from the process environment only; it does not load `.env` itself.

1. Optional: create a [Cloudflare API token](#cloudflare-token-optional) for DNS-01 certificates and automatic DNS records.
2. Build the binary (Go only, no Node build step):

   ```sh
   make build        # bin/servanago
   ```
3. Copy the example environment file and fill it in:

   ```sh
   cp .env.example .env
   ```

   `SERVANAGO_HOST` and `ACME_EMAIL` are required, plus `SERVANAGO_HOST_IP` if you set `CLOUDFLARE_API_TOKEN`. Set `ADMIN_PASSWORD` too: it creates the first administrator on the first start.
4. Run it as an unprivileged user. Either let it bind 80 and 443 with a capability, or choose other ports:

   ```sh
   sudo setcap cap_net_bind_service=+ep bin/servanago        # then HTTP_PORT/HTTPS_PORT can stay default
   set -a; . ./.env; set +a
   DATA_DIR="$PWD/data" ./bin/servanago
   ```

   With a Cloudflare token, ServanaGo creates the `SERVANAGO_HOST` A record itself (pointing at `SERVANAGO_HOST_IP`). Without one, point `SERVANAGO_HOST` at this server in your own DNS first, because Let's Encrypt validates over HTTP-01.
5. Open `https://<SERVANAGO_HOST>`.

If the zone for `SERVANAGO_HOST` can't be found, set `SERVANAGO_HOST_ZONE`. If a different A record already exists for that name, the dashboard's *UI host* card shows a conflict and a *Take over* button; nothing is overwritten until you click it. To avoid Let's Encrypt rate limits while trying things, set `ACME_STAGING=true`.

## Add your first site

Click **Add site** and enter the hostname (`oc.example.com`; add more, one per line) and its backend: host or IP plus its own **Upstream port** field (`192.168.25.165` and `9200`), or switch the kind to **Static** and give a folder to serve. That is the Caddyfile equivalent of `oc.example.com { reverse_proxy http://192.168.25.165:9200 }`.

- With Cloudflare, ServanaGo finds the zone, adds the domain if it is new, and creates the A record.
- A hostname Cloudflare has no zone for, or any hostname without Cloudflare, is served with its own HTTP-01 certificate; you point its DNS at the server yourself.

The other site kinds are in [Sites](sites.md).

## Cloudflare token (optional)

Create a custom API token at *My Profile → API Tokens* with:

- `Zone : Zone : Read`
- `Zone : DNS : Edit`

scoped to the zones you want to manage. The same token is used for certificate issuance (DNS-01) and for the DNS records. It is read from the environment only; it is never stored in SQLite, logs or the generated Caddy config.

## Without Cloudflare

Leave `CLOUDFLARE_API_TOKEN` unset. Then:

- Add each domain on the *Domains* page before adding sites under it (ServanaGo cannot look up a zone).
- Certificates are per host (HTTP-01/TLS-ALPN); ports 80 and 443 must be reachable from the internet.
- You point DNS at the server yourself.
- A hostname under a domain you added uses that domain's settings; any other hostname gets its own HTTP-01 certificate and no DNS management.
