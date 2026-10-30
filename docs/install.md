# Install and first run

## Package install

Debian 12+ or Ubuntu 22.04+ with systemd. One deb installs the binary, a `servanago` system user, `/etc/servanago/servanago.env`, the `servanago.service` unit, `/var/lib/servanago` (`DATA_DIR`) and `/var/log/servanago`.

```sh
make deb                                    # bin/servanago_0.16.1_amd64.deb
sudo apt-get install ./bin/servanago_0.16.1_amd64.deb
```

Or all of it with nothing but this checkout: `sudo packaging/install.sh`.

The unit is enabled but not started. Fill in the env file first (`SERVANAGO_HOST`, `ACME_EMAIL`, `ADMIN_PASSWORD`; see [Configuration](configuration.md)), then `systemctl start servanago`.

- The env file is a conffile: dpkg keeps your edits across upgrades.
- Database changes apply on start. A database from before 0.5.0 that lacks the PHP and site-user columns is repaired first: ServanaGo writes `servanago.db.pre-repair` (readable by its owner only), adds the missing columns, and records `schema.repaired` on the Audit page. A database older than the 0.2.0 schema is refused with a "not repairable" error and left untouched.
- Logs go to journald (`journalctl -u servanago`).
- Removing the package stops and disables the unit. Purging it also removes the `servanago` user but keeps `/var/lib/servanago` until you delete it.

The deb also installs `servanago-helper.service`, a root daemon. The control plane asks it (over a Unix socket, as the `servanago` user) to do privileged work: per-site systemd units, system users and php-fpm pools, and the PHP builds and per-user PHP defaults. It takes a closed set of typed actions only. The PHP page needs it; when you run ServanaGo from source without it, that page says so.

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
