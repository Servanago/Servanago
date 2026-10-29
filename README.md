<p align="center">
  <img src="docs/brand/servanago-wordmark.png" alt="ServanaGo" width="520">
</p>

# ServanaGo

A lightweight, self-hosted web runtime manager: a small Go app with a web UI, an embedded [Caddy](https://caddyserver.com), SQLite and systemd supervision of the apps it runs. Caddy's configuration is generated from SQLite and applied atomically.

> **Status: early.** Hardening is on the [roadmap](docs/ROADMAP.md), not shipped. Nothing here describes planned features as working.

## What it does

- **Sites** of seven kinds: reverse proxy, static, Node.js, PHP-FPM, FrankenPHP, FastCGI and CGI, each with one or more hostnames and optional per-site user, allowlist, basic auth, magic-link gate, snippets and extra routes. [Sites](docs/sites.md)
- **Certificates** over HTTP-01 by default, or DNS-01 and automatic A/AAAA records with an optional Cloudflare token. [Install](docs/install.md), [Configuration](docs/configuration.md)
- **DNS record management** for every Cloudflare zone the token sees: full CRUD in the UI and MCP, independent of the site model. [MCP](docs/mcp.md)
- **Virus scanning** of site folders through the host's ClamAV daemon: quarantine, restore/ignore, ntfy + email alerts, scanned backups. [MCP](docs/mcp.md)
- **Country filter** per site and for the panel: deny or allow ISO country lists, judged from MaxMind's GeoLite2 (kept fresh by geoipupdate, never configured by ServanaGo). [Sites](docs/sites.md)
- **PHP built from source** when a security release can't wait for your distribution. [PHP](docs/php.md)
- **Encrypted backups** of sites and the panel, with restore from the UI. [Backups](docs/backups.md)
- **Multiple administrators** with authenticator app, passkeys and Turnstile; every change is audited. [Security](docs/security.md)
- **MCP endpoint, CLI and agent skills** for managing it from an agent or a shell. [MCP](docs/mcp.md)
- A single static Go binary; all state in one data directory.

## Quick start

Debian 12+ or Ubuntu 22.04+ with systemd:

```sh
make deb                                    # bin/servanago_0.11.2_amd64.deb
sudo apt-get install ./bin/servanago_0.11.2_amd64.deb
```

Edit `/etc/servanago/servanago.env` (`SERVANAGO_HOST`, `ACME_EMAIL`, `ADMIN_PASSWORD`), then `sudo systemctl start servanago` and open `https://<SERVANAGO_HOST>`.

Running from source, Cloudflare setup and adding your first site are in [docs/install.md](docs/install.md).

## Documentation

| Doc | Covers |
|---|---|
| [Install](docs/install.md) | Package, from source, first site, Cloudflare token, running without Cloudflare |
| [Configuration](docs/configuration.md) | Environment variables, addresses, IPv6 |
| [Sites](docs/sites.md) | Site kinds, runtimes, per-site user, snippets, how changes are applied, DNS |
| [PHP](docs/php.md) | Building PHP from source, what is verified |
| [Backups](docs/backups.md) | Backup jobs, restore, what carries state |
| [Security](docs/security.md) | Administrators, 2FA, passkeys, magic-link gate, recovery |
| [MCP and CLI](docs/mcp.md) | MCP tools, command line, agent skills |
| [Development](docs/development.md) | Tests, lint, e2e, real PHP compile |
| [Releasing](docs/RELEASING.md), [Roadmap](docs/ROADMAP.md), [Design](docs/DESIGN.md), [Requirements](docs/REQUIREMENTS.md) | Project internals |

## License

MIT, see `LICENSE`. Third-party notices (Caddy, caddy-dns/cloudflare: Apache-2.0, and others) are in `NOTICE`.
