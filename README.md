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
- **Web application firewall** per site: the OWASP CRS v4 ruleset (compiled into the binary via the panel's own Coraza handler) inspects every request; five app profiles, an engine-mode select (detection first), per-app exclusions with one-click tuning from a WAF events feed, a read-only rules browser, and rate limiting per client IP. [Sites](docs/sites.md)
- **Mail bridge** per domain: Postmark handles internet-facing mail, inbound messages reach your LMTP server through the panel's webhook, MX/SPF/DKIM/Return-Path and verification are managed end to end. [MCP](docs/mcp.md)
- **PHP built from source** when a security release can't wait for your distribution. [PHP](docs/php.md)
- **Encrypted backups** of sites and the panel, with restore from the UI. [Backups](docs/backups.md)
- **Multiple administrators** with authenticator app, passkeys and Turnstile; every change is audited. [Security](docs/security.md)
- **MCP endpoint, CLI and agent skills** for managing it from an agent or a shell. [MCP](docs/mcp.md)
- A single static Go binary; all state in one data directory.

## Quick start

**You need:** a Debian 12+ or Ubuntu 22.04+ server with systemd and root (sudo) access, a hostname for the panel (for example `panel.example.com`), and free ports 80 and 443. No Go toolchain is needed.

**1. Install the package** from the [latest release](https://github.com/Servanago/Servanago/releases/latest):

```sh
curl -LO https://github.com/Servanago/Servanago/releases/download/v0.20.8/servanago_0.20.8_amd64.deb
sudo apt-get install ./servanago_0.20.8_amd64.deb
```

**2. Point DNS at the server.** Create an A record for your panel hostname that points at the server's IP. (With a Cloudflare token ServanaGo creates it for you; see [Install](docs/install.md#cloudflare-token-optional).) Without Cloudflare the server must be reachable from the internet on ports 80 and 443, because Let's Encrypt checks the hostname over HTTP.

**3. Edit the settings** in `/etc/servanago/servanago.env`:

| Setting | Put |
|---|---|
| `SERVANAGO_HOST` | the panel hostname from step 2 |
| `ACME_EMAIL` | your email address (Let's Encrypt contact, bare address only) |
| `ADMIN_PASSWORD` | the password for the first administrator (used once, on the first start) |
| `CLOUDFLARE_API_TOKEN` | leave empty unless you use Cloudflare |

**4. Start it** (helper first):

```sh
sudo systemctl enable --now servanago-helper servanago
sudo systemctl status servanago
```

**5. Sign in** at `https://<SERVANAGO_HOST>` as `admin` with your `ADMIN_PASSWORD`, then add your first site with **Add site**. Set up an authenticator app under your user as soon as you can: until an administrator exists the panel is open to anyone who can reach it.

**If it doesn't start:** `journalctl -u servanago -n 50`. The usual cause is `address already in use`: another program holds port 80, 443 or 8080 (find it with `sudo ss -ltnp | grep -E ':(80|443|8080) '`). Stop that program, or move the panel's internal listener by adding `UI_LISTEN=127.0.0.1:8082` to the env file. Then `sudo systemctl reset-failed servanago && sudo systemctl start servanago`.

Building the package yourself (`make deb`), running from source, Cloudflare setup and a private-network install are in [docs/install.md](docs/install.md).

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

MIT, see `LICENSE`. Third-party notices (Caddy, caddy-dns/cloudflare, Coraza and the OWASP Coreruleset: Apache-2.0, and others) are in `NOTICE`.
