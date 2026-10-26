# Configuration

ServanaGo is configured through environment variables (the package reads `/etc/servanago/servanago.env`). Everything else lives in the UI and SQLite.

## Core

| Variable | Required | Meaning |
|---|---|---|
| `SERVANAGO_HOST` | yes | Hostname the UI is served on. It gets its own certificate. |
| `ACME_EMAIL` | yes | Let's Encrypt contact; a bare address. |
| `ADMIN_PASSWORD` | no | Creates the first administrator (named by `ADMIN_USER`) on the first start, when no administrators exist yet. After that it is **ignored**: passwords live in the database and are changed in the UI. **Unset with no administrators means the UI is open** (warning in the log and a red banner). |
| `ADMIN_USER` | no | Name of that first administrator: lower-case letters, digits, `.`, `_`, `-`. Default `admin`. |
| `SERVANAGO_SECRET_KEY` | no | At least 32 characters (`openssl rand -hex 32`). Encrypts the authenticator-app seed, the SMTP password and per-site secrets in SQLite, and signs magic-link sessions; without it those options are off. Back it up with the data directory: if it is lost, run `servanago 2fa-reset NAME` for each administrator. |
| `REQUIRE_2FA` | no | Default `true`: no administrator signs in with a password alone. A user with an authenticator app is asked for its code; a user with a passkey must sign in with it (the password is refused); a user with neither gets a session limited to the Security page until one is set up. The last second factor cannot be removed. `false` turns this off. |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET` | no | Both or neither. Adds a Cloudflare Turnstile check to the password form on `SERVANAGO_HOST`. The `UI_LISTEN` recovery address is exempt. Passkey and code steps have no widget. |
| `SERVANAGO_STATIC_ROOTS` | no | Colon-separated absolute prefixes that a static site's folder must sit under, such as `/srv/www:/home`. Unset allows any folder except `DATA_DIR`, `/etc`, `/proc`, `/sys`, `/dev`, `/root` and `/`. Symlinks are resolved before the check. ServanaGo never changes permissions: the user it runs as needs execute on the parent directories and read on the folder. |
| `ACME_ISSUER` | no | `internal` serves self-signed certificates from Caddy's local CA (offline setups and tests). Default is Let's Encrypt. |
| `ACME_STAGING` | no | `true` uses the Let's Encrypt staging CA. |
| `UI_LISTEN` | no | Default `127.0.0.1:8080`. See the [recovery warning](security.md#ui_listen-is-a-recovery-hatch). |
| `DATA_DIR` | no | Default `/var/lib/servanago`. The user running ServanaGo must be able to write it; from source set it to a folder of your own. |
| `HTTP_PORT`, `HTTPS_PORT` | no | Caddy listen ports, default 80 and 443. |

## MCP

| Variable | Required | Meaning |
|---|---|---|
| `SERVANAGO_MCP_TOKEN` | no | At least 32 characters (`openssl rand -hex 32`). Turns on the MCP endpoint; unset means `/mcp` does not exist. Read at start. |
| `SERVANAGO_MCP_PUBLIC` | no | Default `false`: `/mcp` then answers only the local `servanago mcp` relay and the public URL gives 404. `true` lets remote clients through Caddy. |
| `SERVANAGO_MCP_ALLOWLIST` | no | Comma-separated IPs or CIDRs. With `SERVANAGO_MCP_PUBLIC=true`, only these remote addresses reach `/mcp` (others get 404, before the token is checked). Unset: any address. |

See [MCP and command line](mcp.md).

## Cloudflare (optional)

Leave `CLOUDFLARE_API_TOKEN` unset to run without it. Set it to get DNS-01 certificates (wildcards available) and automatic A and AAAA records. Token permissions are in [Install](install.md#cloudflare-token-optional).

| Variable | Required | Meaning |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | no | Unset: no DNS management, per-host HTTP-01 certificates. Set: DNS-01 certificates and record sync. A malformed token is rejected at startup. |
| `SERVANAGO_HOST_IP` | with a token | Address `SERVANAGO_HOST` resolves to; ServanaGo creates and syncs that A record. |
| `SERVANAGO_HOST_IP6` | no | Optional IPv6 address of `SERVANAGO_HOST`; ServanaGo also creates and syncs an AAAA record for it. A global unicast or unique-local address; the IPv4 address is still required. |
| `SERVANAGO_HOST_ZONE` | no | Cloudflare zone name for that record. Unset walks up the host's labels. |
| `ACME_RESOLVERS` | no | Resolvers for the DNS-01 check. Default `1.1.1.1,8.8.8.8`. |
| `ACME_PROPAGATION_DELAY`, `ACME_PROPAGATION_TIMEOUT` | no | DNS-01 tuning, e.g. `2m` / `10m`. Unset uses Caddy's defaults. |

## Addresses

An A record target (`SERVANAGO_HOST_IP`, a domain's default IP, a site's DNS record IP) can be any usable IPv4 address: public, private (10/8, 172.16/12, 192.168/16) or CGNAT (100.64/10, Tailscale). Loopback, link-local, multicast and reserved addresses are refused.

**IPv6 is dual-stack.** An optional IPv6 address next to each IPv4 one (`SERVANAGO_HOST_IP6`, a domain's IPv6, a site's AAAA record IPv6) makes ServanaGo manage an AAAA record beside the A record, with its own state, conflict and take-over handling. The IPv4 address stays required; an IPv6-only site is not supported. Cloudflare-proxied (orange cloud) records are not supported either.

## Settings page

SMTP (host, port, user, password, MAIL FROM) is set on the Settings page, not in the environment. The password is sealed with `SERVANAGO_SECRET_KEY`. This account only sends ServanaGo's own notices (such as the PHP release mail); magic-link mail for a gated site is set per site.
