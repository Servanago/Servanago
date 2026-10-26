# Sites

A site is one or more free hostnames (FQDNs; the first is the main one) served by one backend. Each hostname gets its own A (and optional AAAA) record when Cloudflare is configured.

## Kinds

| Kind | What it does |
|---|---|
| Reverse proxy | Forwards to a host or IP and port. |
| Static | Serves a folder. |
| Node.js | Own system user and a sandboxed systemd unit running your start command, behind a loopback port Caddy forwards to. |
| PHP-FPM | Own php-fpm pool and socket; the version is picked from the php-fpm binaries on the host, or from PHP that ServanaGo builds ([PHP](php.md)). |
| FrankenPHP | One `frankenphp php-server` unit per site behind a loopback port. |
| FastCGI | Caddy's FastCGI transport to an admin-run socket path or host:port. Nothing is supervised. |
| CGI | Socket-activated fcgiwrap (`servanago-<slug>.socket` and `.service`). |

Node.js, PHP, FrankenPHP and CGI sites need the packaged install (the root helper does the privileged work).

## Runtimes

ServanaGo detects Node.js and php-fpm and shows the install command; it never installs a runtime, never runs your install or build commands, and never changes the ownership of your files. Give `sg-NAME` access yourself (the Help page has the commands). The edit page shows the unit's state and recent journal lines.

Users on the same host are separated by Unix permissions only: **do not host mutually untrusted sites.**

## Run a site as its own user

A site can run as a login-less user named after the site (such as `luckyedward.com`, home `/home/luckyedward.com`, folder `public_html`) or as an existing regular user. One site per user. A PHP site's user gets the site's `php` and `composer`. A public folder such as `public` keeps framework code out of the web root. A static site with a user is served by a small unit running as that user.

## Per-site controls

- Enable/disable: a disabled site answers a 503 maintenance page.
- CIDR allowlist, basic auth, streaming and upload limits, admin notes.
- Magic-link gate ([Security](security.md#magic-link-site-access)).
- Snippets: attach named Caddyfile snippets (below).

A site can't use the hostname of `SERVANAGO_HOST`, since the UI route always wins in Caddy.

## Snippets

The Snippets page holds named Caddyfile snippets (headers, redirects, canned responses, compression) that sites attach by name. They run after the gate, allowlist and basic auth and before the handler, in alphabetical order; `/.well-known/*` bypasses them. Handlers that serve, proxy or authenticate are refused, as are `import`, env/file placeholders and extra site blocks.

`servanago import` reads `(name) {}` blocks and `import` lines from a Caddyfile ([command line](mcp.md#command-line)).

## Reference page

Every site with its kind, address, folder and notes in one place.

## How changes are applied

Every change writes SQLite, renders the full Caddy JSON, and loads it with `caddy.Load`. If Caddy rejects it, the database change is rolled back, the previous configuration stays live, and the UI shows Caddy's exact error.

If the stored configuration fails to load at startup, ServanaGo first restores the last successfully loaded configuration (`caddy-last-good.json` in the data directory), and only falls back to a bootstrap setup (UI only) when there is none. The dashboard shows a banner in both cases, and the Audit page records `config.changed`, `config.rejected`, `config.restored` and `config.bootstrapped` events.

## DNS records

Cloudflare records ServanaGo creates are marked `managed by servanago` and are the only ones it will change or delete.

- An identical existing record is adopted and never touched.
- A different one is reported as a conflict, with an explicit *Take over* action.
- The same rules apply to the UI host's record, which is synced at startup and from the dashboard, and never deleted automatically.
- A site's A record points at its domain's default IP unless the site sets its own *DNS record IP*.
- A DNS failure never reverts a site: the dashboard shows the error with a *Retry* button.

## Monitoring

Dashboard and Logs show upstream health, certificate expiry, DNS state and a live Caddy/ACME log. The Audit page lists every sign-in and change, including MCP actions.

## Built-in help

A hint under every field, a live preview of what *Add site* will create, plain-language explanations of errors and status words, a getting-started checklist and a Help page.
