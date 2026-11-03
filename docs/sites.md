# Sites

A site is one or more free hostnames (FQDNs; the first is the main one) served by one backend. Each hostname gets its own A (and optional AAAA) record when Cloudflare is configured.

## The site view

Every site has a control view at `/sites/<id>`: one page per area, shared by a tab rail.

| Tab page | What lives there |
|---|---|
| `/sites/<id>` (Settings) | The editor: hostnames, kind and its fields, notes; the delete button. |
| `/sites/<id>/dns` | The site's A/AAAA records with their sync state, resync and take-over, and the per-site record IP overrides. |
| `/sites/<id>/ssl` | Certificate facts per hostname: issuer, valid-until, state. |
| `/sites/<id>/scan` | This site's scan runs and findings, with a manual scan now. |
| `/sites/<id>/backups` | Per-site schedule, database dumps, container volumes, run now. |
| `/sites/<id>/mail` | The gate's mail provider (SMTP or Postmark) and a test mail. |
| `/sites/<id>/snippets` | Attach/detach the site's snippets. |
| `/sites/<id>/runtime` | Unit state and journal tail; start, stop and restart. |
| `/sites/<id>/gate` | Gate mode, who may ask for a link, IP allowlist, basic auth. |
| `/sites/<id>/routes` | Extra routes and a proxy site's TLS/stream/upload tuning. |
| `/sites/<id>/countries` | The site's country rule. |
| `/sites/<id>/waf` | The site's web application firewall. |
| `/sites/<id>/waf/rules` | The compiled CRS, read-only: rules files and every rule's facts. |

Tabs save in place: a form posts from its tab, the button shows the save, and the page does not reload. Actions that came from the dashboard rows (resync, scan, backup saves, access list rows) accept a return-to tab.

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

ServanaGo detects Node.js and php-fpm and shows the install command; it never installs a runtime, never runs your install or build commands, and never changes the ownership of your files. Give `sg-NAME` access yourself (the Help page has the commands). The site's Runtime tab shows the unit's state and recent journal lines, and offers start, stop and restart.

Users on the same host are separated by Unix permissions only: **do not host mutually untrusted sites.**

## Run a site as its own user

A site can run as a login-less user named after the site (such as `luckyedward.com`, home `/home/luckyedward.com`, folder `public_html`) or as an existing regular user. One site per user. A PHP site's user gets the site's `php` and `composer`. A public folder such as `public` keeps framework code out of the web root. A static site with a user is served by a small unit running as that user.

## Per-site controls

- Enable/disable: a disabled site answers a 503 maintenance page.
- CIDR allowlist, basic auth, streaming and upload limits, admin notes.
- Magic-link gate ([Security](security.md#magic-link-site-access)).
- Snippets: attach named Caddyfile snippets (below).
- Extra routes: send certain paths of the site to a different app, one `path=dial` per line (for example `/cryptpad_websocket=127.0.0.1:3303`; dial is `host:port` or an absolute socket path). A path matches itself and everything below it. Any access control still applies first. Also settable over MCP (`extra_routes` on `create_site` and `update_site`).

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

## The DNS pages

The DNS page is a full independent record view of every Cloudflare zone the token can see — not just managed domains: create, edit and delete records in the browser (types A, AAAA, CNAME, TXT, MX, SRV, CAA, NS), with the same rules for rarer types, name input and the managed badge as the MCP record tools (see [MCP](mcp.md)).

## Country filter

A site's Country filter (the access area of its editor) answers whole countries with a plain 403: **Deny these countries** keeps the listed ones out, **Allow only these countries** keeps everyone else out. Codes are ISO 3166-1 two-letter codes (DE, US), space or comma separated. Everything from the machine itself, a home network or a tailnet (private addresses) is never judged, and the `/.well-known/` paths always stay open so certificates keep renewing. A record proxied through Cloudflare is judged by the address Cloudflare names in `CF-Connecting-IP` (a header Cloudflare sets itself); otherwise the visiting address is. The database is MaxMind's GeoLite2-Country, read from Settings' path — ServanaGo never installs it: `apt install geoipupdate` keeps the file current with your license key in `/etc/GeoIP.conf`. A rule that cannot read the database lets everyone in.

A site's **Web application firewall** (the WAF tab) inspects every request against the OWASP Coreruleset (CRS v4, compiled into the binary via Coraza — no rule files to install). The **ruleset select** picks what runs: the bare CRS preset, one of the profiles (`PHP generic`, `WordPress`, `PHP ecommerce`, `Go / generic API`, `Node / JSON API` — each ships the CRS with the health-check false positives that class of app always needs, nothing more), or **custom**, which appends your own SecLang lines. File-reading or DNS-resolving operators (`@inspectFile`, `@pmFromFile`, `@rbl`, ...) are refused; the tail compiles against the CRS at save, so a rule id that no longer ships fails there instead of inside Caddy's load.

The **engine mode** is its own select: log only (detection) records every match in **Events** without refusing anything — tune there first — and Block answers 403 the moment a rule fires. It owns the single `SecRuleEngine` line of the composed ruleset; a custom tail may not set the engine itself. The mode applies to any preset.

**Events** are the tab's tuning feed: one row per matched rule with a verdict (blocked or detection-only), capped at 10,000 like the audit log, plus per-rule aggregates over the last 24 hours. Each of the loudest rules carries its CRS tags and two buttons: **Disable** removes the rule for this site (one exclusion row); **Narrow** pre-fills the exclusions form to stop the rule looking at one request item (`!ARGS:checkout` style) — the surgical fix.

**Exclusions** are the per-site rows your clicks and forms created — remove a rule by id, remove a whole CRS category (the **category boxes**), or narrow a rule to a target — each with note and who added it. Undo = delete the row; the next save re-renders without its line. Exclusion rows compose after the preset and before the engine line.

The **rules browser** (`/sites/<id>/waf/rules`, read-only) lists every compiled CRS file with its rule count and opens one to show every rule's id, message, phase and tags, and which files the site has excluded rules from.

**Rate limiting** sits at the bottom of the tab: N requests per client IP per window (1m, 5m or 1h; the address Cloudflare names, else the connecting one), optionally scoped to path prefixes (`/login`, one per line — children included). Over the limit answers 429 with a `Retry-After` until the window passes; every other address is unaffected, and the panel's own probes are never counted. A limit without a ruleset still runs (engine-off). Counters live in the panel process — bounded to a million addresses — and reset at a restart.

The WAF runs after the country rule and before the gate; requests to the gate's own `ml.` host are never inspected. A ruleset that fails inside Caddy's load restores the site's last-known-good config automatically.

## Virus scanning

The Scan page shows the runs and their hits. ServanaGo streams each site's served folder through ClamAV's clamd (its socket lives on Settings; the daemon, installed with `apt install clamav-daemon`, keeps its own signatures fresh), quarantines every hit into `DATA_DIR/quarantine/`, alerts ntfy and email once per scan, and offers restore or ignore per hit. The daily sweep runs at the hour Settings names; Scan now runs any time; a site backup streams its files through the same scan and skips infected ones from the archive.

## Built-in help

A hint under every field, a live preview of what *Add site* will create, plain-language explanations of errors and status words, a getting-started checklist and a Help page.
