---
name: servanago-sites
description: Create, inspect, update, disable and delete ServanaGo sites (proxy, static, Node.js, PHP-FPM, FrankenPHP, FastCGI, CGI) through the ServanaGo MCP tools. Use when asked to add a website, point a hostname at an app, change a site's upstream, folder, allowlist, snippets or notes, check a site's unit status, or remove a site on a ServanaGo host.
---

# ServanaGo sites over MCP

Requires ServanaGo 0.2.0 or newer.

Tools: `list_sites`, `get_site`, `list_domains`, `runtime_report`, `unit_status`, `audit_tail`, `create_site`, `update_site`, `set_site_enabled`, `delete_site`, and since 0.10.0 the DNS tools `resync_dns` and `take_dns` plus the domain tools `create_domain` and `update_domain`, since 0.12.0 the record tools `list_dns_zones`, `list_dns_records`, `create_dns_record`, `update_dns_record`, `delete_dns_record`, and since 0.13.0 the scan tools `run_scan`, `list_scan`, `quarantine_hit`, `restore_hit`, `ignore_hit`, and since 0.14.0 the site country filter is a `create_site`/`update_site` field (`country_mode` deny|allow, `countries` ISO codes). Connection and safety rules are in `servanago-mcp`.

## Domains and DNS records

A hostname's DNS record points at `record_ip`/`record_ip6` if the site sets one, else the domain's `default_ip`/`default_ip6` (`list_domains` shows them). Without a Cloudflare zone there is no DNS sync.

- `create_domain {name, default_ip, default_ip6?, cert_mode?}` adds a zone; the name must be visible to the Cloudflare token.
- `update_domain {id, default_ip, default_ip6?, cert_mode?}` changes only what you pass. Existing records are not touched: run `resync_dns {id}` on each site to converge.
- `get_site` returns per-hostname DNS rows (`state` synced | pending | conflict | error). A `conflict` row (Cloudflare already points elsewhere, unowned) is only resolved by `take_dns`, which overwrites the record and marks it managed; `resync_dns` leaves it alone. Both are idempotent on synced records.

## Create

`create_site` needs `kind`, `hostnames` and that kind's fields. The first hostname is the main address.

| kind | fields |
|---|---|
| `proxy` | `scheme` (http or https), `upstream_host`, `upstream_port`; `tls_skip_verify` for a self-signed https upstream |
| `static` | `static_root`: absolute folder |
| `node` | `static_root`, `start_command`, `port` (loopback, 1024-65535); `install_command` and `build_command` are shown to the admin and never run |
| `php` | `static_root`, `fpm_version` (a detected php-fpm, or a ServanaGo-built branch such as `8.4`) |
| `frankenphp` | `static_root`, `port` |
| `fastcgi` | `static_root`, `fcgi_addr`: absolute socket path or host:port |
| `cgi` | `static_root` (socket-activated fcgiwrap) |

Common optional fields: `allowlist` (CIDRs or IPs, one per line), `enabled` (default true), `record_ip` / `record_ip6` (DNS record for this site), `snippets` (names), `extra_routes` (since 0.11.0; paths sent to another app, one `path=dial` per line, e.g. `/api=127.0.0.1:3303`; dial is host:port or an absolute socket path), `notes` (plain text, at most 10,000 characters; since 0.6.0).

Check `runtime_report` first: Node, php-fpm, frankenphp and fcgiwrap are detected, never installed by ServanaGo. Hostnames must be real FQDNs: `.local`, `.internal`, `.home.arpa`, IP literals and the panel's own hostname are rejected.

## Update

`update_site {id, ...}` changes only the fields you pass. Everything else keeps its stored value, including access controls: the magic-link gate, basic auth and upload limit are UI-only and are never touched or settable over MCP.

- `snippets`: `[]` detaches all; leaving it out keeps the stored ones.
- `extra_routes`: `""` clears; leaving it out keeps them. `get_site` returns them.
- `notes`: `""` clears; leaving it out keeps them.
- `allowlist`: empty keeps the stored list.

## Enable, disable, delete

- `set_site_enabled {id, enabled}`: a disabled site answers a 503 maintenance page and its supervised unit stops.
- `delete_site {id, delete_dns?}`: tears down the unit and user. Site files are never touched. The DNS record is kept unless `delete_dns` is true. Confirm with the user first.

## Diagnose

`unit_status {id}` returns state and recent journal lines for node, php, frankenphp and cgi sites. `get_site` shows the stored configuration. Runtime units are not re-applied at startup: after restoring a host, update each such site once to recreate its unit.

## Do not

- Expect ServanaGo to chown or chmod site files. The operator grants the `sg-<slug>` user access.
- Promise tenant isolation. Per-site Unix users are not a sandbox for mutually untrusted tenants.
