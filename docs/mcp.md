# MCP, command line and agent skills

## MCP

Off unless `SERVANAGO_MCP_TOKEN` is set (see [Configuration](configuration.md#mcp)). Streamable HTTP (stateless) at `https://<SERVANAGO_HOST>/mcp` with `Authorization: Bearer <token>`. It is reachable from outside only with `SERVANAGO_MCP_PUBLIC=true`, optionally limited by `SERVANAGO_MCP_ALLOWLIST`.

Clients that only speak stdio run `servanago mcp`, which relays to the local endpoint and needs `SERVANAGO_MCP_TOKEN` in its environment (`SERVANAGO_MCP_URL` overrides the endpoint).

- Read tools: `list_sites`, `get_site`, `list_domains`, `runtime_report`, `unit_status`, `audit_tail`, `list_snippets`, `backup_status`, `list_backups`, `plan_restore`, `list_dns_zones`, `list_dns_records`, `list_scan`, `list_mail_domains`, `get_mail_domain`, `list_mail_events`.
- Write tools: `create_site`, `update_site`, `set_site_enabled`, `delete_site`, `resync_dns`, `take_dns`, `create_domain`, `update_domain`, `create_dns_record`, `update_dns_record`, `delete_dns_record`, `create_snippet`, `update_snippet`, `delete_snippet`, `run_backup`, `restore_site`, `run_scan`, `quarantine_hit`, `restore_hit`, `ignore_hit`, `create_mail_domain`, `update_mail_domain`, `delete_mail_domain`.
- DNS records (0.12.0): the record tools are the [/dns pages](sites.md) for any zone the token sees, independent of the site model. `list_dns_records` marks rows `managed` that ServanaGo writes for sites; editing or deleting one works, and the next save of its site (or a startup) may write the site's value back. Writable types: A, AAAA, CNAME, TXT, MX, SRV, CAA, NS; rarer types are listed but refused (`type TLSA is read-only in ServanaGo`). Names post zone-relative (`www`, `_dmarc`, `*.static`, `@` = the apex).
- Virus scanning (0.13.0): `run_scan {id}` starts a site's scan in the background; `list_scan {site?, limit?}` reads runs with hits; the hit tools are the Scan page's buttons (`quarantine_hit`, `restore_hit`, `ignore_hit`). Scanning needs clamd running on the host (the Settings page holds its socket); backups stream their site files through clamd and skip infected ones from the archive.
- Country filter (0.14.0): `create_site`/`update_site` take `country_mode` (deny | allow; `""` off) and `countries` (ISO 3166-1 two-letter codes, space or comma separated); `get_site` returns both. The panel's own rule lives on the Settings page and has no MCP field: change it in the UI.
- Mail bridge (0.15.0): `create_mail_domain {domain, adopt?, lmtp_addr?, hook_user?, hook_pass?}` provisions a domain (a Postmark server named `mail-<domain>`, the domain, webhook URLs, MX/SPF/DKIM/Return-Path via the DNS feature, then verification watch). Existing Postmark objects stop it unless `adopt`. `update_mail_domain {domain, lmtp_addr?}` re-provisions with adopt (re-push, reconcile DNS, re-verify); `get_mail_domain/`list_mail_domains show states, notes and counters; `delete_mail_domain {domain}` forgets the local state only — Postmark and DNS stay. Generated webhook credentials appear once in the result's warnings; passing `hook_user`/`hook_pass` suppresses the generation.
- `update_site` changes only the fields passed; the rest, including snippets, extra routes, notes and the access controls, keep their stored values. `get_site` returns snippets, extra routes, notes and the DNS rows.
- Writes run the UI's own handlers, so validation, the apply path, DNS and audit are the same. The audit actor is `mcp token`.

**One token, read and write, no scopes and no per-person audit.** A leaked token can create, change and delete sites: treat it like an administrator password. Gate credentials, basic-auth passwords and upload limits are UI-only. The panel is never restored over MCP.

### Claude Code

Two ways to connect; the token is the same `SERVANAGO_MCP_TOKEN`.

```sh
# Local relay: the packaged binary (a stdio relay to the local endpoint; SERVANAGO_MCP_URL picks another one)
claude mcp add servanago -s user -e SERVANAGO_MCP_TOKEN=<SERVANAGO_MCP_TOKEN> -- /usr/bin/servanago mcp

# Remote endpoint: needs SERVANAGO_MCP_PUBLIC=true (and the allowlist) to answer beyond the host
claude mcp add servanago -s user --transport http https://<SERVANAGO_HOST>/mcp \
  -H 'Authorization: Bearer ${SERVANAGO_MCP_TOKEN}'
```

- `-s user` makes the server available in every project of yours; without it, the scope is the current project. Remove with `claude mcp remove servanago -s user`; `claude mcp list` shows whether it connects.
- The HTTP form single-quotes the header on purpose: Claude Code stores the literal `${SERVANAGO_MCP_TOKEN}` and expands it from the environment at connect time. Quoting it double-quoted instead bakes the token itself into `~/.claude.json` — avoid, and treat that file as a secret either way.

## Command line

| Command | What it does |
|---|---|
| `servanago` | Runs the control plane. |
| `servanago user add NAME`, `user passwd NAME` | Create an administrator or set a password (reads the password from the terminal or stdin). Needs only `DATA_DIR`. |
| `servanago 2fa-reset NAME` | Removes that administrator's second factor. Needs only `DATA_DIR`. |
| `servanago import [-dry-run] Caddyfile` | Turns a Caddyfile's site blocks and `(name) {}` snippets into sites. Needs Cloudflare; stop the service first. |
| `servanago backup list\|verify\|run\|restore` | Works on backup archives; see [Backups](backups.md). |
| `servanago mcp` | Stdio relay to the MCP endpoint. |

`helper`, `php-job`, `backup-job` and `serve-static` are internal subcommands that the packaged systemd units run.

## Agent skills

Skills that teach an AI agent to set up a host and use the MCP tools live in [`skills/`](../skills): `servanago-setup`, `servanago-mcp`, `servanago-sites` (sites, DNS, scanning, the mail bridge), `servanago-snippets`, `servanago-backups`. Install them with the [skills CLI](https://www.skills.sh/docs/cli):

```sh
npx skills add Servanago/Servanago                          # choose from all five
npx skills add Servanago/Servanago --skill servanago-sites  # one skill
```

The repo is also a Claude Code plugin (`.claude-plugin/plugin.json`). A test keeps the skills in step with the registered MCP tools.
