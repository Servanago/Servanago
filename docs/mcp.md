# MCP, command line and agent skills

## MCP

Off unless `SERVANAGO_MCP_TOKEN` is set (see [Configuration](configuration.md#mcp)). Streamable HTTP (stateless) at `https://<SERVANAGO_HOST>/mcp` with `Authorization: Bearer <token>`. It is reachable from outside only with `SERVANAGO_MCP_PUBLIC=true`, optionally limited by `SERVANAGO_MCP_ALLOWLIST`.

Clients that only speak stdio run `servanago mcp`, which relays to the local endpoint and needs `SERVANAGO_MCP_TOKEN` in its environment (`SERVANAGO_MCP_URL` overrides the endpoint).

- Read tools: `list_sites`, `get_site`, `list_domains`, `runtime_report`, `unit_status`, `audit_tail`, `list_snippets`, `backup_status`, `list_backups`, `plan_restore`.
- Write tools: `create_site`, `update_site`, `set_site_enabled`, `delete_site`, `create_snippet`, `update_snippet`, `delete_snippet`, `run_backup`, `restore_site`.
- Writes run the UI's own handlers, so validation, the apply path, DNS and audit are the same. The audit actor is `mcp token`.

**One token, read and write, no scopes and no per-person audit.** A leaked token can create, change and delete sites: treat it like an administrator password. Gate credentials, basic-auth passwords and upload limits are UI-only. The panel is never restored over MCP.

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

Skills that teach an AI agent to set up a host and use the MCP tools live in [`skills/`](../skills): `servanago-setup`, `servanago-mcp`, `servanago-sites`, `servanago-snippets`, `servanago-backups`. Install them with the [skills CLI](https://www.skills.sh/docs/cli):

```sh
npx skills add Servanago/Servanago                          # choose from all five
npx skills add Servanago/Servanago --skill servanago-sites  # one skill
```

The repo is also a Claude Code plugin (`.claude-plugin/plugin.json`). A test keeps the skills in step with the registered MCP tools.
