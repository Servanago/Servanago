---
name: servanago-backups
description: Check, run and restore ServanaGo backups through MCP. Use when asked about backup status or archives on a ServanaGo host, to run a backup now, to see what a restore would do, or to restore a site's files, database dumps or volumes from an archive.
---

# ServanaGo backups over MCP

Requires ServanaGo 0.7.4 or newer.

Tools: `backup_status`, `list_backups`, `run_backup`, `plan_restore`, `restore_site`. Connection and safety rules are in `servanago-mcp`.

## Model

The operator configures scheduled, passphrase-encrypted archives (tar, zstd, age) of the panel and of opted-in sites (files, database dumps, container volumes) with retention. Over MCP you can look, run a backup, and restore a site. The panel itself is never restored over MCP; that is a CLI step for the operator.

## Read

- `backup_status`: settings (no passphrase), whether a job is running, any stale or failed warning, the latest result per scope.
- `list_backups {scope?}`: archives newest first and recent runs. `scope` is `panel` or a site's short name (its slug); leave it out for all.

## Run

`run_backup {scope}` with `all`, `panel` or a site's short name starts a job. The result appears in `backup_status` and `list_backups` within a minute of the job ending; poll those, do not assume success.

## Restore (destructive: follow this order)

1. `list_backups {scope: <site>}` to pick the archive.
2. `plan_restore {id, archive}`: shows what the archive holds, which volumes can be restored, and which containers a volume restore stops and starts again. Show this to the user.
3. Get the user's explicit go-ahead.
4. `restore_site {id, archive, files?, dumps?, volumes?, confirm}`: `confirm` must be the site's short name, exactly. ServanaGo takes a backup of the current state first, then overwrites the chosen parts. Request only the parts the user asked for.
5. Verify with `backup_status` / `list_backups` and `unit_status` if the site runs a unit.

Never guess `confirm` to get past an error; a wrong value means you have the wrong site.
