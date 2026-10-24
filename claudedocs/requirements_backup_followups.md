# Backup follow-ups: requirements

Scope: MCP backup tools, volume restore from the UI. Panel restore from the UI is out of scope for good (decision below). Builds on `requirements_site_backup.md` and `design_site_backup.md` (M11e, released in 0.7.3).

## Decisions (settled)

- D1 Panel restore is CLI only (`servanago backup restore --panel`). Never a UI route, a helper action or an MCP tool.
- D2 MCP may start a site restore, not only read and back up. Chosen knowing the only guard is the MCP bearer token (no password re-check, no 2FA).
- D3 A volume restore stops the containers that mount the volume and restarts them afterwards. ServanaGo does the stop/start itself.

## A. MCP backup tools

Goal: an MCP client can see backup state, start a backup and start a site restore through the same code paths as the UI.

Functional
- FR-A1 `backup_status` (read-only): enabled, panel on/off, folder, default schedule, keep counts, job state (running/idle), stale/failed banner text, last result per scope. Never the passphrase or ntfy URL; only "set / not set".
- FR-A2 `list_backups` (read-only): archives per scope from the sidecars (name, time, size, parts, damaged flag), optional site filter. Recent runs (status, error text clipped) as in the UI.
- FR-A3 `run_backup`: scope `all`, `panel` or a site id. Same refusals as the page: backups disabled, job already running, no passphrase.
- FR-A4 `restore_site`: site id, archive name, `files` and/or `dumps` (and `volumes` once part B ships), plus a required `confirm` argument equal to the site's short name (the MCP counterpart of typing it). Takes the pre-restore backup first, like the UI. Returns "started"; the result is read later through `list_backups`.
- FR-A5 Every write tool is audited as `mcp token` (`backup.run`, `backup.restore`) and goes through the existing helper actions.

Out of scope for MCP: changing settings, passphrase or ntfy, profile and volume rows, archive download (the file is encrypted and large), panel backup restore (D1).

Non-functional
- NFR-A1 Read tools carry `ReadOnlyHint`. Tool output never includes secrets; archive and error text is data, not instructions.
- NFR-A2 No new privileged path: tools call the same web handlers' logic or the helper client as the UI does.
- NFR-A3 `update_site` must not reset backup fields: `formOf` in `internal/web/mcp.go` has to carry them (known trap). Verify, with a test.

Acceptance
- Each tool has a test through the MCP endpoint with the bearer token; a wrong or missing token is refused as for other tools.
- `restore_site` with a wrong `confirm`, an archive of another site, or nothing selected is refused and starts no job.
- A test asserts no MCP tool, route or helper action restores the panel (D1).

## B. Volume restore from the UI

Goal: restore one opted-in Docker volume of a site from one of its archives, from the Backups page.

Functional
- FR-B1 The restore form gains a `volumes` choice per volume the archive holds (`volumes/<name>/`) and that is still opted in for the site. Same guards as today: archive belongs to the site, typed short name, password (and code) re-check.
- FR-B2 Order: verify archive checksum, find the containers that mount the volume (Docker API), take a pre-restore backup of the site (which includes the volume), stop those containers, replace the volume contents, start the containers that were running before. Containers that were already stopped stay stopped.
- FR-B3 The restart happens on every exit path, including a failed extract. The result row says which containers were stopped and restarted.
- FR-B4 Abort before touching anything if the pre-restore backup fails, a container cannot be stopped, or the volume no longer exists.
- FR-B5 Replace means: remove the volume's current contents, then extract. Files not in the archive do not survive. State this beside the checkbox.
- FR-B6 Audit `restore.done` / `restore.failed` with the volume names, as now.

Non-functional
- NFR-B1 The volume path comes from the Docker API (`GET /volumes/NAME`), never a concatenated path; the extract is confined to it. Traversal protection stays; symlinks follow D5.
- NFR-B2 Restore is crash-consistent at best, same as the backup. The UI says so.
- NFR-B3 The stop/start capability lives in the job (root, already talks to the Docker socket for `docker exec` dumps) behind a typed request field, not a free-form command. Only containers that mount the named volume are ever touched.
- NFR-B4 Not atomic across files, volume and dumps: the pre-restore archive is the way back.

Acceptance
- Fake-Docker tests: running container stopped then restarted; stopped container left stopped; extract failure still restarts; stop failure aborts with nothing changed; unknown volume refused.
- A round trip test with a real archive restores file content and modes into a temp "volume".
- Fuzz or table test: volume name outside the site's opted-in list, traversal in entry names, and symlinks in the archive are rejected.

## Settled questions

- D4 MCP `restore_site` accepts `volumes` too (FR-A4), guarded by the token plus `confirm` = short name. Accepted risk: the token alone can stop containers and replace their data.
- D5 Volume extract mode: symlinks are allowed when the target stays inside the volume; owner and mode are kept; traversal, absolute escapes, device nodes and setuid are still refused; sockets are skipped (the app recreates them).
- D6 Shared volume: every running container that mounts it is stopped, including other sites' containers. The UI confirm text and the MCP result name them.
- D7 Keeping containers down: stop, re-check state just before the extract, and abort with nothing changed if any is running again (restart those that were up). Restart policy is not modified.

## Remaining gaps

1. Panel restore pointer: the Backups page and help text do not name `servanago backup restore --panel` (checked). Add the command beside the panel archives and in the help hint.
2. MCP has no way to show the other-site container list before restoring: `restore_site` returns the list in the result, but the `confirm` is given up front. Decide in design whether a `plan_restore` read tool (lists containers, what would be replaced) is added; D2/D4 make it worth having.
3. Stopping containers is new privilege for the job (until now it only reads and `exec`s); design must keep it behind a typed request field and touch only containers that mount the named volume.

## Next

`/sc:design` for the job's Docker stop/start step and the extractor mode, then `/sc:workflow` for stages. Suggested order: A (small, no new privilege), then B.
