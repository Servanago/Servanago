# Backup follow-ups: design

Implements `requirements_backup_followups.md` (decisions D1-D7): five MCP backup tools and Docker volume restore from the UI and MCP. No schema change, no migration. Panel restore stays CLI only (D1).

This design was written against the code as released in 0.7.3. Where it differs from the requirements, the section "Corrections to the requirements" says so.

## What exists (verified)

- `backup.RestoreSite(ctx, e Env, p Plan, archive, files, dumps)`: verifies the checksum, takes a `pre-restore` backup, then streams the archive once; `files/` entries go through `Extractor`, `dumps/` through `restoreDump`. Volumes are ignored. Callers: `cmd/servanago/backup.go`, `cmd/servanago/backupjob.go`, `internal/backup/run_test.go`.
- `Extractor` accepts directories, regular files and symlinks only. A symlink is created as a link and never followed, any entry below a symlink is refused, modes are masked with `0o777`, anything else is an error.
- `Env.Chown` is `lchownFromHeader` (job, root only): `OwnerFromHeader` maps by user name when the name exists on the host, else numeric id.
- `internal/backup/docker.go`: GET-only client on `/var/run/docker.sock` (10 s timeout, 4 MB body cap); `DockerVolume` (mountpoint must lie under `/var/lib/docker/volumes/`), `DockerRunning`.
- Archives hold `volumes/<name>/…`; the manifest lists `Volumes []string`. The plan carries the site's opted-in `Volumes`.
- Helper `BackupRestore` takes `slug`, `archive`, `restore_files`, `restore_dumps` and writes `request.json` (`BackupRequestData{Op, Scope, Slug, Archive, Files, Dumps, Actor}`); the job reads and deletes it, then calls `RestoreSite`.
- Web `restoreBackup` (form: site, name, files, dumps, sure, password) and `runBackup`; both call helper actions. `mcpRun` runs a web handler with a synthesized form as `mcpActor`, but handlers that call `s.confirm` (password re-check) cannot be reached that way.
- MCP: tools are registered in `mcpServer` with `ro` annotations for reads; writes are audited as `mcp token`.

## Corrections to the requirements

1. **D5 symlink rule dropped.** "Symlinks stay if the target remains inside the volume" is not needed and would break valid volumes: the extractor never follows a symlink, so a link (absolute or `..`) cannot make the restore write outside the volume. Absolute links are normal inside containers. Volume mode reuses the existing symlink handling unchanged.
2. **Ownership must be numeric.** `OwnerFromHeader` prefers the user *name* on the host. For a volume, container uid 999 `postgres` would be mapped to the host's `postgres` (a different uid). Volume restore chowns with the archived `Uid`/`Gid` only.
3. **Sockets and fifos.** The extractor errors on any other type. Volume mode skips FIFOs (and anything the archive cannot hold: Go's `tar.FileInfoHeader` refuses sockets). Device nodes and hard links stay refused with a clear error. Open check: confirm `AddTree` skips sockets when *backing up*; if it fails on one, such a volume cannot be backed up today.
4. **Mode bits.** The extractor keeps only `0o777`, so sticky and setgid directory bits are lost on restore. Accepted for volumes (setuid stays refused by policy).
5. **D7 is a backstop.** `POST /containers/{id}/stop` marks a container as stopped by hand, and Docker's restart policies do not restart it afterwards. The re-check before extracting stays, but a restart race is unlikely rather than expected.
6. **Dumps and volumes together.** A dump restore needs its database container *running*; a volume restore stops it. One restore may select both, so volumes run in their own pass first, containers restart, then the existing files/dumps pass runs. The archive is therefore decrypted twice in that case.
7. **FR-B3 / result detail.** `Result` has no notes field and `backup_runs` has no column for one; adding it needs migration 006. Default taken: failures put the container names in `Error`; on success the names go to the journal only. Say so if you want a column.

## Design

### `internal/backup`

`docker.go`
- `dockerDo(method, path string, okCodes ...int) ([]byte, error)` replaces the body of `dockerGet` (which stays as the GET wrapper). Per-call timeout 10 s, 70 s for stop.
- `type Container struct { ID, Name string; Running bool }`
- `ContainersUsing(volume string) ([]Container, error)`: `GET /containers/json?all=1&filters={"volume":["NAME"]}`. The name passes `ValidVolume`, the filter JSON is built with `json.Marshal`, never concatenated.
- `StopContainer(id)`: `POST /containers/{id}/stop?t=30` (204, 304 ok). `StartContainer(id)`: `POST /containers/{id}/start` (204, 304 ok). `ContainerRunning(id)`: `GET /containers/{id}/json`, `State.Running`. IDs are checked as 12 to 64 hex characters before use.
- No other container operation exists. Nothing takes a free-form id or command.

`run.go`
- `Env` gains four seams, replaced in tests: `Users func(volume string) ([]Container, error)`, `Stop func(id string) error`, `Start func(id string) error`, `IsRunning func(id string) (bool, error)`; and `VolumeChown func(path string, h *tar.Header) error` (numeric).
- `type RestoreOpts struct { Files, Dumps bool; Volumes []string }`; `RestoreSite(ctx, e, p, archive, o)`.
- Order inside `RestoreSite`:
  1. Name check, `VerifyChecksum`, `m.Scope == p.Scope` (as now).
  2. Every `o.Volumes` entry must be in `p.Volumes` (still opted in) and in `m.Volumes` (in this archive); otherwise abort naming the volume. Nothing selected at all is an error.
  3. `resolveRoot`, then the `pre-restore` backup (as now). It runs before any container is touched.
  4. If volumes were chosen: `restoreVolumes` (below).
  5. If files or dumps were chosen: the existing pass.
- `restoreVolumes(ctx, e, path, volumes)`:
  1. Resolve every directory through `e.Volume` first; one failure aborts before anything is stopped. A directory must match `^/var/lib/docker/volumes/[^/]+/_data$`.
  2. Collect `e.Users(v)` for each volume; the set of running ones is `stopped`, de-duplicated by id.
  3. `defer` restart: start every container in `stopped` (reverse stop order), on every exit path; start errors are joined into the returned error.
  4. Stop each; then re-check with `e.IsRunning`. If any is running again: abort, nothing changed.
  5. Open the archive (second decrypt), one pass: on the first entry under `volumes/<v>/` for a chosen volume, empty that directory's children (`os.ReadDir` + `os.RemoveAll` per child; the directory itself is kept), then extract with `Extractor{Dest: dir, Chown: e.VolumeChown, Volume: true}`. A chosen volume with no entries in the stream is an error (the manifest said it exists), found after the pass, with the pre-restore archive named.
  6. A failure mid-pass leaves the volume partly restored; the error says so and names the pre-restore archive.
- Journal (`slog`): which containers were stopped and restarted, per volume.

`extract.go`
- `Extractor.Volume bool`: skips `tar.TypeFifo` entries; everything else unchanged. Hard links, devices and unknown types still error.

### `cmd/servanago`

- `backupjob.go`: `request.json` gains `Volumes []string`; `execute` passes `RestoreOpts`. `openJob` sets `env.VolumeChown = lchownNumeric` (root only; `os.Lchown(path, h.Uid, h.Gid)`) and wires the real Docker functions into the new `Env` seams.
- `backup.go` (CLI): call updated to `RestoreOpts{Files, Dumps}`; no `--volume` flag now (YAGNI; add when asked).

### `internal/helper`

- `Vals`: `RestoreVolumes []string`. `BackupRestore` validates each with `backup.ValidVolume`, at most 20, no duplicates; at least one of files, dumps, volumes. `BackupRequestData` gains `Volumes`. The existing archive-name and slug checks stay.
- New read-only action `backup-volume-users`: `slug` plus `volumes`, returns per volume the containers using it (`name`, `running`). It checks the volumes against nothing stored (the helper has no DB); it only reads Docker. Added through the `Seam` interface (`VolumeUsers(volume)`), `RealSeam` (calls `backup.ContainersUsing`) and `fakeSeam`.
- The helper never stops or starts containers. Only the job does, and only for volumes in a validated restore request.

### `internal/web`

- Core split so MCP can call the same logic without a password re-check:
  - `startBackup(r *http.Request, scope, slug string) error`
  - `startRestore(r *http.Request, site store.Site, archive string, o backup.RestoreOpts) error`
  `startRestore` does: archive in the list and not damaged (`scopeArchive`), selection non-empty, volumes ⊆ site's opted-in ∩ manifest, helper call, audit `backup.restore` with slug, archive and volume names, flash. Errors carry an HTTP status (small `statusErr{code, msg}`).
  `runBackup`/`restoreBackup` keep form parsing, the typed `sure` check and `s.confirm`, then call these.
- `mcpRequest(ctx, ip) *http.Request` is factored out of `mcpRun` (request with `mcpActor` and the client address) so the MCP tools can pass a request to the cores for audit and actor.
- Backups page, restore form per archive (site scopes only): a "Volumes" group with one checkbox per volume that is in this archive and still opted in, beside the text "Replaces everything in the volume. Containers that use it are stopped and started again." and the containers per volume from `backup-volume-users` (called once per page render for the opted-in volumes; on error the group shows "Container list unavailable" and the checkboxes stay enabled, since the job re-checks). The form posts `volumes` (repeated).
- Panel rows: the text "Restore a panel archive from the command line: servanago backup restore --panel" plus a help hint `backup_panel_restore` (plain text; avoid `<`, `>` and the word docker, see the help tests).

### MCP tools (`internal/web/mcp.go`)

| Tool | Args | Does | Annotations |
|---|---|---|---|
| `backup_status` | none | enabled, panel on/off, folder, default schedule, keep counts, passphrase and ntfy "set" flags, job state (helper `backup-status`), stale/failed banner text, last result per scope | read-only |
| `list_backups` | `scope` (optional): `panel` or a site slug | archives from sidecars (name, time, size, parts, volumes, damaged), newest runs (status, clipped error) | read-only |
| `run_backup` | `scope`: `all`, `panel` or a site slug | `startBackup`; audit `backup.run` | write |
| `plan_restore` | `id` (site), `archive` | what the archive holds (files, dumps, volumes from the manifest), which volumes may be restored (opted in ∩ in archive), containers per volume with running flag, and a warning list | read-only |
| `restore_site` | `id`, `archive`, `files`, `dumps`, `volumes[]`, `confirm` | requires `confirm` == the site's short name exactly, then `startRestore` | write |

- All tools: no passphrase, no ntfy URL, no archive contents; error and path text is data.
- `restore_site` returns "started" and the volume list; the outcome is read later with `list_backups`.
- Not exposed: settings, passphrase, ntfy, profile and volume rows, download, panel anything (D1).
- A test walks the registered tool list and the route table and fails if any name or path contains panel restore.
- `formOf` check: confirm `update_site` does not reset backup fields (NFR-A3) with a test that updates a site that has backup settings.

## Security notes

- Container control is the new privilege. It sits in the job (root), is reachable only through a validated `request.json` written by the helper, takes volume names that pass `ValidVolume` and are in the site's opted-in list and in the archive's manifest, and can only stop and start containers that mount one of those volumes.
- The extract target is the Docker-reported mountpoint, pattern-checked; the extractor refuses traversal, writes through links and special files; the "clear" step removes children of that exact directory only.
- MCP restore (D2, D4) is guarded by the token plus the exact short name in `confirm`. The token has no 2FA or password step; an attacker holding it can overwrite a site and replace container data, after a pre-restore backup. Accepted.

## Tests

Backup package (fake `Env`, temp dirs; no real Docker):
- running container is stopped, the volume replaced, the container started; a container that was stopped before stays stopped.
- extract failure still restarts; stop failure aborts with nothing changed and restarts the ones already stopped; a container reported running again after stop aborts the restore.
- unknown volume, volume not opted in, volume not in the archive: rejected before any stop.
- `pre-restore` failing aborts before any stop.
- numeric ownership is passed to `VolumeChown` (a header with `Uname: "postgres", Uid: 999` never resolves a host name).
- symlink entries restored as links (absolute and relative), FIFO skipped, device node and hard link refused, `..` and absolute names refused, a symlink entry followed by a child below it refused.
- children of the volume directory are removed, stale files do not survive; the directory pattern check refuses `/var/lib/docker/volumes/x` and `/var/lib/docker/volumes/x/_data/..`.
- volumes plus dumps in one restore: volumes run first, containers are running when the dump pass starts.
- Mutate each guard once (`if false &&`) and see it red.

Helper: `BackupRestore` rejects bad volume names, more than 20, duplicates, nothing selected; `backup-volume-users` through `fakeSeam`; a fuzz target for the volume list given what the action reads first (`builtSeam`-style, so the fuzz is not vacuous).

Web: restore with volumes posts `volumes`, refuses a volume not in the archive, shows the container list and the panel CLI text; `TestEveryHintIsPlainNonEmptyText` and the docker-word test stay green. Page-complete assertions (`>Save</button>`, `</form>`).

MCP: each tool through the endpoint with the bearer token; wrong token refused; `restore_site` with a wrong `confirm`, another site's archive, or an empty selection starts nothing; `plan_restore` and `list_backups` leak no secret; the no-panel-restore walk.

Real-host checks (v1, not automatable): restore a small volume of a real container (stop, replace, start, app works); a volume with a symlink; ownership of a postgres or redis volume after restore; a compose container with a restart policy stays down during the extract; `docker` unavailable gives a clear refusal.

## Stages

Each is a branch commit after `make check`; none needs a migration.

| # | Stage | Success |
|---|---|---|
| 1 | `backup`: Docker ops, `Extractor.Volume`, `RestoreOpts`, `restoreVolumes` | the backup-package tests above pass |
| 2 | Job and CLI wiring: `Volumes` in `request.json`, `VolumeChown`, real Docker seams | job-level test restores a volume through a fake Docker |
| 3 | Helper: `RestoreVolumes`, `backup-volume-users`, `Seam.VolumeUsers`, fuzz | helper tests and fuzz green |
| 4 | Web: `startBackup`/`startRestore` split, restore form volumes, panel CLI text and hint | web tests green; existing backup tests unchanged |
| 5 | MCP: five tools, `mcpRequest`, `formOf` check | MCP tests green |
| 6 | Docs: ROADMAP row (deferred list shrinks), help text, requirements/design cross-links; v1 first-run checks | `make check`, then deploy only when asked |

Order matters: 1 to 3 give the engine, 4 and 5 are independent of each other after 3. MCP tools `backup_status`, `list_backups` and `run_backup` could ship without 1 to 3, but `restore_site` and `plan_restore` need them.

## Defaults taken (change on request)

- Success detail (stopped/restarted containers) goes to the journal, not the run row (needs migration 006).
- No `--volume` on the CLI restore.
- Sticky and setgid directory bits are not restored.
- A stop timeout of 30 s per container; a container that does not stop in time aborts the restore.
