# Site backup: design (2026-10-23)

Input: `claudedocs/requirements_site_backup.md` (all questions resolved). Output: architecture, schema, helper actions, UI, tests, stages. No implementation code.

## 1. Shape

```
 timer (every 15 min) ──┐
 UI "Back up now" ──► servanago (unprivileged) ──helper socket──► helper (root)
 CLI `servanago backup` ┘                                            │ writes request.json, starts
                                                                     ▼
                                       servanago-backup.service  (oneshot, root, nice/ionice)
                                       ExecStart: servanago backup-job run|restore
                                            │ reads DB (read-only) + EnvironmentFile for the secret key
                                            │ per scope: snapshot → tar → zstd → age(passphrase) → file + sidecar
                                            ▼
                         /var/backups/servanago/<scope>/<scope>-<UTC>.tar.zst.age  (+ .json sidecar)
                         /var/backups/servanago/.runs/<runid>.json  (result files)
                                            ▲
 servanago ingests .runs/*.json every minute → backup_runs table, audit_log (actor system), banner state
 job itself sends the ntfy push on failure
```

Decisions that shape everything:

- **One unit, one timer, job decides what is due.** `servanago-backup.timer` fires every 15 minutes (`OnCalendar=*:00/15`, `Persistent=yes`). The job evaluates each scope's schedule against its last successful run. Per-site overrides therefore need no per-site timer and a schedule edit needs no unit rewrite. Presets: `hourly`, `daily@HH:MM`, `weekly@DOW@HH:MM` (UTC? no: host local time, shown as such).
- **The job reads its plan from SQLite itself; the helper request carries no secrets and no plan.** The helper actions take only a scope and a mode. Dump credentials stay sealed in SQLite; the job (root) opens them with `SERVANAGO_SECRET_KEY` from `EnvironmentFile=/etc/servanago/servanago.env`, the same file `servanago.service` uses. Nothing sensitive crosses the socket or sits in `request.json`.
- **The job never writes the live SQLite DB.** A root process creating `-wal`/`-shm` files in a DB owned by `servanago` could lock the service out. The job opens the DB `mode=ro`, and results go to `.runs/*.json` (root:servanago 0640) which the service ingests.
- **Archives are readable by the service.** Directory `0750 root:servanago`, files `0640 root:servanago`. They are encrypted, so group read is acceptable, and it lets the UI list and download without a helper round trip for bytes (the helper protocol is one JSON line).
- **Dependencies: `filippo.io/age` (new) and `github.com/klauspost/compress/zstd` (already in the module graph as indirect; hand-edit `go.mod` to direct).** age because the archive stays decryptable with the stock `age -d` tool and a passphrase on any machine after total loss of v1 (no servanago needed); no home-made crypto format. Scrypt work factor is age's default. Alternative rejected: DIY chacha20poly1305 from x/crypto.

## 2. Package layout

| Path | Role |
|---|---|
| `internal/backup` | Pure core: schedule (`Due`), retention (`Prune`), manifest, archive writer/reader (tar→zstd→age), safe extract, SQLite snapshot, dump argv builders, `Env` seam struct (clock, FS roots, `Exec`, docker, ntfy POST), `RunScope`, `Restore`. No systemd, no root assumptions: runs against temp dirs in tests. |
| `internal/store` (`backup.go`, `migrations/005_backup.sql`) | Settings columns, site columns, profiles, volumes, runs. |
| `internal/helper` (`backup.go`) | Typed actions, unit/timer templates, `Seam` additions. |
| `cmd/servanago` (`backupjob.go`, `backup.go`) | `backup-job run|restore` (unit entry, mirrors `phpjob.go`) and `backup run|list|restore|prune|verify` (admin CLI, works with the UI down). |
| `internal/web` (`backups.go`, templates) | Backups page, Settings section, site-form section, download, restore, ingest goroutine, banner. |

## 3. Schema: migration `005_backup.sql` (additive; bump `user_version` to 5 in `TestMigrationsIdempotent`)

```
settings:
  backup_enabled     INTEGER NOT NULL DEFAULT 0
  backup_dir         TEXT    NOT NULL DEFAULT '/var/backups/servanago'
  backup_pass        BLOB                       -- secretbox-sealed passphrase; NULL = not set
  backup_sched       TEXT    NOT NULL DEFAULT 'daily@03:00'
  backup_keep        INTEGER NOT NULL DEFAULT 7  -- newest N archives
  backup_keep_weekly INTEGER NOT NULL DEFAULT 4  -- plus newest archive of each of the last M ISO weeks
  backup_panel       INTEGER NOT NULL DEFAULT 1  -- include the panel scope
  backup_ntfy        BLOB                       -- secretbox-sealed https URL (may carry a token)

sites:   (all NULL/0 = inherit global)
  backup_on          INTEGER NOT NULL DEFAULT 0 CHECK (backup_on IN (0,1))
  backup_sched       TEXT                       -- override preset
  backup_keep        INTEGER
  backup_keep_weekly INTEGER

backup_profiles:     -- typed dump profile, many per site
  id INTEGER PK, site_id FK ON DELETE CASCADE,
  name TEXT NOT NULL,                           -- label inside the archive: dumps/<name>.*
  engine TEXT NOT NULL CHECK (engine IN ('mariadb','postgres','sqlite')),
  container TEXT NOT NULL DEFAULT '',           -- mariadb|postgres: docker container name
  db_name TEXT NOT NULL DEFAULT '',
  db_user TEXT NOT NULL DEFAULT '',
  secret BLOB,                                  -- sealed DB password
  path TEXT NOT NULL DEFAULT '',                -- sqlite: relative to the site root
  UNIQUE (site_id, name)

backup_volumes:      -- opt-in docker volume tarballs
  site_id FK ON DELETE CASCADE, volume TEXT, PRIMARY KEY (site_id, volume)

backup_runs:         -- ingested from .runs/*.json; history is capped to the newest 2000 rows
  run_id TEXT PRIMARY KEY, scope TEXT NOT NULL,   -- 'panel' or a site slug (text, survives site deletion)
  trigger TEXT NOT NULL,                          -- schedule | manual | pre-restore | cli
  started_at INTEGER, finished_at INTEGER,
  status TEXT NOT NULL CHECK (status IN ('ok','failed','skipped')),
  bytes INTEGER NOT NULL DEFAULT 0, archive TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT ''
```

`TargetKind` (container versus tcp) is deliberately absent: v1 dumps mariadb/postgres only through `docker exec`; a `tcp` target needs host client binaries that v1 does not have. Adding it later is an additive migration.

## 4. Archive and manifest

Name: `<dir>/<scope>/<scope>-<YYYYMMDDTHHMMSSZ>.tar.zst.age` where scope is `panel` or the site slug. `panel` passes the slug regex, so **the site slug `panel` is reserved** and slug validation must reject it (v1 has no such site).

Tar contents (all names relative, regular files/dirs/symlinks only, uid/gid/uname/gname preserved):

```
manifest.json
files/…               site root (the directory the site serves from and its parent as configured), for static/php/node/cgi/fastcgi/frankenphp
dumps/<profile>.sql   mariadb-dump   |  dumps/<profile>.pgdump (pg_dump -Fc)  |  dumps/<profile>.sqlite (VACUUM INTO)
volumes/<volume>.tar  docker volume contents
panel/servanago.db    VACUUM INTO snapshot
panel/caddy/…         ACME account, certs
panel/caddy-last-good.json
panel/servanago.env   the secret key (the whole reason the archive is encrypted)
```

Sidecar `<archive>.json` (plain, no secrets) next to the archive: scope, run id, start/finish, host, servanago version, schema `user_version`, parts `[{name, kind, bytes, sha256}]` (sha256 of plaintext parts, recorded while streaming), `archive_sha256` (of the encrypted file), and the profile/volume names. Listing in the UI reads sidecars only. A sidecar without a matching archive, or the reverse, is shown as damaged and never counted toward retention.

Write order: stream to `…​.part`, fsync, write sidecar `.part`, rename sidecar then archive (archive last: it is the commit). Any failure removes the `.part` files. A failed scope never leaves a listed archive.

SQLite snapshots (panel DB and file-based site DBs): copy the DB plus any `-wal`/`-shm` into the job's scratch directory (`PrivateTmp`), open the copy, `VACUUM INTO` the output. This never creates files in the live directory, and it is crash-consistent for WAL databases. Verified at job time with `PRAGMA integrity_check` on the output.

Docker volumes: resolve the mountpoint through the Docker API (`GET /volumes/NAME`), never by concatenating a path. Crash-consistent only; the UI says so beside the field.

## 5. Dump profiles (typed, no free-form commands)

The job builds argv itself; the strings from SQLite are validated at run time again (the DB is written by the unprivileged web process, so the job treats rows as untrusted):

- `container`: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` and present in `docker-list` as running.
- `db_name`, `db_user`: `^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,63}$`, never starting with `-`.
- sqlite `path`: relative, clean, no `..`, resolved with `EvalSymlinks` and confined under the site root.
- mariadb: `docker exec -i -e MYSQL_PWD <container> mariadb-dump -u <user> --single-transaction --routines --triggers --events <db>` (fallback binary `mysqldump` when `mariadb-dump` is absent in the image, decided by a fixed two-name probe).
- postgres: `docker exec -i -e PGPASSWORD <container> pg_dump -U <user> -Fc <db>`.
- The password goes in the child's environment (`cmd.Env`), forwarded by the bare `-e NAME`; it is never on any argv. stderr is clipped to 200 characters before it enters a result file, an audit row or an ntfy body.
- Timeout per dump (default 30 minutes), output size capped by free space checked before the run.

Risk accepted and stated: a compromised web process can write a profile row. The constraints above (running container, fixed argv, charset-limited names, confined sqlite path) limit that row to dumping databases of containers that already exist on the host. The same actor can already add proxy sites to those containers.

## 6. Helper actions (typed, in the closed set; spec fields added to `Spec`, strict decode retained)

| Action | Spec fields | Effect |
|---|---|---|
| `backup-enable` | `enabled` bool | Installs (or removes) `servanago-backup.service` and `.timer` from the helper's templates, `daemon-reload`, enable/disable the timer. Verifies units with `systemd-analyze verify`. Refuses when no passphrase is set. |
| `backup-start` | `scope`: `all` \| `panel` \| `site`, `slug` (site only) | Writes `request.json` in the job dir, starts the unit. Refuses when a run is active. Manual runs ignore "due" and run the scope now. |
| `backup-restore` | `slug`, `archive` (file name, regex-checked, must exist under `<dir>/<slug>/`), `restore_files` bool, `restore_dumps` bool | Same unit, `op: restore`. The job first runs a `pre-restore` backup of the site. Volumes are never restored by this action. |
| `backup-status` | none | Job phase from `state.json`, unit state, journal tail. |

`Seam` additions (interface, `RealSeam`, `fakeSeam`): none beyond existing `Exe`, `WriteFile`, `StartUnit`, `UnitStatus`, `UnitLogs`, `VerifyUnit`, `DaemonReload`, `Enable`, `DisableUnit`, `DockerList`, `FreeBytes`. The job (not the helper) does the heavy work, so the helper stays small. Docker volume lookup and `docker exec` live behind `internal/backup.Env`, not `Seam`.

Unit (template, helper-owned, fixed content):

```
[Service] Type=oneshot, User=root, EnvironmentFile=/etc/servanago/servanago.env
ExecStart=<exe> backup-job run  (restore: backup-job restore)
Nice=10  IOSchedulingClass=idle  MemoryMax=2G  TimeoutStartSec=8h
NoNewPrivileges=yes  PrivateTmp=yes  ProtectSystem=full  ProtectKernelTunables=yes  ProtectControlGroups=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER
```

`ProtectSystem=full` (not `strict`) because restore writes into admin-chosen site roots anywhere; `ProtectHome` stays off for the same reason. Verify the capability set with `systemd-run --user` equivalents where possible and on v1 by hand (first real run is a gate in Stage 7).

## 7. Job algorithm

`backup-job run`:

1. Open DB read-only; read settings, derive the passphrase with the secret key. No passphrase or no key: write a `failed` result, notify, exit non-zero.
2. Determine scopes: from `request.json` (manual) or, for the timer, every enabled scope whose preset says it is due now and has no successful run since its last scheduled slot (injected clock; missed slots collapse into one run).
3. Check free space for the estimated size (sum of source sizes × 1.1) on the backup dir; skip with `status: skipped` and a clear error when short.
4. For each scope sequentially: build the part list, stream tar→zstd→age to `.part`, hash while writing, write sidecar, rename, then prune that scope (retention below), then write `.runs/<runid>.json`. One scope failing never stops the next.
5. On any `failed` result, POST the ntfy message (title `ServanaGo backup failed`, body `<scope>: <clipped error>`).

Retention: keep the newest `keep` archives, plus the newest archive in each of the last `keep_weekly` ISO weeks (union). Only files matching this feature's name pattern with a valid sidecar are candidates; `pre-restore` archives follow the same rule but are never the only reason another is pruned. Pure function, table-tested.

`backup-job restore`: verify `archive_sha256` against the sidecar before decrypting; decrypt and read `manifest.json` first; refuse a manifest whose scope differs from the request; run the `pre-restore` backup of the current state (abort the restore if it fails); then per requested part:

- files: extract into the site root as an overlay. Every entry is checked: relative, no `..`, no absolute path, no device/fifo/socket, no setuid/setgid bits, symlinks must resolve inside the root, no write through an existing symlink in the destination path, `EvalSymlinks` confinement against the current site root recorded in the DB (not the manifest). Ownership is restored by name when the user exists, else numeric. Files absent from the archive are not deleted.
- dumps: sqlite file replaced atomically beside the original (same mode and owner); mariadb piped into `mariadb`; postgres `pg_restore --clean --if-exists --no-owner` into the named database. The UI shows these as destructive and names the target.

The panel scope is restored only by the CLI (§9).

## 8. Web (UI)

- **Settings** (`/settings`, new "Backups" block): enable, directory, default preset, keep / keep-weekly, panel on/off, passphrase (write-only field; shows "set" and the date; changing it warns that older archives still need the old one), ntfy URL (sealed, write-only). Saving with enable on calls `backup-enable`. Needs re-auth to change the passphrase.
- **Site edit** (`siteedit.html`): "Backup" section: enable, schedule override, retention override, profile rows (add/remove via `hx-post` with `form="none"` inputs and `hx-include`, same pattern as the gate access rows), volume rows for proxy sites. A site form without the backup fields leaves them untouched, and `formOf` (`internal/web/mcp.go`) must carry the new fields or MCP `update_site` resets them (known trap). `$id` bound before any `range` (known template trap).
- **Backups page** (`/backups`): table of scopes with last status, last success, size, next due; "Back up now" per row and for all; archive list per scope with download and restore buttons; run history. Download is `POST /backups/download` with the password field (re-auth), streaming the file with `Content-Disposition: attachment`; the file name is regex-checked and resolved inside the scope directory. Restore is `POST /backups/restore` with password, part checkboxes, and a confirm that names the site; answers 204 + `HX-Redirect` per project convention.
- **Banner**: shown on every page when backups are enabled and a scope has had no successful run within twice its interval (hourly → 2 h, daily → 48 h, weekly → 14 d), or the last run of any scope failed.
- **Ingest**: a goroutine in `servanago` (1-minute ticker, same pattern as the PHP checker) reads `.runs/*.json`, inserts into `backup_runs` idempotently by `run_id`, writes audit events `backup.ok` / `backup.failed` / `backup.skipped` / `restore.done` / `restore.failed` (actor `system`; manual runs record the starting user via the request file's `actor`), then deletes the result file. A missing or unreadable `.runs` is logged once, not a crash.
- **Audit and re-auth**: `backup.download`, `backup.restore`, `backup.passphrase` are audited with the acting user; the three require the account password.
- **MCP**: read-only tools `list_backups` and `backup_status`; `run_backup` is allowed, restore and download are not exposed over MCP.

## 9. CLI (works without the UI)

```
servanago backup run [--scope panel|SLUG|all]     # root; same code as the job
servanago backup list [SLUG]
servanago backup verify ARCHIVE                  # checksum vs sidecar, decrypt to /dev/null, manifest present
servanago backup prune [SLUG]
servanago backup restore --panel ARCHIVE         # service stopped; refuses newer schema; atomic DB swap; restores caddy/ env/ files
servanago backup restore --site SLUG ARCHIVE [--files] [--dumps]
```

Passphrase for the CLI comes from `--passphrase-file` or stdin, never argv. Fresh-host recovery: install the deb, stop `servanago`, `servanago backup restore --panel`, start, then per-site restores. The archive also opens with `age -d` and a tar extract if servanago itself is unavailable; document this in the README.

## 10. Security notes

- Passphrase and dump passwords: `secretbox`-sealed in SQLite, never logged, never in a request body to the helper, never in ntfy text or audit rows, never in argv.
- The job treats every DB row and every path as untrusted (§5, §7); extract and snapshot code is fuzzed.
- Archives hold the secret key and TOTP seeds: encrypted always; plaintext never lands in the backup directory (scratch is `PrivateTmp`, tmpfs not guaranteed, so scratch files are removed on every exit path and limited to SQLite copies).
- Download of an archive gives an attacker with an admin session offline attack material; age scrypt plus a long passphrase is the control. The passphrase form enforces a minimum length (20 characters or a generated one offered).
- No claim of tenant isolation (project rule).
- `ntfy` URL must be `https`; the job refuses redirects to non-https.

## 11. Tests

Unit, in `internal/backup` (no root, temp dirs, injected clock and `Exec`):

- `Due`: presets × edge times (DST change, missed slots, never run, run just before the slot). Reject malformed presets.
- `Prune`: keep N and weekly union, damaged pairs ignored, `pre-restore` handling. After writing, mutate the pruning guard once to see it go red.
- Archive round trip: files, dumps, volumes, manifest; sha256 per part; archive sha256 vs sidecar; wrong passphrase fails; truncated archive fails; `age -d` interoperability when the `age` binary is present (skip otherwise, not fail).
- SQLite snapshot of a WAL database with a live writer; output passes `integrity_check`; no files created in the source directory.
- Safe extract table + fuzz (`FuzzExtractNoEscape`): `..`, absolute names, NUL, symlink then write-through, hardlink, device nodes, setuid, over-long names, tar bombs (entry count and size caps). Each row asserts why it failed.
- Dump argv: table test per engine, and `FuzzDumpArgvNoInjection` (the fake `Exec` must be given what the builder reads first, or the fuzz is vacuous); asserts the password is never in argv.
- Failure isolation: scope A fails, scope B still produces an archive; `.part` files removed.

Helper (`fakeSeam`): each action's validation rows (slug, archive name regex, missing passphrase, run already active, enable/disable writes exactly the two templates, templates pass the injection fuzz).

Store: migration 005 on a fresh DB and on a 004 DB, cascade deletes, runs cap, sealed columns round trip.

Web (`newServer`, `runtimeServer`): settings save seals the passphrase; re-auth required for passphrase, download, restore (wrong password rows assert the reason, one `newServer` per throttle path); site form posts leave backup rows untouched when absent; MCP `update_site` does not reset them (`formOf`); Backups page and site edit render to the end (`>Save</button>`, `</form>`); ingest is idempotent; banner logic with an injected clock; download rejects traversal in the file name.

e2e (Playwright): settings → enable → site with a sqlite profile → "Back up now" runs `servanago backup run` against a temp dir through a test `Deps` seam (the e2e server is not root and has no systemd), archive appears, download works with the password, restore round trip on a fixture site. Real systemd, docker and root behaviour is not covered here.

Manual gate on v1 (Stage 7): first real run, each of mariadb, postgres, sqlite dump, restore of one small site into a scratch copy, and `age -d` of a real archive on the workstation.

## 12. Staged plan

| Stage | Goal | Success criteria | Status |
|---|---|---|---|
| 1 | `internal/backup` core | Schedule, retention, manifest, archive round trip, SQLite snapshot, safe extract + fuzz green | Not Started |
| 2 | Dump profiles | Argv builders, validators, fake docker/exec seam, fuzz green | Not Started |
| 3 | Store + migration 005 | Settings, site columns, profiles, volumes, runs; sealed columns; `user_version` 5 | Not Started |
| 4 | Job, CLI, helper | `backup-job run|restore`, `servanago backup …`, four helper actions, unit/timer templates, fuzz, `pre-restore` | Not Started |
| 5 | Web | Settings block, site-form section, Backups page, download, restore, reauth, MCP read tools | Not Started |
| 6 | Ingest, audit, ntfy, banner | Result files become runs and audit rows; ntfy on failure; banner rule tested | Not Started |
| 7 | Release | `make check`, docs (README, DESIGN, ROADMAP, help text), packaging tests, version bump, manual v1 gate | Not Started |

Each stage: failing test first, `make check`, commit on a branch (not `main`).

## 13. Deploy notes for v1

- Migration `005` applies on start; copy the DB first (`servanago.db.pre-<ver>`), as with 0.5.0.
- First use: set the passphrase in Settings and store it off-box before pressing enable. The panel archive is the only place v1's secret key is copied to.
- `/var/backups/servanago` lives on the same disk as everything else: until the later remote target exists, the Download button (or an `rsync` from your workstation as a user in group `servanago`) is the off-box copy. Say this on the Backups page.
- Estimated size per full cycle with current sites: roughly 0.5 GB per daily run (dominated by `luckyedward.com`), about 6 GB at keep 7 + 4 weekly, against 188 GB free.

## 14. Deferred

Remote targets (S3-compatible, SFTP), tcp dump targets, extra paths, incremental storage, UI panel restore, volume restore from the UI.

## 15. Confirmed by the user (2026-10-23)

- Presets use host local time, shown as such in the UI.
- Site slug `panel` is reserved (reject in slug validation).
- `ProtectSystem=full` for the backup unit; first real v1 run is the capability-set gate in Stage 7.

Still for Stage 1: check `filippo.io/age` builds with Go 1.26 (`go get filippo.io/age@<ver>`, hand-edit `go.mod` if `go mod tidy` fails on `./data`).
