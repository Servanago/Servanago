# Site backup: requirements (brainstorm 2026-10-23)

Status: requirements only. No design or code. Next step: `/sc:design`.

## Investigation of v1 (ssh v1, Ubuntu 24.04.5, 244G disk / 188G free, 11G RAM)

- No backups today: no cron/timers, no restic/borg/rclone. Present: rsync, tar, zstd, gpg, sqlite3. Only copies are `servanago.db.pre-<ver>` on the same disk.
- ServanaGo state (~4 MB): `/var/lib/servanago` (`servanago.db` + WAL, `caddy/` ACME account and certs, `caddy-last-good.json`), `/etc/servanago/servanago.env` (holds `SERVANAGO_SECRET_KEY`; without it sealed TOTP seeds, SMTP password, site env values and gate secrets in a restored DB are unreadable). Regenerable: `/etc/servanago/{fpm,php,php-users}`, `servanago-*.service`, `/opt/servanago/php` (269M).
- Site roots: `/home/<domain>/public_html`, dirs `drwx--x--x` owned by the site user, so reading needs root. Sizes: briantafoya.com 44M, luckyedward.com 385M (incl. `storage/database.sqlite` 32M), rustzerobbs.com 540K, rest ~20K.
- 14 of 19 sites are `proxy` kind to containers not managed by ServanaGo: 27 containers, 10 docker volumes (1.4G): MariaDB 10.6 (x4), Postgres 16/17 (x3), Redis, Forgejo, n8n, trilium, ntfy, mixpost, glitchtip.
- Other data: `/home/linuxuser/luckyedward-archive` 7.6G (outside scope unless added).
- Constraints from the codebase: web UI never runs as root; privileged work is typed helper actions with no free-form strings; site files are never chowned; schema changes are new `NNN_*.sql` migrations; `DESIGN.md` currently says import/export is out of scope and a DB copy is the backup.

## Decisions (from the user)

| Topic | Decision |
|---|---|
| Scope | ServanaGo-managed state plus site files plus per-site DB dumps |
| DB dumps | Typed dump profiles (mariadb / postgres / sqlite), helper builds argv; no free-form commands |
| Target | Local directory first; remote target (S3-compatible/SFTP) later |
| Schedule | Global default schedule + per-site override + manual "Back up now" |
| Protection | Encrypted archives |
| Restore | From the UI per site (files and/or DB), plus archive download from the UI |
| Alerts | Backups page status + audit log, ntfy push, stale-backup banner |

## Functional requirements

- FR-1 Panel backup: consistent snapshot of `servanago.db` (SQLite online backup, not a raw copy of a live WAL DB), `caddy/` data dir, and the env/secret-key file.
- FR-2 Site file backup: for each opted-in site of kind static/php/node/cgi/fastcgi/frankenphp, archive its root (and `public_dir` parent as configured) read as root through the helper. Respect existing path validation (clean absolute roots, EvalSymlinks confinement).
- FR-3 Site DB backup: a site may declare one or more dump profiles (engine mariadb|postgres|sqlite, target = container name or host:port or file path, database name, credentials sealed with `secretbox`). The helper builds the dump command itself. SQLite uses the online backup API.
- FR-4 Proxy sites: backup applies only through their dump profiles (and optionally named docker volumes, open question below). Nothing else about the container is touched.
- FR-5 Scheduling: global default schedule (default daily 03:00, via systemd timer), per-site override (schedule and retention), per-site opt-in, "Back up now" for one site or all.
- FR-6 Retention: keep-N policy, global default, per-site override; pruning only removes archives this feature created.
- FR-7 Encryption: every archive is encrypted at rest. Key handling must not make the archive the only holder of the key that decrypts it.
- FR-8 Local store: archives written to a configured absolute directory (default under `/var/backups/servanago`), mode 0700/0600, free-space check before a run.
- FR-9 Restore from UI per site: choose an archive, then files, DB, or both; requires password re-auth; takes a pre-restore snapshot first; audit-logged; never chowns site files.
- FR-10 Download from UI: stream an archive to the browser; requires re-auth; audit-logged.
- FR-11 Backups page: per site last run, status, size, duration, error text, archive list; panel backup row.
- FR-12 Alerts: audit events (`backup.ok`, `backup.failed`, `restore.*`), ntfy push on failure (topic URL in Settings), banner when no success within 2x the schedule.
- FR-13 CLI parity: `servanago backup run|list|restore|prune` so recovery works with the web UI down.

## Non-functional requirements

- NFR-1 No secrets in logs, audit rows or ntfy bodies. Dump credentials sealed at rest, never on argv visible to other users (use env or a root-only temp file).
- NFR-2 Backup never restarts or blocks `servanago` or running site units; low impact (nice/ionice) on a host with 11G RAM serving production.
- NFR-3 A failed run for one site does not stop others; partial archives are discarded, never listed as good.
- NFR-4 Integrity: each archive carries a checksum and manifest (contents, versions, schema `user_version`); verify before restore.
- NFR-5 Restore of the panel DB must refuse an archive from a newer schema than the binary.
- NFR-6 Helper actions typed, re-validated, fuzzed (traversal, symlinks, NUL, injection through profile fields), per project rules.
- NFR-7 Schema change is a new `NNN_*.sql` migration; `TestMigrationsIdempotent` `user_version` bumped.
- NFR-8 Unix-user separation is not a sandbox: do not claim tenant isolation for backups.

## User stories and acceptance

- As the admin I enable backup on `luckyedward.com`, add a sqlite profile for `storage/database.sqlite`, press "Back up now", and see an encrypted archive with a manifest listing files and the DB snapshot. Accept: archive listed, size shown, checksum verified, audit row written.
- As the admin I add a mariadb profile to the `billing` proxy site and the nightly job dumps it from the container without stopping it. Accept: dump present in the archive, restore into a scratch DB succeeds.
- As the admin I restore one site's files from last Tuesday. Accept: re-auth required, pre-restore snapshot taken, files replaced, no ownership changes, audit row.
- As the admin I do not look at the panel for a week and the job silently fails. Accept: ntfy push on the first failure, banner after 2x the interval.
- As the admin I lose v1 entirely and recover from a downloaded archive on a new host. Accept: documented CLI procedure restores DB, certs and env on a fresh install.

## Resolved open questions

1. Key (FR-7): separate backup passphrase, set in Settings (sealed in SQLite), kept by the admin off-box. Not derived from `SERVANAGO_SECRET_KEY`.
2. Docker volumes (FR-4): opt-in named-volume tarballs per proxy site (crash-consistent only; live DBs use a dump profile). This also covers Redis/Forgejo/n8n/trilium/ntfy file data; no per-app exporters in v1.
3. Arbitrary extra paths (e.g. `/home/linuxuser/luckyedward-archive`): out of v1.
4. Format: full tar+zstd+encrypt per run, standalone archives. No dedup store. Estimate ~6G at keep 7+4 for current sites.
5. Panel DB restore: CLI only, service stopped. UI restore covers sites only.
6. Schedule input: presets (hourly, daily HH:MM, weekly weekday HH:MM) mapped to systemd OnCalendar.
7. Job: systemd oneshot started via the helper, like the PHP build jobs; root, nice/ionice, journal logging.

## Open questions

None blocking. Detail choices (archive layout, manifest fields, helper action names, migration number) belong to `/sc:design`.

## Next

`/sc:design` for archive format, helper actions, schema and job model; then `/sc:workflow` for staged implementation.
