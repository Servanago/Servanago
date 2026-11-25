# M13 step 1: migration 013 rehearsal plan

Status: plan only, 2026-11-25. Nothing in step 1 is written yet; this gates it. Design: `design_corvus_features.md` §4, §11, §16.

What 013 does to live data: rebuilds `sites` (new kind `page` in the CHECK), adds `site_guard`, `site_x402`, `site_page`, `bans`, `guard_settings`, `alert_dests`, `site_alert_dests`, and copies `settings.scan_ntfy`(+token) and `settings.backup_ntfy` into `alert_dests`. 011 emptied child tables on bee once (sqlite3 CLI ran with FK off); `migrate()` now runs rebuilds with FK off.

## Order

1. Write `013_guard.sql` and its tests first (red): `TestMigrationsIdempotent` user_version 13, `TestMigrationRebuildKeepsChildRows` extended (seed `site_hostnames`, `dns_records`, `waf_exclusions`, a gate grant, snippet attachments), the ntfy copy (both configured, only one, none), `TestEveryKindHandled` (kinds parsed from the CHECK).
2. Green on a fresh DB and on `testdata/old001.sql` lineage through `Open`.
3. Rehearse on a copy of the local DB, through a real Store, never the sqlite3 CLI. **v1 (and timmy) are never touched during development**: no ssh, no copies, no queries. Production DBs only meet 013 at a deploy Brian asks for.
   - bee (this machine): `sudo -n sqlite3 -readonly /var/lib/servanago/servanago.db ".backup SCRATCH/servanago.db"`, `chown` to yourself, then `printf 'pw\n' | DATA_DIR=SCRATCH bin/servanago user add rehearsal` (Open applies 013).
   - Anything bee cannot cover (a v1-shaped DB) comes from fixtures: `testdata/old001.sql` lineage plus a seeded DB built in the test.
4. Per copy, compare before/after: per-table row counts for every pre-existing table (must match), `PRAGMA foreign_key_check` empty, `PRAGMA integrity_check` ok, `PRAGMA user_version` 13, the `sites` row count and a checksum of `id, slug, kind, hostnames` per site, `alert_dests` rows equal to configured ntfy values (blob bytes identical to the source), audit row present.
5. Delete the copies (they hold password hashes and sealed secrets).
6. Only then build anything that reads the new tables.

## Stop conditions
Any count mismatch, a `foreign_key_check` row, or a changed `sites` checksum: stop, fix the migration, rerun from step 3. Three failed attempts: stop and report.

## Deploy note (when asked)
Pre-upgrade copy `servanago.db.pre-0.21.0` as in the v1 upgrade procedure; the rebuild is not reversible except by that copy.
