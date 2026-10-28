# Requirements: startup self-heals hand-edit-era schema gaps

Status: settled 2026-10-27 (brainstorm). Design not started.

## Problem

`store.Open` runs `migrate(db)` (internal/store/store.go:56), which applies every embedded
`NNN_*.sql` above `PRAGMA user_version`. That is correct for the migration system (from 0.5.0):
new schema always ships as a new `NNN_*.sql`, so applying 002+ carries everything.

But before 0.5.0, schema changes edited `001_init.sql` in place. A DB created from an
old `001` has `user_version = 1` **forever**: the runner skips 001, so the in-place deltas are
never applied, and `migrate` ends "fully migrated" while columns are missing.

Real case, bee (dpkg install, 0.1.0-era DB, upgraded to 0.10.0 2026-10-27): start at
11:59:14 logged `stored config rejected error="SQL logic error: no such column: php_extensions (1)"`,
fell back to last-known-good config, and reconcile fails; hourly
`php release check failed ... no such column: php_check_json (1)`. Service stays active and
degrades. v1 is unaffected (hand-converted at 0.2.0/0.3.0). The repo-adjacent
`data/servanago.db` is a `user_version = 1` fossil, not backing any install.

## Decision

Self-heal on start (user, 2026-10-27): startup verifies the actual schema and repairs the
known gap set itself, after a consistent DB backup — no operator step, same spirit as
"Caddy and DNS converge at startup".

## Functional requirements

1. **Verify after migrate.** `store.Open` must determine, from the actual schema
   (`pragma_table_info` / table list), whether the DB misses any known object. `user_version`
   is not trusted for this.
2. **Closed repair set.** Repair covers exactly the objects added by the two in-place `001`
   edits, nothing else:
   - v0.2.0 (9cc2e79): `sites.php_extensions`, `sites.php_health_path`, `php_user_defaults`
     table, `settings.php_check_json`, `settings.php_checked_at`
   - v0.3.0 (ef714d8): `sites.site_user`, `sites.public_dir`, the partial unique index
     `sites_site_user` (001:63)
   The definitions used must be the current `001_init.sql` ones. New schema changes never
   enter this list; they are `NNN_*.sql` migrations only.
3. **Vintage gate.** Repair applies only when the DB is at least 0.1.0 vintage
   (`sites.fpm_version` present — 0.1.0's 001 had it). An older DB (no `fpm_version`) is
   unsupported: `Open` refuses with a descriptive error naming the vintage, never partially
   repairs. (Covers the repo fossil DB: refuse, do not half-fix.)
4. **Backup before any ALTER.** Before creating the first object, take a consistent snapshot
   (`VACUUM INTO` or `sqlite3 .backup` path is a design choice), named like the existing
   convention (`<db>.pre-repair`, gitignored `*.pre-*` pattern). If the snapshot fails, no
   repair happens and `Open` fails with its error. No dependence on a host `sqlite3` binary.
5. **Repair evidence.** One journal line per created object plus one system audit event
   (actor `system`) for the repair as a whole, following `config.bootstrapped` precedent.
6. **Every entry point covered.** Because repair lives in the `store.Open` path, server
   start, CLI (`user add`, `2fa-reset`), helper DB use and the php job all get it — no
   caller may see "no such column" after a successful `Open`.
7. **Idempotent.** On a complete DB the whole pass is pure reads (v1 unaffected). On a
   repaired DB, the second start creates nothing and logs nothing.
8. **Failure mode.** If an ALTER fails, `Open` returns a descriptive error (fail fast, with
   the snapshot already on disk); the app does not run half-repaired.

## Non-functional

- Healthy-startup cost: a handful of `pragma_table_info` reads, negligible.
- No secrets in logs or audit rows (repair logs object names only).
- Startup philosophy kept: fail fast on unusable DB, banner path unchanged for config issues.

## Acceptance criteria (failing test first)

1. **Bee vintage.** Fixture DB with 0.1.0-era `sites` (has `fpm_version`, lacks the repair
   set) and `user_version = 5`: `Open` succeeds, all 7 objects exist with current-001
   definitions, pre-existing rows intact, snapshot file exists.
2. **Idempotence.** Opening the fixture twice: second run performs no ALTERs/creates.
3. **Healthy DB.** Current-001 fixture: verification is a no-op, no snapshot written, no
   audit row.
4. **Pre-0.1.0 vintage.** Fixture without `fpm_version`: `Open` errors, message names the
   vintage, nothing modified.
5. **Repair failure.** Snapshot failure (e.g. unwritable dir): `Open` errors, DB unchanged.

Bee deployment acceptance: upgrade bee with a build containing this code, start once,
journal shows repair + no `no such column` errors, reconcile succeeds, Audit page shows the
event.

## Open questions (design phase)

- `VACUUM INTO` vs external snapshot; audit event name (proposal `schema.repaired`).
- Exact definitions sync: how repair SQL stays in sync with `001_init.sql` (a test that
  diffs them is the cheap guard).
- Does `php_user_defaults` need its seed row(s) on a repaired DB, or does `ReconcilePHP`
  create them?

## Explicitly out of scope

- A full generic expected-schema oracle, reverse migrations, downgrades.
- Repairing the repo fossil `data/servanago.db` (refused by the vintage gate).
- Retroactive `NNN_*.sql` for already-shipped in-place edits (they are unreachable for
  future DBs; only legacy DBs carry the gap, which the repair set covers).