# Design: startup schema self-heal

Companion to `requirements_migration_selfheal.md` (settled 2026-10-27). Not implemented.

## Approach

One new file, `internal/store/repair.go`, plus a few lines in `store.Open` (internal/store/store.go:47-51).
No new CLI, no new packages, no systemd changes. The `store.Open` callers are `cmd/servanago/main.go` (server),
`reset.go` (the `user` and `2fa-reset` CLI), `import.go` and `backupjob.go`. The helper and the php-job never open
the DB. `backupjob.go:92` opens a *snapshot copy* of the live DB, so it uses `OpenSnapshot(path)`: same as `Open`
without repair and vintage gate (the daemon repairs the live DB; a repair beside a copy would be wrong).

Repair runs **before** `migrate`, keyed on the actual schema, not `user_version`: a future migration that touches
`sites` columns must never meet a legacy DB. Flow in `Open`:

```
Open(path)
  ├─ db := sql.Open(...)
  ├─ repaired, err := repairLegacy(db, path)
  │    ├─ no `sites` table (fresh DB)  -> return false, nil          // migrate builds it
  │    ├─ vintage gate (below): not met -> hard error, nothing touched
  │    ├─ probe each legacy object (pragma reads only)
  │    ├─ all present          -> return false, nil          // v1, current DBs: zero writes
  │    ├─ snapshot: VACUUM INTO <db>.pre-repair (file DBs only)
  │    ├─ BEGIN IMMEDIATE; re-check; ALTER/CREATE each missing; COMMIT
  │    └─ one slog.Info per created object
  ├─ migrate(db)                        // unchanged: 002..005 by user_version
  ├─ st := &Store{db, q: db}
  ├─ if repaired { st.AddAudit(context.Background(), {system, schema.repaired, database}) } // non-fatal
  └─ return st
```

## Vintage gate

Repair applies only when the DB already has everything the repair cannot add: `sites.fpm_version`,
`sites.extra_routes` (both in `sites`), and a `sites` CREATE statement (`sqlite_master.sql`) whose kind CHECK
contains `'cgi'`. ALTER cannot change a CHECK, so a DB with an older kind CHECK would be "repaired" and still
reject fastcgi/cgi sites. Anything older is refused with a message naming the missing piece:
`database <path> predates Servanago 0.2.0 (sites.extra_routes missing); not repairable`.

## The repair list (closed)

DDL is copied verbatim from `001_init.sql` (line refs current) and executed only when the
object is absent:

| Object | Check | DDL |
|---|---|---|
| `sites.php_extensions` | `pragma_table_info` | `ALTER TABLE sites ADD COLUMN php_extensions TEXT NOT NULL DEFAULT ''` (001:37) |
| `sites.php_health_path` | `pragma_table_info` | same shape (001:38) |
| `sites.site_user` | `pragma_table_info` | same shape (001:39) |
| `sites.public_dir` | `pragma_table_info` | same shape (001:40) |
| `sites_site_user` index | `sqlite_master` type=index | `CREATE UNIQUE INDEX sites_site_user ON sites (site_user) WHERE site_user != ''` (001:63) |
| `settings.php_check_json` | `pragma_table_info` | `ALTER TABLE settings ADD COLUMN php_check_json TEXT NOT NULL DEFAULT ''` (001:182) |
| `settings.php_checked_at` | `pragma_table_info` | same shape (001:183) |
| `php_user_defaults` | `sqlite_master` type=table | `CREATE TABLE php_user_defaults (username TEXT PRIMARY KEY, version TEXT NOT NULL CHECK (version != ''))` (001:188) |

**Known limit: CHECK constraints.** `ALTER TABLE ADD COLUMN` cannot add table-level CHECKs, so a repaired DB
lacks the `001` cross-column CHECKs on `site_user`, `public_dir`, `php_extensions` and `php_health_path`
(001:41-43). The application validates these values, so the effect is a weaker backstop, not a behavior change.
A rebuild of `sites` would restore them but is out of scope (data-moving, FK-heavy). The sync guard therefore
compares columns and indexes only, and the docs must not claim "identical to a fresh DB".

Probing before any write: a DB that fails the vintage gate is refused before the probe list runs. Existing rows are safe: added columns default to `''`/`0`, which
satisfy every sites CHECK (001:41-43) for the old kinds; the index on `site_user != ''` is
empty until a site names a user. `php_user_defaults` needs no seed rows — `ReconcilePHP` and
the form handlers create rows on demand.

## Snapshot

- `VACUUM INTO '<dir>/<db>.pre-repair'` — consistent, works on WAL, ships inside the binary
  (modernc), no host `sqlite3`. Delete a stale `.pre-repair` first (VACUUM INTO refuses an
  existing target), then `os.Chmod(0o600)` and `os.Chown` to the owner of the DB file (a root-run CLI must not leave
  a root-owned snapshot in the `servanago` data dir) — the file carries password hashes.
- Taken only when the probe found ≥1 missing object, before the repair tx. Failed ALTER →
  `Open` returns the error with the snapshot already on disk; operator has the old state.
- `:memory:` (tests/fresh) never has gaps, so no path special-casing beyond that.
- Re-run after a failure: the ALTERs are one transaction, so a failed repair leaves the DB unchanged; the next
  `Open` probes the same gaps and re-makes the snapshot.

Atomicity: the ALTERs run in one `BEGIN IMMEDIATE` tx re-checking inside the tx, so a repair
half-fails as a unit and a concurrent `store.Open` (CLI while daemon runs) either no-ops or
fails visibly with `duplicate column` and succeeds on retry. No lock protocol beyond that.

## Evidence

- One `slog.Info("schema repair", "object", "sites.site_user")` per created object.
- One audit row after commit: actor `system`, action `schema.repaired`, target `database`,
  time `now` UTC RFC3339. Write failure is `slog.Error`, never rolls back the ALTERs
  (same rule as `apply.Service.audit`). `audit_log` exists in every 0.1.0+ vintage (M2.5
  predates the first release).
- Refusals (below the vintage gate) get a hard `Open` error naming the missing piece (see Vintage gate).
  The repo fossil `data/servanago.db` then fails with that message instead of leaking
  `no such column` mid-process.

## Refusal matrix

| DB state | user_version | Outcome |
|---|---|---|
| Empty file / no `sites` table | 0 | repair skipped, migrate builds it |
| Current 001 or v1-like complete | 1 or 5 | pure probe reads, no audit row, no snapshot |
| Bee vintage (gate met, lacks repair set) | 1 | repaired, snapshot, then migrate 002..005, audit row |
| Below the gate (no `fpm_version`, no `extra_routes`, or kind CHECK without `'cgi'`) | any | `Open` error, DB untouched |
| `OpenSnapshot` (backup job copy) | any | no repair, no gate; migrate only |
| Migration itself fails (e.g. corrupt) | — | unchanged behavior: migrate's error |

## Test plan (unit only, stdlib, file DBs in `t.TempDir()`)

Fixture = the bee-vintage schema (everything up to 9cc2e79^ in `001_init.sql`), captured once at design time
from git (`git show 9cc2e79^:internal/store/migrations/001_init.sql` → `internal/store/testdata/old001.sql`)
and embedded. Verified against bee's live DB (2026-10-27): it has `extra_routes` and `fastcgi` in the kind CHECK
and lacks the four `sites` columns. Executed with raw `database/sql` at `user_version = 1`, plus one site/user row
each. `:memory:` never exercises the file paths, so all tests use file paths.

1. `TestRepairAddsMissingLegacyObjects` — Open the fixture: succeeds; all 8 objects exist;
   site/user rows intact; `.pre-repair` exists (mode 0600); one `schema.repaired` audit row;
   migrations 002..005 applied (`user_version` 5).
   **Sync guard**: compare `pragma_table_info` rows (name, type, notnull, dflt_value, pk) and index definitions of
   the repaired objects against the same rows of a fresh-`Open` DB — drift between the DDL
   list and 001 turns this red. (CHECKs are not compared; see the known limit.)
2. `TestRepairIsIdempotent` — second `Open` of the repaired file: no new writes
   (`.pre-repair` mtime/content unchanged, still one audit row).
3. `TestOpenHealthyDBRepairsNothing` — fresh `Open`: no `.pre-repair`, no `schema.repaired` row.
4. `TestOpenRefusesBelowVintageGate` — table: fixture minus `fpm_version`; minus `extra_routes`; kind CHECK
   without `'cgi'`. Each: `Open` errors naming the missing piece (assert the substring); file byte-identical
   afterwards. Mutate the gate once to see it red.
4b. `TestOpenSnapshotDoesNotRepair` — `OpenSnapshot` on the fixture: no `.pre-repair`, no repair.
5. `TestRepairSnapshotFailureAborts` — unwritable DATA_DIR (guard: skip when euid == 0):
   `Open` errors, DB unchanged.

`TestMigrationsIdempotent` and the golden tests are untouched. e2e unaffected (fresh DBs).

## Resolved open questions (from the requirements)

- Snapshot: `VACUUM INTO`, Go-side — decided.
- Audit name: `schema.repaired` — decided.
- `php_user_defaults` seeding: none needed — decided (row creation is on-demand).

## Non-goals (unchanged from requirements)

- No generic schema oracle beyond the closed list, no downgrades, no retroactive `NNN_*.sql`,
  no repair of the repo fossil DB, no rebuild of `sites` to restore CHECKs.

## Deployment note

Ships in the next patch release; bee self-repairs on first start after the dpkg upgrade
(no PHP build in progress). v1: no-op pass. Requirements doc gains one line in its FR2
inventory (`sites_site_user` index) — updated there, not re-brainstormed.