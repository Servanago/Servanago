# Design: startup schema self-heal

Companion to `requirements_migration_selfheal.md` (settled 2026-10-27). Not implemented.

## Approach

One new file, `internal/store/repair.go`, plus ~6 lines in `store.Open` (internal/store/store.go:47-51).
No new CLI, no new packages, no systemd changes. Every `store.Open` caller (server, `user add`,
`2fa-reset`, `import`, `reset`, `php-job`, the backup job's snapshot) inherits repair and the vintage gate.

Flow in `Open`, after `migrate(db)`:

```
Open(path)
  ├─ migrate(db)                        // unchanged: 002..005 by user_version
  ├─ st := &Store{db, q: db}
  ├─ repaired, err := st.repairLegacy()
  │    ├─ vintage check: sites.fpm_version absent -> hard error, nothing touched
  │    ├─ probe each legacy object (pragma reads only)
  │    ├─ all present          -> return false, nil          // v1, fresh DBs: zero writes
  │    ├─ snapshot: VACUUM INTO <db>.pre-repair (file DBs only)
  │    ├─ BEGIN IMMEDIATE; re-check; ALTER/CREATE each missing; COMMIT
  │    └─ one slog.Info per created object
  ├─ if repaired { st.AddAudit(context.Background(), {system, schema.repaired, database}) } // non-fatal
  └─ return st
```

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

Probing before any write, in the vintage order above: a DB missing `fpm_version` is refused
before the probe list runs. Existing rows are safe: added columns default to `''`/`0`, which
satisfy every sites CHECK (001:41-43) for the old kinds; the index on `site_user != ''` is
empty until a site names a user. `php_user_defaults` needs no seed rows — `ReconcilePHP` and
the form handlers create rows on demand.

## Snapshot

- `VACUUM INTO '<dir>/<db>.pre-repair'` — consistent, works on WAL, ships inside the binary
  (modernc), no host `sqlite3`. Delete a stale `.pre-repair` first (VACUUM INTO refuses an
  existing target), then `os.Chmod(0o600)` — the file carries password hashes.
- Taken only when the probe found ≥1 missing object, before the repair tx. Failed ALTER →
  `Open` returns the error with the snapshot already on disk; operator has the old state.
- `:memory:` (tests/fresh) never has gaps, so no path special-casing beyond that.
- Re-run after a partial failure: probe shrinks, snapshot is re-made, no double-ALTER.

Atomicity: the ALTERs run in one `BEGIN IMMEDIATE` tx re-checking inside the tx, so a repair
half-fails as a unit and a concurrent `store.Open` (CLI while daemon runs) either no-ops or
fails visibly with `duplicate column` and succeeds on retry. No lock protocol beyond that.

## Evidence

- One `slog.Info("schema repair", "object", "sites.site_user")` per created object.
- One audit row after commit: actor `system`, action `schema.repaired`, target `database`,
  time `now` UTC RFC3339. Write failure is `slog.Error`, never rolls back the ALTERs
  (same rule as `apply.Service.audit`). `audit_log` exists in every 0.1.0+ vintage (M2.5
  predates the first release).
- Refusals (pre-0.1.0 vintage) get a hard `Open` error naming the vintage:
  `database <path> predates Servanago 0.1.0 (sites.fpm_version missing); not repairable`.
  The repo fossil `data/servanago.db` then fails with that message instead of leaking
  `no such column` mid-process.

## Refusal matrix

| DB state | user_version | Outcome |
|---|---|---|
| Fresh (current 001) or v1-like complete | 5 | pure probe reads, no audit row, no snapshot |
| 0.1.0 vintage (has `fpm_version`, lacks repair set) | 1→5 via migrate | repaired, snapshot + audit row |
| Partially repaired (earlier crash) | 1→5 | remainder repaired, fresh snapshot |
| Pre-0.1.0 (no `fpm_version`) | 1 | `Open` error, DB untouched |
| Migration itself fails (e.g. corrupt) | — | unchanged behavior: migrate's error |

## Test plan (unit only, stdlib, file DBs in `t.TempDir()`)

Fixture = the real 0.1.0 schema, captured once at design time from git
(`git show 9cc2e79^:internal/store/<schema path>` → `internal/store/testdata/old001.sql`)
and embedded. Executed with raw `database/sql` at `user_version = 1`, plus one site/user row
each. `:memory:` never exercises the file paths, so all tests use file paths.

1. `TestRepairAddsMissingLegacyObjects` — Open the fixture: succeeds; all 8 objects exist;
   site/user rows intact; `.pre-repair` exists (mode 0600); one `schema.repaired` audit row.
   **Sync guard**: compare `pragma_table_info` rows (name, type, notnull, dflt_value, pk) of
   the repaired objects against the same rows of a fresh-`Open` DB — drift between the DDL
   list and 001 turns this red.
2. `TestRepairIsIdempotent` — second `Open` of the repaired file: no new writes
   (`.pre-repair` mtime/content unchanged, still one audit row).
3. `TestOpenHealthyDBRepairsNothing` — fresh `Open`: no `.pre-repair`, no `schema.repaired` row.
4. `TestOpenRefusesPre01Vintage` — fixture minus `fpm_version`: `Open` errors with the
   vintage message; file byte-identical afterwards.
5. `TestRepairSnapshotFailureAborts` — unwritable DATA_DIR (guard: skip when euid == 0):
   `Open` errors, DB unchanged.

`TestMigrationsIdempotent` and the golden tests are untouched. e2e unaffected (fresh DBs).

## Resolved open questions (from the requirements)

- Snapshot: `VACUUM INTO`, Go-side — decided.
- Audit name: `schema.repaired` — decided.
- `php_user_defaults` seeding: none needed — decided (row creation is on-demand).

## Non-goals (unchanged from requirements)

- No generic schema oracle beyond the closed list, no downgrades, no retroactive `NNN_*.sql`,
  no repair of the repo fossil DB.

## Deployment note

Ships in the next patch release; bee self-repairs on first start after the dpkg upgrade
(no PHP build in progress). v1: no-op pass. Requirements doc gains one line in its FR2
inventory (`sites_site_user` index) — updated there, not re-brainstormed.