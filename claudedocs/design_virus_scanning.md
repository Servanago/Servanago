# Design: Site virus scanning

Requirements: `claudedocs/requirements_next_features.md` §5 (settled). No implementation here; stages at the end.

## Shape

ClamAV's `clamd` does the scanning; ServanaGo is the driver. It talks the clamd socket (`PING`, `zINSTREAM`, verdict `stream: <name> FOUND`), walks a site's served webroot, and moves hits into a quarantine under `DATA_DIR`. Signature updates, file size limits and the daemon itself stay ClamAV's business — ServanaGo never installs, updates or configures clamd (runtimes-are-detected rule).

```
scan (manual/sweep/backup) → walk webroot → stream each file to clamd → verdict
  hit → quarantine move (DATA_DIR/quarantine/<slug>/) + scan_hits row + notify (ntfy urgent + SMTP mail)
       → site badge, scan page, MCP, audit
```

## Data model — migration `006_scan.sql`

```sql
ALTER TABLE settings ADD COLUMN scan_socket TEXT NOT NULL DEFAULT '';   -- clamd socket; empty = feature off
ALTER TABLE settings ADD COLUMN scan_hour   INTEGER NOT NULL DEFAULT 3; -- sweep hour 0-23
ALTER TABLE settings ADD COLUMN scan_ntfy   BLOB;                       -- sealed https:// topic URL, optional
ALTER TABLE settings ADD COLUMN scan_ntfy_token BLOB;                   -- sealed access token, optional

CREATE TABLE scan_runs (   -- one row per site per scan
  id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  trigger TEXT NOT NULL,            -- manual | sweep | backup
  started_at INTEGER NOT NULL, finished_at INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL,              -- running | ok | error
  files INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE scan_hits (
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL, path TEXT NOT NULL,           -- absolute original path
  virus TEXT NOT NULL, action TEXT NOT NULL,              -- live | quarantined | restored | ignored | error
  quarantined_to TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0
);
```

Settings edits must not lose data in a migration (ALTER ADD only). `store_test.go`'s hard-coded `user_version` assertion bumps to 6. Retention: keep the newest 50 runs per sweep trigger, delete older (hits cascade).

## `internal/scan` package

```go
type Client struct{ ... }                       // clamd unix socket
func New(socket string) *Client
func (c *Client) Ping(ctx) error                // PING → PONG health check
func (c *Client) Scan(ctx, path string) (Verdict{Clean | Hit{Name} | TooBig | Err{err}}, error) // zINSTREAM
type Walker func(root string, fn func(rel string, info fs.FileInfo) error) error — no, plain WalkDir inside ScanTree
func (c *Client) ScanTree(ctx, root string, hit func(path, virus string)) (files, skipped int, err error)
```

- Walk: `filepath.WalkDir`, skip symlinks (CountSkipped), skip files > 100 MB (`TooBig`, skipped counter — clamd's own `StreamMaxLength` default), per-file context timeout 60 s, sequential (ponytail: clamd parallelizes internally; site-level Parallel only when a sweep visibly lags).
- Quarantine move lives in `scan`: `Quarantine(path) (to string, err error)` renames into `DATA_DIR/quarantine/<slug>/<unix>-<n>-<base>` (dir made 0750 under the panel's user; the panel user already owns DATA_DIR). Cross-fs rename failure or `EPERM` (site files may belong to the site user) → the hit stays `live` with the move error recorded — never a crash, never a chown.
- `Restore(to, original)` refuses when `original` already exists; `Ignore` only marks the row.
- Re-alarm control: a hit for a `path + virus` whose latest hit row is `quarantined` or `ignored` does not notify again.

## Scheduler and process model

Scans run as goroutines of the panel process (clamd holds the heavy signature load; nothing to supervise):

- `Server.RunScans(ctx)`: hourly tick, modeled on `RunPHPChecks`; a sweep is due when the local clock passed `scan_hour` and the newest `trigger='sweep'` run is older than today's. Walks every enabled site that has a served root (`kind != node/proxy`, `StaticRoot != ""`), one run row each, state from start to finish; sweep failures (clamd down) are logged + one audit `scan.sweep` row with the error, no retry storm.
- Manual scan: the site page / MCP start a detached goroutine (`detached()` context, 30 min cap) and return at once; the UI polls the badge/page.
- Restart mid-scan: a run row left `running` is marked `error` ("interrupted by restart") on the next `Open` — sweeps re-run daily anyway.

## Notifications

- ntfy: `scan/notify.go` POSTs the sealed `scan_ntfy` URL, `Priority: urgent`, `Title: ServanaGo virus scan`, body = site + virus + path (never more), `Authorization: Bearer` when `scan_ntfy_token` is sealed, 10 s timeout, https-only redirect guard (same shape as the backup job's `notify`).
- Email: existing Settings SMTP via `s.sendMail` to the Mail-From mailbox (same convention as the PHP-release notice), one mail per sweep/manual run with hits.
- Sends happen once per run (new `quarantined`/`error` hits only), after the run commits.

## Web UI

- Settings gains a "Virus scanning" fieldset (like Backups'):
  socket path (label: the Debian default `/run/clamav/clamd.ctl`), sweep hour select, ntfy topic URL + access token (both sealed, "stored"/"clear" pattern), notify-on-hits checkbox. Tests for sealing and blank-keeps follow the backup row.
- New `/scan` page: runs table (site, trigger, state pill, files, hits, when) newest first, filter per site; hits table under a run with per-hit actions: Quarantined rows get **Restore** and **Ignore** (`hx-confirm`), `live` rows get **Quarantine**, `ignored` rows get **Restore**. Every action audits (`scan.hit_quarantined` etc., actor = admin or `mcp token`).
- Site page: badge chip from the latest run (`scan-ok` / `scan-error` statuses reuse the `.dns-*` pill styling classes with a scan-* variant… no new color tokens — reuse `cert-issued`/`cert-error` classes) + "Scan now" button next to the Resync DNS row. Disabled sites / kinds without a root: no button.
- Scan page nav: Operations group (after Backups). `RunScans` starts with the server like RunPHPChecks.

## MCP tools

| Tool | Args | Notes |
|---|---|---|
| `run_scan` | `id` (site) | starts the detached scan, returns run id |
| `list_scan` | `site?` | recent runs + hits (+ running flag) |
| `quarantine_hit`, `restore_hit`, `ignore_hit` | `id` (hit) | the three hit actions |

`toolLike` verb regex in `skills_test.go` gains `scan|quarantine|ignore`. Skills: servanago-sites tool list + servanago-mcp read/write lists ("since" = next minor).

## Backup integration

`backup.Env` gains an optional `Scan func(rel string, r io.Reader) error` seam; the site archiver calls it per file before writing (nil in tests today = skip). Implementation: stream the same bytes the archiver already reads through clamd, skip hit files from the archive, record them in `Manifest` (`scan_hits: [...]`) and quarantine-move after the walk. A scan that cannot run (socket unset) is absent from the manifest — backups keep working (scan never blocks backup).

## Docs to update (repo rule)

`docs/mcp.md` (tools), `llms.txt` (UI list + MCP lists + status line), README feature bullet, `docs/ROADMAP.md`, `skills/*` ("since next minor"), `internal/web/help.go` hints (`scan_off`, `scan_hits`, `scan_notify`… plain text, no `<>`).

## Build stages

1. **Migration + store**: `006_scan.sql`, store methods (runs/hits CRUD + retention + latest-per-site query), `user_version` bump. **Complete** (f57cf26).
2. **scan engine**: clamd client, walker, quarantine move/restore, fake clamd over a real unix socket in tests. **Complete** (01466ed). Note: no real clamd on this host — protocol verified against the documented behavior + fake only; live clamd verification pending on v1 (`apt install clamav-daemon` at deploy).
3. **Web**: settings section, `/scan` page, site badge + Scan now, notifications, `RunScans` wiring in `main`, help hints. **Complete** (9935a9e). Live-panel screenshot pass done (desktop + 390 px): mobile hides the Files/Skipped/Hits columns of the runs table (`.scanruns`); a sweep ran live on the panel start; the no-daemon states (flash after save, the /scan banner) verify the failure paths. Hit pages with real hits verified in HTML tests only until clamd exists on a host.
4. **MCP + backup + docs + gate**: five tools, regex, skills; backup `Env.Scan` seam + manifest; docs lines; `make check`; ff main. **Complete** (a7cab76, f324f67, 1ba4539; 6592b8e fixes the test callers). Gate: `exit=0`, 23 packages, e2e 40 passed; branch ff'd to local `main` (not pushed).

Each stage commits. Never scan while a backup of the same site archives (a quarantined move mid-archive is harmless to SQLite but confusing): trivial guard — sweeps skip the site the archiver currently holds if backup surfaces that state (ponytail: only when backup exposes it cheaply).