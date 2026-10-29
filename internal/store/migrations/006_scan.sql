-- Site virus scanning: ClamAV clamd socket settings, one run row per scanned site, and the
-- hits it found with their quarantine state. Nothing else changes.
ALTER TABLE settings ADD COLUMN scan_socket     TEXT    NOT NULL DEFAULT ''; -- clamd socket path; empty = scanning off
ALTER TABLE settings ADD COLUMN scan_hour       INTEGER NOT NULL DEFAULT 3;  -- daily sweep hour 0-23
ALTER TABLE settings ADD COLUMN scan_ntfy       BLOB;                        -- sealed https:// topic URL; NULL = none
ALTER TABLE settings ADD COLUMN scan_ntfy_token BLOB;                        -- sealed ntfy access token; NULL = none

-- trigger: manual | sweep | backup. state: running | ok | error.
CREATE TABLE scan_runs (
  id          INTEGER PRIMARY KEY,
  site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  trigger     TEXT NOT NULL CHECK (trigger IN ('manual', 'sweep', 'backup')),
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'ok', 'error')),
  files       INTEGER NOT NULL DEFAULT 0,
  skipped     INTEGER NOT NULL DEFAULT 0, -- symlinks and files over the stream size limit
  error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_scan_runs_site ON scan_runs (site_id, started_at);

-- action: live | quarantined | restored | ignored | error. path is the absolute original
-- path; quarantined_to is where the file was moved (empty while live).
CREATE TABLE scan_hits (
  id             INTEGER PRIMARY KEY,
  run_id         INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  site_id        INTEGER NOT NULL,
  path           TEXT NOT NULL,
  virus          TEXT NOT NULL,
  action         TEXT NOT NULL CHECK (action IN ('live', 'quarantined', 'restored', 'ignored', 'error')),
  quarantined_to TEXT NOT NULL DEFAULT '',
  updated_at     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_scan_hits_run ON scan_hits (run_id);
CREATE INDEX idx_scan_hits_path ON scan_hits (site_id, path, virus);