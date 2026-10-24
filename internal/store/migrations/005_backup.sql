-- Site backup: global settings, per-site opt-in and overrides, typed dump profiles, docker volumes, run history.
-- backup_pass and backup_ntfy are secretbox-sealed; profile secrets too.
ALTER TABLE settings ADD COLUMN backup_enabled     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN backup_dir         TEXT    NOT NULL DEFAULT '/var/backups/servanago';
ALTER TABLE settings ADD COLUMN backup_pass        BLOB;
ALTER TABLE settings ADD COLUMN backup_sched       TEXT    NOT NULL DEFAULT 'daily@03:00';
ALTER TABLE settings ADD COLUMN backup_keep        INTEGER NOT NULL DEFAULT 7;
ALTER TABLE settings ADD COLUMN backup_keep_weekly INTEGER NOT NULL DEFAULT 4;
ALTER TABLE settings ADD COLUMN backup_panel       INTEGER NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN backup_ntfy        BLOB;

ALTER TABLE sites ADD COLUMN backup_on          INTEGER NOT NULL DEFAULT 0 CHECK (backup_on IN (0, 1));
ALTER TABLE sites ADD COLUMN backup_sched       TEXT    NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN backup_keep        INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN backup_keep_weekly INTEGER NOT NULL DEFAULT 0;

CREATE TABLE backup_profiles (
  id        INTEGER PRIMARY KEY,
  site_id   INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name      TEXT NOT NULL,
  engine    TEXT NOT NULL CHECK (engine IN ('mariadb', 'postgres', 'sqlite')),
  container TEXT NOT NULL DEFAULT '',
  db_name   TEXT NOT NULL DEFAULT '',
  db_user   TEXT NOT NULL DEFAULT '',
  secret    BLOB,
  path      TEXT NOT NULL DEFAULT '',
  UNIQUE (site_id, name)
);

CREATE TABLE backup_volumes (
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  volume  TEXT NOT NULL,
  PRIMARY KEY (site_id, volume)
);

-- Ingested from the job's result files; scope is 'panel' or a site slug (text: it outlives the site).
CREATE TABLE backup_runs (
  run_id      TEXT PRIMARY KEY,
  scope       TEXT NOT NULL,
  trigger     TEXT NOT NULL,
  actor       TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL CHECK (status IN ('ok', 'failed', 'skipped')),
  archive     TEXT NOT NULL DEFAULT '',
  bytes       INTEGER NOT NULL DEFAULT 0,
  error       TEXT NOT NULL DEFAULT '',
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL
);
CREATE INDEX backup_runs_scope ON backup_runs (scope, finished_at);
