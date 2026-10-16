-- DNS record for SERVANAGO_HOST itself; not tied to a route, so a one-row twin of dns_records.
CREATE TABLE ui_dns_record (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT
);
