-- Dual-stack records: an optional IPv6 target beside the IPv4 one, and one DNS row per record family.
ALTER TABLE domains ADD COLUMN default_ip6 TEXT NOT NULL DEFAULT '';
ALTER TABLE routes ADD COLUMN record_ip6 TEXT;

-- dns_records was keyed by route_id alone; rebuild it keyed by (route_id, family). Existing rows are A records.
CREATE TABLE dns_records_new (
  route_id     INTEGER NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
  family       TEXT NOT NULL DEFAULT 'A' CHECK (family IN ('A','AAAA')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT,
  PRIMARY KEY (route_id, family)
);
INSERT INTO dns_records_new (route_id, family, cf_record_id, content, owned, state, error, synced_at)
  SELECT route_id, 'A', cf_record_id, content, owned, state, error, synced_at FROM dns_records;
DROP TABLE dns_records;
ALTER TABLE dns_records_new RENAME TO dns_records;

-- The UI host's record: one row per family instead of the single id = 1 row.
CREATE TABLE ui_dns_record_new (
  family       TEXT PRIMARY KEY CHECK (family IN ('A','AAAA')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT
);
INSERT INTO ui_dns_record_new (family, cf_record_id, content, owned, state, error, synced_at)
  SELECT 'A', cf_record_id, content, owned, state, error, synced_at FROM ui_dns_record;
DROP TABLE ui_dns_record;
ALTER TABLE ui_dns_record_new RENAME TO ui_dns_record;
