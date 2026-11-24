-- Aliases and the magic-link host get a CNAME to the primary hostname (claudedocs/design_cname_aliases.md).
-- SQLite cannot alter a CHECK, so dns_records rebuilds once with CNAME as a third family.

CREATE TABLE dns_records_new (
  hostname     TEXT NOT NULL,
  site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  family       TEXT NOT NULL DEFAULT 'A' CHECK (family IN ('A','AAAA','CNAME')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT,
  PRIMARY KEY (hostname, family)
);
INSERT INTO dns_records_new (hostname, site_id, family, cf_record_id, content, owned, state, error, synced_at)
  SELECT hostname, site_id, family, cf_record_id, content, owned, state, error, synced_at FROM dns_records;
DROP TABLE dns_records;
ALTER TABLE dns_records_new RENAME TO dns_records;
