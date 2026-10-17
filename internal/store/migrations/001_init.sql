-- Initial schema. The app has no deployed data yet, so this is one clean migration rather than a history.
-- Later changes go in 002_*.sql and up, each applied once (PRAGMA user_version).

CREATE TABLE domains (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  zone_id     TEXT NOT NULL,                  -- Cloudflare zone; '' without Cloudflare
  default_ip  TEXT NOT NULL,                  -- IPv4 target of the domain's A records; '' without Cloudflare
  default_ip6 TEXT NOT NULL DEFAULT '',       -- optional IPv6 target of its AAAA records
  cert_mode   TEXT NOT NULL DEFAULT 'wildcard' CHECK (cert_mode IN ('wildcard','per_host')),
  created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sites (
  id              INTEGER PRIMARY KEY,
  domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE RESTRICT,
  subdomain       TEXT NOT NULL,
  scheme          TEXT NOT NULL DEFAULT 'http' CHECK (scheme IN ('http','https')),
  upstream_host   TEXT NOT NULL,
  upstream_port   INTEGER NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
  tls_skip_verify INTEGER NOT NULL DEFAULT 0,
  enabled         INTEGER NOT NULL DEFAULT 1,
  record_ip       TEXT,                       -- IPv4 override for this site's A record; NULL = domain default
  record_ip6      TEXT,                       -- IPv6 override for its AAAA record; NULL = domain default
  allowlist       TEXT NOT NULL DEFAULT '',
  basic_user      TEXT,
  basic_hash      TEXT,
  stream          INTEGER NOT NULL DEFAULT 0, -- flush_interval -1
  max_body        INTEGER NOT NULL DEFAULT 0 CHECK (max_body >= 0), -- request_body max_size in bytes; 0 = Caddy default
  gate_mode       TEXT NOT NULL DEFAULT '',   -- magic-link gate (DESIGN.md §18): '' = ungated, 'acl' = email allowlist, 'open' = any email
  UNIQUE (domain_id, subdomain)
);

-- One Cloudflare record per site and family (A or AAAA).
CREATE TABLE dns_records (
  site_id     INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  family       TEXT NOT NULL DEFAULT 'A' CHECK (family IN ('A','AAAA')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT,
  PRIMARY KEY (site_id, family)
);

-- The records for SERVANAGO_HOST itself; not tied to a site, so a twin of dns_records keyed by family only.
CREATE TABLE ui_dns_record (
  family       TEXT PRIMARY KEY CHECK (family IN ('A','AAAA')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT
);

-- Admin 2FA. totp has one row (single admin); the seed is secretbox-sealed, never plaintext.
CREATE TABLE totp (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  secret     BLOB NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  last_step  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE backup_codes (
  code_hash TEXT PRIMARY KEY,
  used_at   TEXT
);
CREATE TABLE passkeys (
  id            TEXT PRIMARY KEY,
  rp_id         TEXT NOT NULL,
  credential_id BLOB NOT NULL UNIQUE,
  credential    TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at  TEXT
);

-- Magic-link site gate (DESIGN.md §18).
CREATE TABLE gate_grants (
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  mode     TEXT NOT NULL CHECK (mode IN ('email', 'domain')),
  value    TEXT NOT NULL,
  UNIQUE (site_id, mode, value)
);
CREATE TABLE gate_identities (
  email      TEXT PRIMARY KEY,
  nonce      TEXT NOT NULL UNIQUE,     -- random; the session secret is HKDF(SecretKey, 'gate|'+email+'|'+nonce)
  token_hash TEXT NOT NULL UNIQUE,     -- SHA-256 of the session secret at last issuance
  created_at TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  expire     TEXT NOT NULL             -- sliding window per mode, recomputed on each passing check
);
CREATE TABLE gate_tokens (
  token_hash  TEXT PRIMARY KEY,        -- SHA-256 of the magic-link token
  host        TEXT NOT NULL,           -- verify is host-pinned
  email       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT
);

-- App-level settings: email delivery for the magic-link gate. One row, same pattern as the single-row totp.
-- smtp_pass is secretbox-sealed with SERVANAGO_SECRET_KEY; NULL = no password.
CREATE TABLE settings (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  smtp_host  TEXT NOT NULL DEFAULT '',
  smtp_port  INTEGER NOT NULL DEFAULT 587,
  smtp_user  TEXT NOT NULL DEFAULT '',
  smtp_pass  BLOB,
  mail_from  TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT ''
);
INSERT INTO settings (id) VALUES (1);
