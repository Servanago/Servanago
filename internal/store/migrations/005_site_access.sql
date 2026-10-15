-- Per-route magic-link gate (DESIGN.md §18). gate_mode: '' = ungated, 'acl' = email allowlist, 'open' = any email.
ALTER TABLE routes ADD COLUMN gate_mode TEXT NOT NULL DEFAULT '';
CREATE TABLE gate_grants (
  route_id INTEGER NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
  mode     TEXT NOT NULL CHECK (mode IN ('email', 'domain')),
  value    TEXT NOT NULL,
  UNIQUE (route_id, mode, value)
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