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
