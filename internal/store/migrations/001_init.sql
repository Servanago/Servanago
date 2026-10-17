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
  slug            TEXT NOT NULL UNIQUE,       -- immutable, derived once from the first hostname: ^[a-z][a-z0-9-]{1,31}$
  kind            TEXT NOT NULL DEFAULT 'proxy' CHECK (kind IN ('proxy','static','node','php','frankenphp','fastcgi','cgi')),
  scheme          TEXT NOT NULL DEFAULT 'http' CHECK (scheme IN ('http','https')),
  upstream_host   TEXT,                       -- proxy, node, frankenphp and fastcgi; node/frankenphp store 127.0.0.1, fastcgi a host or an absolute socket path
  upstream_port   INTEGER CHECK (upstream_port BETWEEN 1 AND 65535), -- proxy only; node and frankenphp: the app's port; fastcgi: NULL when the upstream is a socket path
  static_root     TEXT,                       -- static, node and php: absolute directory
  start_command   TEXT NOT NULL DEFAULT '',   -- node: the long-running start command (systemd ExecStart)
  install_command TEXT NOT NULL DEFAULT '',   -- node: shown to the admin, who runs it by hand on the server
  build_command   TEXT NOT NULL DEFAULT '',   -- node: same
  fpm_version     TEXT NOT NULL DEFAULT '',   -- php: version of the detected php-fpm binary, e.g. 8.2
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
  CHECK (
       (kind = 'proxy'  AND upstream_host IS NOT NULL AND upstream_port IS NOT NULL AND static_root IS NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
   OR (kind = 'static' AND static_root IS NOT NULL AND upstream_host IS NULL AND upstream_port IS NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
   OR (kind = 'node'   AND static_root IS NOT NULL AND upstream_host = '127.0.0.1' AND upstream_port IS NOT NULL
                      AND start_command != '' AND fpm_version = '')
   OR (kind = 'php'    AND static_root IS NOT NULL AND upstream_host IS NULL AND upstream_port IS NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version != '')
   OR (kind = 'frankenphp' AND static_root IS NOT NULL AND upstream_host = '127.0.0.1' AND upstream_port IS NOT NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
   OR (kind = 'fastcgi' AND static_root IS NOT NULL AND upstream_host IS NOT NULL
                      AND (upstream_port IS NULL) = (substr(upstream_host, 1, 1) = '/')
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
   OR (kind = 'cgi'    AND static_root IS NOT NULL AND upstream_host IS NULL AND upstream_port IS NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
  )
);

-- A site answers on one or more free FQDNs. Its domain (Cloudflare zone, default IPs, cert mode) is the
-- longest-suffix match in domains and may not exist. Exactly one hostname per site is primary.
CREATE TABLE site_hostnames (
  site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  hostname   TEXT NOT NULL UNIQUE,
  is_primary INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX site_hostnames_one_primary ON site_hostnames (site_id) WHERE is_primary = 1;

-- One Cloudflare record per hostname and family (A or AAAA); site_id groups them and cascades on delete.
CREATE TABLE dns_records (
  hostname     TEXT NOT NULL,                 -- one record pair per hostname that resolves to a domain
  site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  family       TEXT NOT NULL DEFAULT 'A' CHECK (family IN ('A','AAAA')),
  cf_record_id TEXT,
  content      TEXT,
  owned        INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','synced','error','conflict')),
  error        TEXT,
  synced_at    TEXT,
  PRIMARY KEY (hostname, family)
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

-- Admins: equal, no roles. username is stored lower-case. session_epoch is part of every session cookie and is bumped
-- whenever the user's sessions must end (password change, 2FA reset, removal). webauthn_id is the random,
-- stable WebAuthn user handle.
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,                -- bcrypt
  webauthn_id   BLOB NOT NULL UNIQUE,
  session_epoch INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_login_at TEXT
);

-- Admin 2FA, per user. The seed is secretbox-sealed, never plaintext.
CREATE TABLE totp (
  user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret     BLOB NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  last_step  INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE backup_codes (
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at   TEXT,
  PRIMARY KEY (user_id, code_hash)
);
CREATE TABLE passkeys (
  id            TEXT PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rp_id         TEXT NOT NULL,
  credential_id BLOB NOT NULL UNIQUE,
  credential    TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at  TEXT
);

-- Who did what. actor is the username at the time (kept after the user is removed); never holds secrets.
CREATE TABLE audit_log (
  id     INTEGER PRIMARY KEY,
  at     TEXT NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log (id DESC);

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
