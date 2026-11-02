-- WAF M12 (design claudedocs/design_waf_m12.md): the engine mode and the site rate limit join
-- waf on the site row; exclusions and events become rows of their own. SQLite cannot alter a
-- CHECK, so the sites table rebuilds once without migration 010's waf value CHECK (the app
-- layer validates presets now) and gains the new columns.

PRAGMA defer_foreign_keys=ON;

CREATE TABLE sites_new (
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
  extra_routes    TEXT NOT NULL DEFAULT '',   -- path prefixes Caddy proxies to their own upstream before the site's handler: one per line, path=dial
  php_extensions  TEXT NOT NULL DEFAULT '',   -- php: space-separated shared extensions loaded by the site's own php.ini; '' = the core set
  php_health_path TEXT NOT NULL DEFAULT '',   -- php: path requested after a PHP switch; '' = only check that the unit stays up
  site_user       TEXT NOT NULL DEFAULT '',   -- node, php, frankenphp, cgi, static: the Unix user the site runs as, one site per user; '' = the generated sg-<slug> (a static site is then served by Caddy)
  public_dir      TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 10000), updated_at TEXT NOT NULL DEFAULT '', gate_provider  TEXT NOT NULL DEFAULT '' CHECK (gate_provider IN ('', 'smtp', 'postmark')), gate_from      TEXT NOT NULL DEFAULT '', gate_smtp_host TEXT NOT NULL DEFAULT '', gate_smtp_port INTEGER NOT NULL DEFAULT 587, gate_smtp_user TEXT NOT NULL DEFAULT '', gate_secret    BLOB, backup_on          INTEGER NOT NULL DEFAULT 0 CHECK (backup_on IN (0, 1)), backup_sched       TEXT    NOT NULL DEFAULT '', backup_keep        INTEGER NOT NULL DEFAULT 0, backup_keep_weekly INTEGER NOT NULL DEFAULT 0, country_mode TEXT NOT NULL DEFAULT '' CHECK (country_mode IN ('', 'deny', 'allow')), countries   TEXT NOT NULL DEFAULT '',
  waf             TEXT NOT NULL DEFAULT '',   -- '' = off; a preset name (crs, php, wordpress, shop, goapi, node) or custom; validated by the apply path
  waf_mode        TEXT NOT NULL DEFAULT '' CHECK (waf_mode IN ('', 'detect', 'block')), -- '' = detect: who emits the SecRuleEngine line
  waf_directives  TEXT NOT NULL DEFAULT '',   -- custom: extra SecLang directives; validated at save
  rl_requests     INTEGER NOT NULL DEFAULT 0, -- rate limit: requests per client IP per window; 0 = off
  rl_window       TEXT NOT NULL DEFAULT '',   -- rate limit window: '' | 1m | 5m | 1h
  rl_paths        TEXT NOT NULL DEFAULT '',   -- rate limit scope: one path prefix per line; '' = the whole site
  -- php, frankenphp, fastcgi, static: the served folder inside static_root; '' = static_root itself  (public_dir comment above is where it ended up in 008)
  CHECK (kind = 'php' OR (php_extensions = '' AND php_health_path = '')),
  CHECK (site_user = '' OR kind IN ('node','php','frankenphp','cgi','static')),
  CHECK (public_dir = '' OR kind IN ('php','frankenphp','fastcgi','static')),
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
INSERT INTO sites_new (id, slug, kind, scheme, upstream_host, upstream_port, static_root, start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at, gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, backup_on, backup_sched, backup_keep, backup_keep_weekly, country_mode, countries, waf, waf_directives)
SELECT   id, slug, kind, scheme, upstream_host, upstream_port, static_root, start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at, gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, backup_on, backup_sched, backup_keep, backup_keep_weekly, country_mode, countries, waf, waf_directives
FROM sites;
DROP TABLE sites;
ALTER TABLE sites_new RENAME TO sites;
CREATE UNIQUE INDEX sites_site_user ON sites (site_user) WHERE site_user != '';

-- Exclusions the admin chose on a site (from an event's click or the form): the renderer
-- appends them to the tail as SecRuleRemoveById / SecRuleUpdateTargetById. narrow rows must
-- name a rule the current CRS still ships (the engine rejects those at compile); remove rows
-- of a retired id are silent no-ops and the rules browser greys them out.
CREATE TABLE waf_exclusions (
  site_id  INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  kind     TEXT NOT NULL CHECK (kind IN ('remove', 'narrow')),
  rule_id  TEXT NOT NULL,
  target   TEXT NOT NULL DEFAULT '',  -- narrow only: the target to drop, "!ARGS:checkout"
  note     TEXT NOT NULL DEFAULT '',  -- the one-line reason, carried over from the event
  added_by TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  PRIMARY KEY (site_id, kind, rule_id, target)
);

-- One row per matched rule (events capped and trimmed by the writer, like the audit log);
-- a log, not desired state: nothing reads it back into the config.
CREATE TABLE waf_events (
  id      INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  ts      INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  message TEXT NOT NULL,
  phase   INTEGER NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('deny', 'detect')),
  host    TEXT NOT NULL,
  path    TEXT NOT NULL,
  client  TEXT NOT NULL DEFAULT '',
  method  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX waf_events_site ON waf_events (site_id, ts DESC);
CREATE INDEX waf_events_rule ON waf_events (site_id, rule_id);