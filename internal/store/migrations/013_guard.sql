-- M13 (design claudedocs/design_corvus_features.md §4): site kind 'page' (maintenance, parked or
-- redirect), per-site guard settings, bans, x402 routes, alert destinations. SQLite cannot alter a
-- CHECK, so sites rebuilds once with 'page' allowed (migrate() runs this with foreign keys off, as for
-- 011). The request log and traffic rollups are NOT here: they live in traffic.db.

PRAGMA defer_foreign_keys=ON;

CREATE TABLE sites_new (
  id              INTEGER PRIMARY KEY,
  slug            TEXT NOT NULL UNIQUE,       -- immutable, derived once from the first hostname: ^[a-z][a-z0-9-]{1,31}$
  kind            TEXT NOT NULL DEFAULT 'proxy' CHECK (kind IN ('proxy','static','node','php','frankenphp','fastcgi','cgi','page')),
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
   OR (kind = 'page'   AND static_root IS NULL AND upstream_host IS NULL AND upstream_port IS NULL
                      AND start_command = '' AND install_command = '' AND build_command = '' AND fpm_version = '')
  )
);
INSERT INTO sites_new (id, slug, kind, scheme, upstream_host, upstream_port, static_root, start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at, gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, backup_on, backup_sched, backup_keep, backup_keep_weekly, country_mode, countries, waf, waf_mode, waf_directives, rl_requests, rl_window, rl_paths)
SELECT   id, slug, kind, scheme, upstream_host, upstream_port, static_root, start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at, gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, backup_on, backup_sched, backup_keep, backup_keep_weekly, country_mode, countries, waf, waf_mode, waf_directives, rl_requests, rl_window, rl_paths
FROM sites;
DROP TABLE sites;
ALTER TABLE sites_new RENAME TO sites;
CREATE UNIQUE INDEX sites_site_user ON sites (site_user) WHERE site_user != '';

-- Per-site protection settings (one row per site that sets any; absent = all off).
CREATE TABLE site_guard (
  site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  ban_on          INTEGER NOT NULL DEFAULT 0,
  ua_mode         TEXT NOT NULL DEFAULT '' CHECK (ua_mode IN ('', 'on', 'auto')),
  ch_kind         TEXT NOT NULL DEFAULT 'pow' CHECK (ch_kind IN ('pow', 'turnstile')),
  ch_difficulty   TEXT NOT NULL DEFAULT 'medium' CHECK (ch_difficulty IN ('low', 'medium', 'high')),
  ch_ttl_min      INTEGER NOT NULL DEFAULT 60,
  ua_auto_rps     INTEGER NOT NULL DEFAULT 0,
  ua_cooldown_min INTEGER NOT NULL DEFAULT 10,
  q_on            INTEGER NOT NULL DEFAULT 0,
  q_capacity      INTEGER NOT NULL DEFAULT 100,
  q_active_ttl_s  INTEGER NOT NULL DEFAULT 300,
  q_max_queue     INTEGER NOT NULL DEFAULT 5000,
  backends        TEXT NOT NULL DEFAULT ''    -- proxy sites: extra "host:port" backends, one per line
);

CREATE TABLE site_x402 (
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  price TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('all', 'bots')),
  grant_kind TEXT NOT NULL CHECK (grant_kind IN ('request', 'token')),
  token_ttl_s INTEGER NOT NULL DEFAULT 600,
  UNIQUE (site_id, path)
);

CREATE TABLE site_page (            -- kind 'page': a built-in or custom page, or a redirect (3xx status + target)
  site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  status INTEGER NOT NULL DEFAULT 503,
  title TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '',
  html TEXT NOT NULL DEFAULT '' CHECK (length(html) <= 65536),
  target TEXT NOT NULL DEFAULT '',
  keep_path INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE bans (                 -- active and recently expired (kept 7 days so the next ban escalates)
  client TEXT PRIMARY KEY,
  site_slug TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL CHECK (source IN ('auto', 'manual')),
  level INTEGER NOT NULL DEFAULT 1,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, until INTEGER NOT NULL, created_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE guard_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  ban_codes TEXT NOT NULL DEFAULT '401 403 429',
  ban_unknown_host INTEGER NOT NULL DEFAULT 0,
  ban_threshold INTEGER NOT NULL DEFAULT 20, ban_window_s INTEGER NOT NULL DEFAULT 60,
  ban_steps_min TEXT NOT NULL DEFAULT '15 60 1440',
  ban_exempt TEXT NOT NULL DEFAULT '',
  log_days INTEGER NOT NULL DEFAULT 7, rollup_days INTEGER NOT NULL DEFAULT 90,
  ua_list TEXT NOT NULL DEFAULT 'GPTBot ClaudeBot CCBot PerplexityBot Bytespider Amazonbot Google-Extended',
  x402_facilitator TEXT NOT NULL DEFAULT '', x402_network TEXT NOT NULL DEFAULT 'eip155:8453',
  x402_pay_to TEXT NOT NULL DEFAULT '',
  x402_api_key_sealed BLOB
);
INSERT INTO guard_settings (id) VALUES (1);

CREATE TABLE alert_dests (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('ntfy', 'webhook', 'email', 'pushover', 'twilio')),
  target_sealed BLOB NOT NULL,
  secret_sealed BLOB,
  events TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '', last_error_at INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE site_alert_dests (
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  dest_id INTEGER NOT NULL REFERENCES alert_dests(id) ON DELETE CASCADE,
  PRIMARY KEY (site_id, dest_id)
);

-- The ntfy topics the scan and backup jobs used to read from settings become destinations; the
-- sealed bytes are copied untouched and the old columns stay, unused (never dropped).
INSERT INTO alert_dests (name, kind, target_sealed, secret_sealed, events)
  SELECT 'ntfy: scan', 'ntfy', scan_ntfy, scan_ntfy_token, 'scan' FROM settings WHERE id = 1 AND scan_ntfy IS NOT NULL;
INSERT INTO alert_dests (name, kind, target_sealed, secret_sealed, events)
  SELECT 'ntfy: backup', 'ntfy', backup_ntfy, NULL, 'backup' FROM settings WHERE id = 1 AND backup_ntfy IS NOT NULL;
