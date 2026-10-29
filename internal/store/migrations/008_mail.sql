-- Postmark mail bridge: inbound webhook → LMTP per domain. The account token and the LMTP
-- credential are secretbox-sealed; webhook passwords live only as bcrypt hashes. Nothing is
-- deleted on Postmark or in DNS when a mail domain goes away (the row does).
ALTER TABLE settings ADD COLUMN mail_pm_token  BLOB;                      -- sealed account token; NULL = bridge off
ALTER TABLE settings ADD COLUMN mail_lmtp      TEXT NOT NULL DEFAULT '';  -- global LMTP target host:port
ALTER TABLE settings ADD COLUMN mail_lmtp_tls  TEXT NOT NULL DEFAULT '' CHECK (mail_lmtp_tls IN ('', 'starttls'));
ALTER TABLE settings ADD COLUMN mail_lmtp_user TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN mail_lmtp_pass BLOB;                      -- sealed; NULL = none

CREATE TABLE mail_domains (
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,       -- lowercase FQDN
  pm_server_id   INTEGER NOT NULL DEFAULT 0, -- Postmark server; 0 = none yet
  pm_domain_id   INTEGER NOT NULL DEFAULT 0, -- Postmark domain; 0 = none yet
  dkim_host      TEXT NOT NULL DEFAULT '',   -- the DKIM TXT record name we published
  dkim_text      TEXT NOT NULL DEFAULT '',
  return_path    TEXT NOT NULL DEFAULT '',   -- pm-bounces.<domain> CNAME name we published
  hook_user      TEXT NOT NULL DEFAULT '',
  hook_pass_hash TEXT NOT NULL DEFAULT '',
  dns_notes      TEXT NOT NULL DEFAULT '',   -- one note per line: written rows, hand-publish hints
  dkim_state     TEXT NOT NULL DEFAULT '' CHECK (dkim_state IN ('', 'pending', 'verified', 'failed')),
  rp_state       TEXT NOT NULL DEFAULT '' CHECK (rp_state IN ('', 'pending', 'verified', 'failed')),
  last_verify    INTEGER NOT NULL DEFAULT 0,
  lmtp_addr      TEXT NOT NULL DEFAULT '',   -- per-domain override of the global endpoint
  recv           INTEGER NOT NULL DEFAULT 0,
  delivered      INTEGER NOT NULL DEFAULT 0,
  deduped        INTEGER NOT NULL DEFAULT 0,
  rejected       INTEGER NOT NULL DEFAULT 0,
  fallbacks      INTEGER NOT NULL DEFAULT 0,
  last_inbound   INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);

-- One row per Postmark event notification (delivery, bounce, spam complaint, SMTP API error, ...).
CREATE TABLE mail_events (
  id          INTEGER PRIMARY KEY,
  domain_id   INTEGER NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
  record_type TEXT NOT NULL,
  record_id   TEXT NOT NULL DEFAULT '',   -- the bounce's own ID
  message_id  TEXT NOT NULL DEFAULT '',
  address     TEXT NOT NULL DEFAULT '',   -- From / Email, whatever the event carried
  summary     TEXT NOT NULL DEFAULT '',   -- one line, safe to render
  payload     TEXT NOT NULL,              -- the JSON we received, bounded
  dsn_sent    INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL
);
CREATE INDEX idx_mail_events_domain ON mail_events (domain_id, created_at);

-- Dedupe: sha256(MessageID|recipient) for inbound, bounce:<id> for DSNs.
CREATE TABLE mail_delivered (
  key        TEXT PRIMARY KEY,
  domain_id  INTEGER NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);