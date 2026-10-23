-- Per-site magic-link mail: provider, sender and sealed credential live on the site (the global settings row
-- stays for system mail). gate_secret is secretbox-sealed: the SMTP password or the Postmark server token.
ALTER TABLE sites ADD COLUMN gate_provider  TEXT NOT NULL DEFAULT '' CHECK (gate_provider IN ('', 'smtp', 'postmark'));
ALTER TABLE sites ADD COLUMN gate_from      TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN gate_smtp_host TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN gate_smtp_port INTEGER NOT NULL DEFAULT 587;
ALTER TABLE sites ADD COLUMN gate_smtp_user TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN gate_secret    BLOB;
-- Who added each access row and when (the structured list on the site page).
ALTER TABLE gate_grants ADD COLUMN added_by TEXT NOT NULL DEFAULT '';
ALTER TABLE gate_grants ADD COLUMN added_at TEXT NOT NULL DEFAULT '';
