-- Country (GeoIP) blocking: per-site rule (the site form's access area) and the panel's own
-- rule; the MaxMind database file is read from the filesystem, never stored here.
ALTER TABLE sites ADD COLUMN country_mode TEXT NOT NULL DEFAULT '' CHECK (country_mode IN ('', 'deny', 'allow'));
ALTER TABLE sites ADD COLUMN countries   TEXT NOT NULL DEFAULT ''; -- space-separated ISO 3166-1 alpha-2 codes

ALTER TABLE settings ADD COLUMN geo_db         TEXT NOT NULL DEFAULT ''; -- GeoLite2-Country.mmdb path; empty = geo off
ALTER TABLE settings ADD COLUMN webui_mode     TEXT NOT NULL DEFAULT '' CHECK (webui_mode IN ('', 'deny', 'allow'));
ALTER TABLE settings ADD COLUMN webui_countries TEXT NOT NULL DEFAULT '';