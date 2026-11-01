-- Update check: the last signed release manifest this install saw (JSON) and when. Nothing is installed from it here.
ALTER TABLE settings ADD COLUMN update_check_json TEXT NOT NULL DEFAULT '';
ALTER TABLE settings ADD COLUMN update_checked_at INTEGER NOT NULL DEFAULT 0;
