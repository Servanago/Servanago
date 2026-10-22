-- Admin notes per site (shown on the Reference page) and the time of the last save (its "recently changed" sort).
ALTER TABLE sites ADD COLUMN notes TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= 10000);
ALTER TABLE sites ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';
UPDATE sites SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
