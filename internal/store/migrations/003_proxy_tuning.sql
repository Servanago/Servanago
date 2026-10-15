-- Per-route proxy tuning: stream = flush_interval -1; max_body = request_body max_size in bytes (0 = Caddy default).
ALTER TABLE routes ADD COLUMN stream INTEGER NOT NULL DEFAULT 0;
ALTER TABLE routes ADD COLUMN max_body INTEGER NOT NULL DEFAULT 0 CHECK (max_body >= 0);
