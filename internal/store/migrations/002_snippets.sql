-- Named Caddyfile snippets an admin attaches to sites. Attach order is by snippet name.
CREATE TABLE snippets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  body       TEXT NOT NULL,                   -- Caddyfile directives, validated and adapted by caddycfg.AdaptSnippet
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE site_snippets (
  site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  snippet_id INTEGER NOT NULL REFERENCES snippets(id) ON DELETE RESTRICT,
  PRIMARY KEY (site_id, snippet_id)
);
