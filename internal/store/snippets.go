package store

import (
	"context"
	"fmt"
)

// Snippet is a named block of Caddyfile directives (see caddycfg.AdaptSnippet) that sites attach by name.
type Snippet struct {
	ID   int64
	Name string
	Body string
}

func (s *Store) ListSnippets(ctx context.Context) ([]Snippet, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT id, name, body FROM snippets ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list snippets: %w", err)
	}
	defer rows.Close()
	var out []Snippet
	for rows.Next() {
		var x Snippet
		if err := rows.Scan(&x.ID, &x.Name, &x.Body); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) CreateSnippet(ctx context.Context, name, body string) (Snippet, error) {
	res, err := s.q.ExecContext(ctx, "INSERT INTO snippets (name, body) VALUES (?,?)", name, body)
	if err != nil {
		return Snippet{}, fmt.Errorf("create snippet %s: %w", name, err)
	}
	id, _ := res.LastInsertId()
	return Snippet{ID: id, Name: name, Body: body}, nil
}

func (s *Store) UpdateSnippet(ctx context.Context, id int64, body string) error {
	if _, err := s.q.ExecContext(ctx, "UPDATE snippets SET body=? WHERE id=?", body, id); err != nil {
		return fmt.Errorf("update snippet %d: %w", id, err)
	}
	return nil
}

func (s *Store) DeleteSnippet(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM snippets WHERE id=?", id); err != nil {
		return fmt.Errorf("delete snippet %d: %w", id, err)
	}
	return nil
}

// SnippetUsers returns the primary hostname of every site that has the snippet attached.
func (s *Store) SnippetUsers(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT h.hostname FROM site_snippets x
		JOIN site_hostnames h ON h.site_id = x.site_id AND h.is_primary = 1 WHERE x.snippet_id=? ORDER BY h.hostname`, id)
	if err != nil {
		return nil, fmt.Errorf("snippet %d users: %w", id, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// siteSnippets returns every site's snippet names keyed by site id, in attach order (by name).
func (s *Store) siteSnippets(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT x.site_id, n.name FROM site_snippets x JOIN snippets n ON n.id = x.snippet_id ORDER BY x.site_id, n.name`)
	if err != nil {
		return nil, fmt.Errorf("list site snippets: %w", err)
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = append(out[id], n)
	}
	return out, rows.Err()
}

// setSnippets replaces a site's attached snippets. An unknown name fails.
func (s *Store) setSnippets(ctx context.Context, siteID int64, names []string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM site_snippets WHERE site_id=?`, siteID); err != nil {
		return fmt.Errorf("clear snippets of site %d: %w", siteID, err)
	}
	for _, n := range names {
		var id int64
		if err := s.q.QueryRowContext(ctx, `SELECT id FROM snippets WHERE name=?`, n).Scan(&id); err != nil {
			return fmt.Errorf("unknown snippet %q", n)
		}
		if _, err := s.q.ExecContext(ctx, `INSERT OR IGNORE INTO site_snippets (site_id, snippet_id) VALUES (?,?)`, siteID, id); err != nil {
			return fmt.Errorf("attach snippet %s: %w", n, err)
		}
	}
	return nil
}
