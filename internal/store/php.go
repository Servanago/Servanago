package store

import (
	"context"
	"fmt"
)

// PHPUserDefault is a login user's default CLI PHP: a label, never a path.
type PHPUserDefault struct {
	Username string
	Version  string
}

// SetPHPUserDefault sets (or replaces) a user's default PHP label.
func (s *Store) SetPHPUserDefault(ctx context.Context, username, version string) error {
	if _, err := s.q.ExecContext(ctx, `INSERT INTO php_user_defaults (username, version) VALUES (?, ?)
		ON CONFLICT(username) DO UPDATE SET version=excluded.version`, username, version); err != nil {
		return fmt.Errorf("set php default for %s: %w", username, err)
	}
	return nil
}

func (s *Store) DeletePHPUserDefault(ctx context.Context, username string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM php_user_defaults WHERE username=?`, username); err != nil {
		return fmt.Errorf("delete php default for %s: %w", username, err)
	}
	return nil
}

// PHPUserDefaults lists every user default, ordered by username.
func (s *Store) PHPUserDefaults(ctx context.Context) ([]PHPUserDefault, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT username, version FROM php_user_defaults ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list php defaults: %w", err)
	}
	defer rows.Close()
	var out []PHPUserDefault
	for rows.Next() {
		var d PHPUserDefault
		if err := rows.Scan(&d.Username, &d.Version); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PHPCheck returns the last release check result (JSON) and when it ran (unix seconds, 0 = never).
func (s *Store) PHPCheck(ctx context.Context) (js string, at int64, err error) {
	if err = s.q.QueryRowContext(ctx, `SELECT php_check_json, php_checked_at FROM settings WHERE id=1`).Scan(&js, &at); err != nil {
		return "", 0, fmt.Errorf("read php check: %w", err)
	}
	return js, at, nil
}

func (s *Store) SavePHPCheck(ctx context.Context, js string, at int64) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE settings SET php_check_json=?, php_checked_at=? WHERE id=1`, js, at); err != nil {
		return fmt.Errorf("save php check: %w", err)
	}
	return nil
}
