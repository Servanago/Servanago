package store

import (
	"context"
	"fmt"
)

// UpdateCheck returns the last update check result (JSON) and when it ran (unix seconds, 0 = never).
func (s *Store) UpdateCheck(ctx context.Context) (js string, at int64, err error) {
	if err = s.q.QueryRowContext(ctx, `SELECT update_check_json, update_checked_at FROM settings WHERE id=1`).Scan(&js, &at); err != nil {
		return "", 0, fmt.Errorf("read update check: %w", err)
	}
	return js, at, nil
}

func (s *Store) SaveUpdateCheck(ctx context.Context, js string, at int64) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE settings SET update_check_json=?, update_checked_at=? WHERE id=1`, js, at); err != nil {
		return fmt.Errorf("save update check: %w", err)
	}
	return nil
}
