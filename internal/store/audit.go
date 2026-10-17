package store

import (
	"context"
	"fmt"
)

// AuditCap is how many audit rows are kept; older ones are dropped as new ones arrive.
const AuditCap = 10000

// AuditEntry is one admin action. Actor is the username at the time, so the row outlives the user.
// It never holds a secret, code or token.
type AuditEntry struct {
	ID     int64
	At     string // RFC3339, UTC
	Actor  string
	Action string
	Target string
	IP     string
}

// AddAudit appends a row and trims the table to the newest AuditCap rows.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, ip) VALUES (?,?,?,?,?)`,
			e.At, e.Actor, e.Action, e.Target, e.IP); err != nil {
			return fmt.Errorf("add audit row: %w", err)
		}
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM audit_log WHERE id <= (SELECT MAX(id) FROM audit_log) - ?`, AuditCap); err != nil {
			return fmt.Errorf("trim audit log: %w", err)
		}
		return nil
	})
}

// ListAudit returns up to limit rows, newest first.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, at, actor, action, target, ip FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
