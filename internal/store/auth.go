package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// TOTP is the single admin's authenticator. Secret is sealed (secretbox); Enabled=false means enrollment is unconfirmed.
type TOTP struct {
	Secret   []byte
	Enabled  bool
	LastStep int64
}

// GetTOTP reports ok=false when nothing is enrolled.
func (s *Store) GetTOTP(ctx context.Context) (t TOTP, ok bool, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT secret, enabled, last_step FROM totp WHERE id=1`).Scan(&t.Secret, &t.Enabled, &t.LastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return TOTP{}, false, nil
	}
	if err != nil {
		return TOTP{}, false, fmt.Errorf("get totp: %w", err)
	}
	return t, true, nil
}

// SaveTOTP stores a fresh unconfirmed seed, replacing any earlier one. It refuses to overwrite an enabled seed.
func (s *Store) SaveTOTP(ctx context.Context, sealed []byte) error {
	res, err := s.q.ExecContext(ctx, `INSERT INTO totp (id, secret) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, last_step=0 WHERE enabled=0`, sealed)
	if err != nil {
		return fmt.Errorf("save totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("totp is already enabled")
	}
	return nil
}

// EnableTOTP confirms the pending seed at step and installs the backup code hashes, atomically.
func (s *Store) EnableTOTP(ctx context.Context, step int64, codeHashes []string) error {
	return s.Tx(ctx, func(tx *Store) error {
		res, err := tx.q.ExecContext(ctx, `UPDATE totp SET enabled=1, last_step=? WHERE id=1`, step)
		if err != nil {
			return fmt.Errorf("enable totp: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errors.New("no totp enrollment in progress")
		}
		return tx.ReplaceBackupCodes(ctx, codeHashes)
	})
}

// AdvanceTOTPStep records step as used; false means that step (or a later one) was already accepted: a replay.
func (s *Store) AdvanceTOTPStep(ctx context.Context, step int64) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE totp SET last_step=? WHERE id=1 AND enabled=1 AND last_step<?`, step, step)
	if err != nil {
		return false, fmt.Errorf("advance totp step: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteTOTP removes the authenticator and its backup codes.
func (s *Store) DeleteTOTP(ctx context.Context) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM backup_codes`); err != nil {
			return fmt.Errorf("delete backup codes: %w", err)
		}
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM totp`); err != nil {
			return fmt.Errorf("delete totp: %w", err)
		}
		return nil
	})
}

func (s *Store) ReplaceBackupCodes(ctx context.Context, hashes []string) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM backup_codes`); err != nil {
			return fmt.Errorf("clear backup codes: %w", err)
		}
		for _, h := range hashes {
			if _, err := tx.q.ExecContext(ctx, `INSERT INTO backup_codes (code_hash) VALUES (?)`, h); err != nil {
				return fmt.Errorf("insert backup code: %w", err)
			}
		}
		return nil
	})
}

// UseBackupCode burns the code; false means unknown or already used.
func (s *Store) UseBackupCode(ctx context.Context, hash string) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE backup_codes SET used_at=datetime('now') WHERE code_hash=? AND used_at IS NULL`, hash)
	if err != nil {
		return false, fmt.Errorf("use backup code: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountBackupCodes counts the unused codes.
func (s *Store) CountBackupCodes(ctx context.Context) (n int, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_codes WHERE used_at IS NULL`).Scan(&n)
	return n, err
}

type Passkey struct {
	ID           string
	RPID         string
	CredentialID []byte
	Credential   string // go-webauthn Credential as JSON
	Name         string
	CreatedAt    string
	LastUsedAt   string
}

func (s *Store) ListPasskeys(ctx context.Context) ([]Passkey, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, rp_id, credential_id, credential, name, created_at, COALESCE(last_used_at,'')
		FROM passkeys ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list passkeys: %w", err)
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.ID, &p.RPID, &p.CredentialID, &p.Credential, &p.Name, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) AddPasskey(ctx context.Context, p Passkey) error {
	if _, err := s.q.ExecContext(ctx, `INSERT INTO passkeys (id, rp_id, credential_id, credential, name) VALUES (?,?,?,?,?)`,
		p.ID, p.RPID, p.CredentialID, p.Credential, p.Name); err != nil {
		return fmt.Errorf("add passkey: %w", err)
	}
	return nil
}

// TouchPasskey saves the updated credential (sign count, backup state) after a login.
func (s *Store) TouchPasskey(ctx context.Context, credentialID []byte, credential string) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE passkeys SET credential=?, last_used_at=datetime('now') WHERE credential_id=?`, credential, credentialID); err != nil {
		return fmt.Errorf("touch passkey: %w", err)
	}
	return nil
}

// DeletePasskey reports whether a row was removed.
func (s *Store) DeletePasskey(ctx context.Context, id string) (bool, error) {
	res, err := s.q.ExecContext(ctx, `DELETE FROM passkeys WHERE id=?`, id)
	if err != nil {
		return false, fmt.Errorf("delete passkey: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ResetAuth wipes every second factor (the 2fa-reset command) and reports what was removed.
func (s *Store) ResetAuth(ctx context.Context) (totp bool, codes, passkeys int, err error) {
	err = s.Tx(ctx, func(tx *Store) error {
		for _, q := range []struct {
			sql string
			n   *int
		}{{`DELETE FROM backup_codes`, &codes}, {`DELETE FROM passkeys`, &passkeys}} {
			res, err := tx.q.ExecContext(ctx, q.sql)
			if err != nil {
				return fmt.Errorf("reset auth: %w", err)
			}
			n, _ := res.RowsAffected()
			*q.n = int(n)
		}
		res, err := tx.q.ExecContext(ctx, `DELETE FROM totp`)
		if err != nil {
			return fmt.Errorf("reset auth: %w", err)
		}
		n, _ := res.RowsAffected()
		totp = n > 0
		return nil
	})
	return
}
