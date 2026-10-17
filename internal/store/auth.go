package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// TOTP is one user's authenticator. Secret is sealed (secretbox); Enabled=false means enrollment is unconfirmed.
type TOTP struct {
	Secret   []byte
	Enabled  bool
	LastStep int64
}

// GetTOTP reports ok=false when the user has nothing enrolled.
func (s *Store) GetTOTP(ctx context.Context, userID int64) (t TOTP, ok bool, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT secret, enabled, last_step FROM totp WHERE user_id=?`, userID).Scan(&t.Secret, &t.Enabled, &t.LastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return TOTP{}, false, nil
	}
	if err != nil {
		return TOTP{}, false, fmt.Errorf("get totp: %w", err)
	}
	return t, true, nil
}

// SaveTOTP stores a fresh unconfirmed seed for the user, replacing any earlier one. It refuses to overwrite an enabled seed.
func (s *Store) SaveTOTP(ctx context.Context, userID int64, sealed []byte) error {
	res, err := s.q.ExecContext(ctx, `INSERT INTO totp (user_id, secret) VALUES (?, ?)
		ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, last_step=0 WHERE enabled=0`, userID, sealed)
	if err != nil {
		return fmt.Errorf("save totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("totp is already enabled")
	}
	return nil
}

// EnableTOTP confirms the user's pending seed at step and installs the backup code hashes, atomically.
func (s *Store) EnableTOTP(ctx context.Context, userID, step int64, codeHashes []string) error {
	return s.Tx(ctx, func(tx *Store) error {
		res, err := tx.q.ExecContext(ctx, `UPDATE totp SET enabled=1, last_step=? WHERE user_id=?`, step, userID)
		if err != nil {
			return fmt.Errorf("enable totp: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errors.New("no totp enrollment in progress")
		}
		return tx.ReplaceBackupCodes(ctx, userID, codeHashes)
	})
}

// AdvanceTOTPStep records step as used by the user; false means that step (or a later one) was already accepted: a replay.
func (s *Store) AdvanceTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE totp SET last_step=? WHERE user_id=? AND enabled=1 AND last_step<?`, step, userID, step)
	if err != nil {
		return false, fmt.Errorf("advance totp step: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteTOTP removes the user's authenticator and backup codes.
func (s *Store) DeleteTOTP(ctx context.Context, userID int64) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id=?`, userID); err != nil {
			return fmt.Errorf("delete backup codes: %w", err)
		}
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM totp WHERE user_id=?`, userID); err != nil {
			return fmt.Errorf("delete totp: %w", err)
		}
		return nil
	})
}

func (s *Store) ReplaceBackupCodes(ctx context.Context, userID int64, hashes []string) error {
	return s.Tx(ctx, func(tx *Store) error {
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id=?`, userID); err != nil {
			return fmt.Errorf("clear backup codes: %w", err)
		}
		for _, h := range hashes {
			if _, err := tx.q.ExecContext(ctx, `INSERT INTO backup_codes (user_id, code_hash) VALUES (?,?)`, userID, h); err != nil {
				return fmt.Errorf("insert backup code: %w", err)
			}
		}
		return nil
	})
}

// UseBackupCode burns the user's code; false means unknown or already used.
func (s *Store) UseBackupCode(ctx context.Context, userID int64, hash string) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE backup_codes SET used_at=datetime('now') WHERE user_id=? AND code_hash=? AND used_at IS NULL`, userID, hash)
	if err != nil {
		return false, fmt.Errorf("use backup code: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// CountBackupCodes counts the user's unused codes.
func (s *Store) CountBackupCodes(ctx context.Context, userID int64) (n int, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_codes WHERE user_id=? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// TOTPUsers lists the users with an enrolled authenticator (for the startup check that the secret key still opens them).
func (s *Store) TOTPUsers(ctx context.Context) ([]int64, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT user_id FROM totp ORDER BY user_id`)
	if err != nil {
		return nil, fmt.Errorf("list totp users: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
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

func (s *Store) ListPasskeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, rp_id, credential_id, credential, name, created_at, COALESCE(last_used_at,'')
		FROM passkeys WHERE user_id=? ORDER BY created_at, id`, userID)
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

func (s *Store) AddPasskey(ctx context.Context, userID int64, p Passkey) error {
	if _, err := s.q.ExecContext(ctx, `INSERT INTO passkeys (id, user_id, rp_id, credential_id, credential, name) VALUES (?,?,?,?,?,?)`,
		p.ID, userID, p.RPID, p.CredentialID, p.Credential, p.Name); err != nil {
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

// HasPasskeyFor reports whether any user has a passkey registered for rpID (the login page offers the button only then).
func (s *Store) HasPasskeyFor(ctx context.Context, rpID string) (bool, error) {
	var n int
	if err := s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkeys WHERE rp_id=?`, rpID).Scan(&n); err != nil {
		return false, fmt.Errorf("count passkeys: %w", err)
	}
	return n > 0, nil
}

// PasskeyOwner is the user a credential belongs to; ok=false for an unknown credential.
func (s *Store) PasskeyOwner(ctx context.Context, credentialID []byte) (userID int64, ok bool, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT user_id FROM passkeys WHERE credential_id=?`, credentialID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("passkey owner: %w", err)
	}
	return userID, true, nil
}

// DeletePasskey removes one of the user's passkeys and reports whether a row was removed.
func (s *Store) DeletePasskey(ctx context.Context, userID int64, id string) (bool, error) {
	res, err := s.q.ExecContext(ctx, `DELETE FROM passkeys WHERE user_id=? AND id=?`, userID, id)
	if err != nil {
		return false, fmt.Errorf("delete passkey: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ResetAuth wipes one user's second factors (2fa-reset) and reports what was removed. Their password and other users are untouched.
func (s *Store) ResetAuth(ctx context.Context, userID int64) (totp bool, codes, passkeys int, err error) {
	err = s.Tx(ctx, func(tx *Store) error {
		for _, q := range []struct {
			sql string
			n   *int
		}{{`DELETE FROM backup_codes WHERE user_id=?`, &codes}, {`DELETE FROM passkeys WHERE user_id=?`, &passkeys}} {
			res, err := tx.q.ExecContext(ctx, q.sql, userID)
			if err != nil {
				return fmt.Errorf("reset auth: %w", err)
			}
			n, _ := res.RowsAffected()
			*q.n = int(n)
		}
		res, err := tx.q.ExecContext(ctx, `DELETE FROM totp WHERE user_id=?`, userID)
		if err != nil {
			return fmt.Errorf("reset auth: %w", err)
		}
		n, _ := res.RowsAffected()
		totp = n > 0
		return nil
	})
	return
}
