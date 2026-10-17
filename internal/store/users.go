package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrLastAdmin is returned when removing a user would leave nobody able to sign in (and the UI open to all).
var ErrLastAdmin = errors.New("cannot remove the last administrator")

// User is one admin. All admins are equal.
type User struct {
	ID           int64
	Username     string // lower-case
	PasswordHash string // bcrypt
	WebAuthnID   []byte // random, stable per user: the WebAuthn user handle
	SessionEpoch int64  // part of every session cookie; bumped to end the user's sessions
	CreatedAt    string
	LastLoginAt  string
}

const userCols = "id, username, password_hash, webauthn_id, session_epoch, created_at, COALESCE(last_login_at,'')"

func scanUser(r interface{ Scan(...any) error }) (User, error) {
	var u User
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.WebAuthnID, &u.SessionEpoch, &u.CreatedAt, &u.LastLoginAt)
	return u, err
}

// CreateUser adds an admin. The username is lower-cased; a name already taken (in any case) fails.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (User, error) {
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	username = strings.ToLower(username)
	res, err := s.q.ExecContext(ctx, `INSERT INTO users (username, password_hash, webauthn_id) VALUES (?,?,?)`, username, passwordHash, handle)
	if err != nil {
		return User{}, fmt.Errorf("create user %s: %w", username, err)
	}
	id, _ := res.LastInsertId()
	return s.GetUser(ctx, id)
}

func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	u, err := scanUser(s.q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id=?", id))
	if err != nil {
		return User{}, fmt.Errorf("get user %d: %w", id, err)
	}
	return u, nil
}

// GetUserByName looks the name up case-insensitively; ok=false when there is no such user.
func (s *Store) GetUserByName(ctx context.Context, username string) (u User, ok bool, err error) {
	u, err = scanUser(s.q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username=?", strings.ToLower(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("get user %s: %w", username, err)
	}
	return u, true, nil
}

// GetUserByWebAuthnID resolves the user handle a passkey login returns.
func (s *Store) GetUserByWebAuthnID(ctx context.Context, handle []byte) (u User, ok bool, err error) {
	u, err = scanUser(s.q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE webauthn_id=?", handle))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, fmt.Errorf("get user by handle: %w", err)
	}
	return u, true, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY username")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) CountUsers(ctx context.Context) (n int, err error) {
	err = s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetPassword replaces the hash and ends the user's sessions.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE users SET password_hash=?, session_epoch=session_epoch+1 WHERE id=?`, hash, id); err != nil {
		return fmt.Errorf("set password of user %d: %w", id, err)
	}
	return nil
}

// BumpEpoch ends the user's sessions.
func (s *Store) BumpEpoch(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE users SET session_epoch=session_epoch+1 WHERE id=?`, id); err != nil {
		return fmt.Errorf("end sessions of user %d: %w", id, err)
	}
	return nil
}

func (s *Store) TouchLogin(ctx context.Context, id int64, at string) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, at, id); err != nil {
		return fmt.Errorf("touch login of user %d: %w", id, err)
	}
	return nil
}

// DeleteUser removes the user and, by cascade, their authenticator, backup codes and passkeys.
// The last remaining user cannot be removed.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	return s.Tx(ctx, func(tx *Store) error {
		n, err := tx.CountUsers(ctx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastAdmin
		}
		if _, err := tx.q.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id); err != nil {
			return fmt.Errorf("delete user %d: %w", id, err)
		}
		return nil
	})
}
