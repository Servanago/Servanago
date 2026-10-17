// Gate methods: ACL grants, magic-link tokens (hashed, consumed atomically) and session
// identities for the per-site magic-link gate (DESIGN.md §18). Hashing and clocks live in the
// caller: these methods take already-hashed values and RFC3339 time strings.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/servanago/servanago/internal/gatelogic"
)

type Grant struct {
	SiteID int64
	Mode   string // email | domain
	Value  string
}

func (s *Store) Grants(ctx context.Context, siteID int64) ([]Grant, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT site_id, mode, value FROM gate_grants WHERE site_id=? ORDER BY mode, value", siteID)
	if err != nil {
		return nil, fmt.Errorf("list grants for site %d: %w", siteID, err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.SiteID, &g.Mode, &g.Value); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) setGrants(ctx context.Context, siteID int64, gs []Grant) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM gate_grants WHERE site_id=?", siteID); err != nil {
		return fmt.Errorf("clear grants for site %d: %w", siteID, err)
	}
	for _, g := range gs {
		g.SiteID = siteID
		if g.Mode != "email" && g.Mode != "domain" {
			return fmt.Errorf("grant mode %q is not email or domain", g.Mode)
		}
		if _, err := s.q.ExecContext(ctx, "INSERT OR IGNORE INTO gate_grants (site_id, mode, value) VALUES (?,?,?)",
			siteID, g.Mode, g.Value); err != nil {
			return fmt.Errorf("add grant for site %d: %w", siteID, err)
		}
	}
	return nil
}

// grantsEqual is set membership by (mode, value); ids are irrelevant when comparing before/after.
func grantsEqual(a, b Grant) bool {
	return a.SiteID == b.SiteID && a.Mode == b.Mode && a.Value == b.Value
}

// ReplaceGrants swaps a site's grant set and revokes identities that lose their last
// qualifying grant: a session no longer matched by any ACL row is deleted in the same tx.
// ponytail: O(identities × grants) rescan; homelab ACL counts are trivial.
func (s *Store) ReplaceGrants(ctx context.Context, siteID int64, gs []Grant) error {
	old, err := s.Grants(ctx, siteID)
	if err != nil {
		return err
	}
	if err := s.setGrants(ctx, siteID, gs); err != nil {
		return err
	}
	removed := make([]gatelogic.Rule, 0, len(old))
	for _, o := range old {
		in := false
		for _, n := range gs {
			in = in || grantsEqual(o, n)
		}
		if !in {
			removed = append(removed, gatelogic.Rule{Mode: o.Mode, Value: o.Value})
		}
	}
	if len(removed) == 0 {
		return nil
	}
	all, err := s.allGrants(ctx) // includes the new set for siteID
	if err != nil {
		return err
	}
	rows, err := s.q.QueryContext(ctx, "SELECT email FROM gate_identities")
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}
	defer rows.Close()
	var victims []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return err
		}
		if !gatelogic.Qualify(e, removed) {
			continue
		}
		if gatelogic.Qualify(e, rulesOf(all)) {
			continue // still holds a grant elsewhere or under the new set
		}
		victims = append(victims, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, e := range victims {
		if _, err := s.q.ExecContext(ctx, "DELETE FROM gate_identities WHERE email=?", e); err != nil {
			return fmt.Errorf("revoke %s: %w", e, err)
		}
	}
	return nil
}

func rulesOf(gs []Grant) []gatelogic.Rule {
	out := make([]gatelogic.Rule, len(gs))
	for i, g := range gs {
		out[i] = gatelogic.Rule{Mode: g.Mode, Value: g.Value}
	}
	return out
}

// IdentityNonce returns the identity's session-nonce when it exists ("", nil when not).
func (s *Store) IdentityNonce(ctx context.Context, email string) (string, error) {
	var nonce string
	err := s.q.QueryRowContext(ctx, "SELECT nonce FROM gate_identities WHERE email=?", email).Scan(&nonce)
	if err == nil {
		return nonce, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return "", fmt.Errorf("read identity %s: %w", email, err)
}

// UpsertIdentity creates or refreshes the identity row. The secret never lands here: only its
// hash and the nonce the caller derived it from.
func (s *Store) UpsertIdentity(ctx context.Context, email, nonce, tokenHash, now string, window time.Duration) error {
	_, err := s.q.ExecContext(ctx, `INSERT INTO gate_identities (email, nonce, token_hash, created_at, last_seen, expire)
		VALUES (?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET token_hash=?, last_seen=?, expire=?`,
		email, nonce, tokenHash, now, now, timeStr(now, window), tokenHash, now, timeStr(now, window))
	if err != nil {
		return fmt.Errorf("upsert identity %s: %w", email, err)
	}
	return nil
}

// Session reports the email behind a hashed cookie value. Expired identities are deleted on
// the spot: the next request cannot resurrect them either.
func (s *Store) Session(ctx context.Context, tokenHash, now string) (email string, ok bool, err error) {
	var expire string
	err = s.q.QueryRowContext(ctx, "SELECT email, expire FROM gate_identities WHERE token_hash=?", tokenHash).Scan(&email, &expire)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read session: %w", err)
	}
	if expire <= now {
		if _, derr := s.q.ExecContext(ctx, "DELETE FROM gate_identities WHERE token_hash=?", tokenHash); derr != nil {
			return "", false, fmt.Errorf("expire session %s: %w", email, derr)
		}
		return "", false, nil
	}
	return email, true, nil
}

// TouchSession slides the window for a passing check (gate_mode decides the window).
func (s *Store) TouchSession(ctx context.Context, tokenHash, now string, window time.Duration) error {
	if _, err := s.q.ExecContext(ctx, "UPDATE gate_identities SET last_seen=?, expire=? WHERE token_hash=?",
		now, timeStr(now, window), tokenHash); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// GateIdentity is one row of the security-page listing.
type GateIdentity struct {
	Email     string
	CreatedAt string
	LastSeen  string
	Expire    string
	Rules     string // comma-joined "value at host" list
}

// GateIdentities lists identities with the ACL grants they qualify for, joined with host names.
func (s *Store) GateIdentities(ctx context.Context) ([]GateIdentity, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT i.email, i.created_at, i.last_seen, i.expire,
		COALESCE((SELECT GROUP_CONCAT(CASE g.mode WHEN 'email' THEN g.value ELSE '@'||g.value END || ' at ' || (r.subdomain || '.' || d.name))
			FROM gate_grants g JOIN sites r ON r.id=g.site_id JOIN domains d ON d.id=r.domain_id
			WHERE r.gate_mode='acl' AND (
				(g.mode='email' AND g.value=i.email) OR
				(g.mode='domain' AND SUBSTR(i.email, INSTR(i.email,'@')) = '@'||g.value))), '') AS rules
		FROM gate_identities i ORDER BY i.email`)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	defer rows.Close()
	var out []GateIdentity
	for rows.Next() {
		var g GateIdentity
		if err := rows.Scan(&g.Email, &g.CreatedAt, &g.LastSeen, &g.Expire, &g.Rules); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteIdentity revokes the session everywhere at once.
func (s *Store) DeleteIdentity(ctx context.Context, email string) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM gate_identities WHERE email=?", email); err != nil {
		return fmt.Errorf("delete identity %s: %w", email, err)
	}
	return nil
}

// IssueToken stores a hashed magic-link token; sweeps expired ones so the table stays small.
func (s *Store) IssueToken(ctx context.Context, tokenHash, host, email, now string, ttl time.Duration) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM gate_tokens WHERE expires_at <= ?", now); err != nil {
		return fmt.Errorf("sweep tokens: %w", err)
	}
	if _, err := s.q.ExecContext(ctx, "INSERT INTO gate_tokens (token_hash, host, email, created_at, expires_at) VALUES (?,?,?,?,?)",
		tokenHash, host, email, now, timeStr(now, ttl)); err != nil {
		return fmt.Errorf("issue token: %w", err)
	}
	return nil
}

// ConsumeToken atomically marks a valid (unconsumed, unexpired, right-host) token used and
// returns its email; a second concurrent caller loses (0 rows affected).
func (s *Store) ConsumeToken(ctx context.Context, tokenHash, host, now string) (email string, ok bool, err error) {
	res, err := s.q.ExecContext(ctx, "UPDATE gate_tokens SET consumed_at=? WHERE token_hash=? AND host=? AND consumed_at IS NULL AND expires_at > ?",
		now, tokenHash, host, now)
	if err != nil {
		return "", false, fmt.Errorf("consume token: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return "", false, nil // unknown, replay, wrong host or expired: one generic outcome
	}
	err = s.q.QueryRowContext(ctx, "SELECT email FROM gate_tokens WHERE token_hash=?", tokenHash).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read token email: %w", err)
	}
	return email, true, nil
}

// allGrants is the raw grant set for revoke bookkeeping (every mode).
func (s *Store) allGrants(ctx context.Context) ([]Grant, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT site_id, mode, value FROM gate_grants")
	if err != nil {
		return nil, fmt.Errorf("list all grants: %w", err)
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.SiteID, &g.Mode, &g.Value); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func timeStr(now string, add time.Duration) string {
	t, err := time.Parse(time.RFC3339, now)
	if err != nil { // now always comes from the caller's clock, RFC3339 formatted
		return now
	}
	return t.Add(add).UTC().Format(time.RFC3339)
}
