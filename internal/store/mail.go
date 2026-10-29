// Postmark mail-bridge state: per-domain provisioning, counters, events and webhook deliveries.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MailDomain is one provisioned mail domain.
type MailDomain struct {
	ID           int64
	Name         string
	PMServerID   int64 // Postmark server id; 0 = none yet
	PMDomainID   int64
	DKIMHost     string
	DKIMText     string
	ReturnPath   string
	HookUser     string
	HookPassHash string
	DNSSetup     string // dns_notes, one line per note
	DKIMState    string // "" | pending | verified | failed
	RPState      string
	LastVerify   int64
	LMTPAddr     string // per-domain override of the global target
	Recv         int
	Delivered    int
	Deduped      int
	Rejected     int
	Fallbacks    int
	LastInbound  int64
	CreatedAt    int64
}

const mailDomainCols = "id, name, pm_server_id, pm_domain_id, dkim_host, dkim_text, return_path, hook_user, hook_pass_hash, dns_notes, dkim_state, rp_state, last_verify, lmtp_addr, recv, delivered, deduped, rejected, fallbacks, last_inbound, created_at"

func scanMailDomain(row interface{ Scan(...any) error }, d *MailDomain) error {
	return row.Scan(&d.ID, &d.Name, &d.PMServerID, &d.PMDomainID, &d.DKIMHost, &d.DKIMText, &d.ReturnPath,
		&d.HookUser, &d.HookPassHash, &d.DNSSetup, &d.DKIMState, &d.RPState, &d.LastVerify,
		&d.LMTPAddr, &d.Recv, &d.Delivered, &d.Deduped, &d.Rejected, &d.Fallbacks, &d.LastInbound, &d.CreatedAt)
}

func (s *Store) GetMailDomain(ctx context.Context, name string) (MailDomain, error) {
	var d MailDomain
	err := scanMailDomain(s.q.QueryRowContext(ctx,
		`SELECT `+mailDomainCols+` FROM mail_domains WHERE name=?`, strings.ToLower(name)), &d)
	return d, err // sql.ErrNoRows is the caller's "not provisioned"
}

func (s *Store) ListMailDomains(ctx context.Context) ([]MailDomain, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+mailDomainCols+` FROM mail_domains ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list mail domains: %w", err)
	}
	defer rows.Close()
	var out []MailDomain
	for rows.Next() {
		var d MailDomain
		if err := scanMailDomain(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpsertMailDomain creates or re-provisions a row by name, leaving counters and notes untouched.
// It returns the row id and whether it was created.
func (s *Store) UpsertMailDomain(ctx context.Context, d MailDomain) (int64, bool, error) {
	if d.Name == "" {
		return 0, false, fmt.Errorf("mail domain name is empty")
	}
	d.Name = strings.ToLower(d.Name)
	cur, err := s.GetMailDomain(ctx, d.Name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, ierr := s.q.ExecContext(ctx,
			`INSERT INTO mail_domains (name, pm_server_id, pm_domain_id, dkim_host, dkim_text, return_path, hook_user, hook_pass_hash, dns_notes, dkim_state, rp_state, lmtp_addr, created_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,strftime('%s','now'))`,
			d.Name, d.PMServerID, d.PMDomainID, d.DKIMHost, d.DKIMText, d.ReturnPath, d.HookUser, d.HookPassHash,
			d.DNSSetup, d.DKIMState, d.RPState, d.LMTPAddr)
		if ierr != nil {
			return 0, false, fmt.Errorf("create mail domain %s: %w", d.Name, ierr)
		}
		id, _ := res.LastInsertId()
		return id, true, nil
	case err != nil:
		return 0, false, err
	}
	if _, err := s.q.ExecContext(ctx,
		`UPDATE mail_domains SET pm_server_id=?, pm_domain_id=?, dkim_host=?, dkim_text=?, return_path=?, hook_user=?, hook_pass_hash=?, dns_notes=?, dkim_state=?, rp_state=?, last_verify=0, lmtp_addr=? WHERE name=?`,
		d.PMServerID, d.PMDomainID, d.DKIMHost, d.DKIMText, d.ReturnPath, d.HookUser, d.HookPassHash,
		d.DNSSetup, d.DKIMState, d.RPState, d.LMTPAddr, d.Name); err != nil {
		return 0, false, fmt.Errorf("update mail domain %s: %w", d.Name, err)
	}
	return cur.ID, false, nil
}

// SetMailDNS stores what the detached DNS write produced (record values and line notes).
func (s *Store) SetMailDNS(ctx context.Context, id int64, dkimHost, dkimText, returnPath, notes string) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE mail_domains SET dkim_host=?, dkim_text=?, return_path=?, dns_notes=? WHERE id=?`,
		dkimHost, dkimText, returnPath, notes, id); err != nil {
		return fmt.Errorf("save mail DNS state %d: %w", id, err)
	}
	return nil
}

// SetMailVerifyStates records the outcome of the last verification check.
func (s *Store) SetMailVerifyStates(ctx context.Context, id int64, dkim, rp string) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE mail_domains SET dkim_state=?, rp_state=?, last_verify=strftime('%s','now') WHERE id=?`,
		dkim, rp, id); err != nil {
		return fmt.Errorf("save mail verify state %d: %w", id, err)
	}
	return nil
}

var mailCounters = map[string]bool{"recv": true, "delivered": true, "deduped": true, "rejected": true, "fallbacks": true}

// CountMail adds one to each named counter (closed list) and stamps last_inbound when asked.
func (s *Store) CountMail(ctx context.Context, id int64, lastInbound bool, which ...string) error {
	sets := make([]string, 0, len(which)+1)
	for _, k := range which {
		if !mailCounters[k] {
			return fmt.Errorf("unknown mail counter %q", k)
		}
		sets = append(sets, k+"="+k+"+1")
	}
	if lastInbound {
		sets = append(sets, "last_inbound=strftime('%s','now')")
	}
	if _, err := s.q.ExecContext(ctx,
		`UPDATE mail_domains SET `+strings.Join(sets, ", ")+` WHERE id=?`, id); err != nil {
		return fmt.Errorf("count mail on %d: %w", id, err)
	}
	return nil
}

// MailEvent is one stored Postmark event notification.
type MailEvent struct {
	ID         int64
	DomainID   int64
	RecordType string
	RecordID   string // the bounce's own ID
	MessageID  string
	Address    string
	Summary    string
	Payload    string
	DSNSent    int64
	CreatedAt  int64
}

// InsertMailEvent stores one event and returns its row id.
func (s *Store) InsertMailEvent(ctx context.Context, e MailEvent) (int64, error) {
	res, err := s.q.ExecContext(ctx,
		`INSERT INTO mail_events (domain_id, record_type, record_id, message_id, address, summary, payload, created_at)
		 VALUES (?,?,?,?,?,?,?,strftime('%s','now'))`,
		e.DomainID, e.RecordType, e.RecordID, e.MessageID, e.Address, e.Summary, e.Payload)
	if err != nil {
		return 0, fmt.Errorf("insert mail event: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// MarkMailEventDSN stamps the event whose DSN went out.
func (s *Store) MarkMailEventDSN(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE mail_events SET dsn_sent=strftime('%s','now') WHERE id=?`, id); err != nil {
		return fmt.Errorf("mark mail event %d: %w", id, err)
	}
	return nil
}

// ListMailEvents returns the newest events, for one domain when domainID != 0.
func (s *Store) ListMailEvents(ctx context.Context, domainID int64, limit int) ([]MailEvent, error) {
	q := "SELECT id, domain_id, record_type, record_id, message_id, address, summary, payload, dsn_sent, created_at FROM mail_events"
	args := []any{}
	if domainID != 0 {
		q += " WHERE domain_id=?"
		args = append(args, domainID)
	}
	if limit <= 0 {
		limit = 25
	}
	args = append(args, limit)
	q += " ORDER BY id DESC LIMIT ?"
	rows, err := s.q.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list mail events: %w", err)
	}
	defer rows.Close()
	var out []MailEvent
	for rows.Next() {
		var e MailEvent
		if err := rows.Scan(&e.ID, &e.DomainID, &e.RecordType, &e.RecordID, &e.MessageID, &e.Address, &e.Summary, &e.Payload, &e.DSNSent, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeliverOnce records a delivery key and reports whether it was new (false = seen before).
func (s *Store) DeliverOnce(ctx context.Context, key string, domainID int64) (bool, error) {
	res, err := s.q.ExecContext(ctx,
		`INSERT OR IGNORE INTO mail_delivered (key, domain_id, created_at) VALUES (?,?,strftime('%s','now'))`,
		key, domainID)
	if err != nil {
		return false, fmt.Errorf("record delivery %s: %w", key, err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeleteMailDomain drops the row and its events and delivered keys; Postmark and DNS are untouched.
func (s *Store) DeleteMailDomain(ctx context.Context, name string) error {
	res, err := s.q.ExecContext(ctx, `DELETE FROM mail_domains WHERE name=?`, strings.ToLower(name))
	if err != nil {
		return fmt.Errorf("delete mail domain %s: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("delete mail domain %s: no row", name)
	}
	return nil
}