package store

import (
	"context"
	"fmt"
)

type Domain struct {
	ID         int64
	Name       string
	ZoneID     string
	DefaultIP  string // IPv4 target of the domain's A records
	DefaultIP6 string // optional IPv6 target of its AAAA records; "" = no AAAA records
	CertMode   string // wildcard | per_host
	CreatedAt  string
}

type Site struct {
	ID            int64
	DomainID      int64
	Subdomain     string
	Scheme        string // http | https
	UpstreamHost  string
	UpstreamPort  int
	TLSSkipVerify bool
	Enabled       bool
	RecordIP      string // "" = domain default
	RecordIP6     string // IPv6 override for this site's AAAA record; "" = domain default
	Allowlist     string // newline-separated CIDRs
	BasicUser     string
	BasicHash     string // bcrypt
	Stream        bool   // no response buffering (flush_interval -1)
	MaxBody       int64  // request body limit in bytes; 0 = Caddy default
	GateMode      string // "" | acl | open: the magic-link gate (gate.go)
}

// Record families: one DNS row per site (and one for the UI host) per family.
const (
	FamilyA    = "A"
	FamilyAAAA = "AAAA"
)

type DNSRecord struct {
	SiteID     int64
	Family     string // FamilyA | FamilyAAAA; "" means FamilyA
	CFRecordID string
	Content    string
	Owned      bool
	State      string // pending | synced | error | conflict
	Error      string
	SyncedAt   string
}

const domainCols = "id, name, zone_id, default_ip, default_ip6, cert_mode, created_at"

func scanDomain(r interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	err := r.Scan(&d.ID, &d.Name, &d.ZoneID, &d.DefaultIP, &d.DefaultIP6, &d.CertMode, &d.CreatedAt)
	return d, err
}

func (s *Store) CreateDomain(ctx context.Context, d Domain) (Domain, error) {
	res, err := s.q.ExecContext(ctx, "INSERT INTO domains (name, zone_id, default_ip, default_ip6, cert_mode) VALUES (?,?,?,?,?)",
		d.Name, d.ZoneID, d.DefaultIP, d.DefaultIP6, d.CertMode)
	if err != nil {
		return Domain{}, fmt.Errorf("create domain %s: %w", d.Name, err)
	}
	id, _ := res.LastInsertId()
	return s.GetDomain(ctx, id)
}

func (s *Store) GetDomain(ctx context.Context, id int64) (Domain, error) {
	d, err := scanDomain(s.q.QueryRowContext(ctx, "SELECT "+domainCols+" FROM domains WHERE id=?", id))
	if err != nil {
		return Domain{}, fmt.Errorf("get domain %d: %w", id, err)
	}
	return d, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+domainCols+" FROM domains ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) UpdateDomain(ctx context.Context, d Domain) error {
	_, err := s.q.ExecContext(ctx, "UPDATE domains SET zone_id=?, default_ip=?, default_ip6=?, cert_mode=? WHERE id=?",
		d.ZoneID, d.DefaultIP, d.DefaultIP6, d.CertMode, d.ID)
	if err != nil {
		return fmt.Errorf("update domain %d: %w", d.ID, err)
	}
	return nil
}

func (s *Store) DeleteDomain(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM domains WHERE id=?", id); err != nil {
		return fmt.Errorf("delete domain %d: %w", id, err)
	}
	return nil
}

const siteCols = "id, domain_id, subdomain, scheme, upstream_host, upstream_port, tls_skip_verify, enabled, " +
	"COALESCE(record_ip,''), COALESCE(record_ip6,''), allowlist, COALESCE(basic_user,''), COALESCE(basic_hash,''), stream, max_body, gate_mode"

func scanSite(r interface{ Scan(...any) error }) (Site, error) {
	var x Site
	err := r.Scan(&x.ID, &x.DomainID, &x.Subdomain, &x.Scheme, &x.UpstreamHost, &x.UpstreamPort, &x.TLSSkipVerify,
		&x.Enabled, &x.RecordIP, &x.RecordIP6, &x.Allowlist, &x.BasicUser, &x.BasicHash, &x.Stream, &x.MaxBody, &x.GateMode)
	return x, err
}

func (s *Store) CreateSite(ctx context.Context, r Site) (Site, error) {
	res, err := s.q.ExecContext(ctx, `INSERT INTO sites (domain_id, subdomain, scheme, upstream_host, upstream_port,
		tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.DomainID, r.Subdomain, r.Scheme, r.UpstreamHost, r.UpstreamPort, r.TLSSkipVerify, r.Enabled,
		nullStr(r.RecordIP), nullStr(r.RecordIP6), r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode)
	if err != nil {
		return Site{}, fmt.Errorf("create site %s: %w", r.Subdomain, err)
	}
	id, _ := res.LastInsertId()
	return s.GetSite(ctx, id)
}

func (s *Store) GetSite(ctx context.Context, id int64) (Site, error) {
	r, err := scanSite(s.q.QueryRowContext(ctx, "SELECT "+siteCols+" FROM sites WHERE id=?", id))
	if err != nil {
		return Site{}, fmt.Errorf("get site %d: %w", id, err)
	}
	return r, nil
}

// ListSites returns all routes ordered by domain then subdomain.
func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+siteCols+" FROM sites ORDER BY domain_id, subdomain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		r, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateSite(ctx context.Context, r Site) error {
	_, err := s.q.ExecContext(ctx, `UPDATE sites SET subdomain=?, scheme=?, upstream_host=?, upstream_port=?,
		tls_skip_verify=?, enabled=?, record_ip=?, record_ip6=?, allowlist=?, basic_user=?, basic_hash=?, stream=?, max_body=?, gate_mode=? WHERE id=?`,
		r.Subdomain, r.Scheme, r.UpstreamHost, r.UpstreamPort, r.TLSSkipVerify, r.Enabled, nullStr(r.RecordIP), nullStr(r.RecordIP6),
		r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode, r.ID)
	if err != nil {
		return fmt.Errorf("update site %d: %w", r.ID, err)
	}
	return nil
}

func (s *Store) DeleteSite(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM sites WHERE id=?", id); err != nil {
		return fmt.Errorf("delete site %d: %w", id, err)
	}
	return nil
}

func familyOf(f string) string {
	if f == "" {
		return FamilyA
	}
	return f
}

// GetDNS returns the site's record of one family (FamilyA or FamilyAAAA).
func (s *Store) GetDNS(ctx context.Context, siteID int64, family string) (DNSRecord, error) {
	d := DNSRecord{Family: familyOf(family)}
	err := s.q.QueryRowContext(ctx, `SELECT site_id, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state,
		COALESCE(error,''), COALESCE(synced_at,'') FROM dns_records WHERE site_id=? AND family=?`, siteID, d.Family).
		Scan(&d.SiteID, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get %s record for site %d: %w", d.Family, siteID, err)
	}
	return d, nil
}

func (s *Store) UpsertDNS(ctx context.Context, d DNSRecord) error {
	d.Family = familyOf(d.Family)
	_, err := s.q.ExecContext(ctx, `INSERT INTO dns_records (site_id, family, cf_record_id, content, owned, state, error, synced_at)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(site_id, family) DO UPDATE SET cf_record_id=excluded.cf_record_id,
		content=excluded.content, owned=excluded.owned, state=excluded.state, error=excluded.error, synced_at=excluded.synced_at`,
		d.SiteID, d.Family, nullStr(d.CFRecordID), nullStr(d.Content), d.Owned, d.State, nullStr(d.Error), nullStr(d.SyncedAt))
	if err != nil {
		return fmt.Errorf("upsert %s record for site %d: %w", d.Family, d.SiteID, err)
	}
	return nil
}

const dnsCols = "site_id, family, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state, COALESCE(error,''), COALESCE(synced_at,'')"

// ListDNS returns every record, ordered by site then family (A before AAAA).
func (s *Store) ListDNS(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+dnsCols+" FROM dns_records ORDER BY site_id, family")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var d DNSRecord
		if err := rows.Scan(&d.SiteID, &d.Family, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDNS removes every record row of the site, whatever the family.
func (s *Store) DeleteDNS(ctx context.Context, siteID int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE site_id=?", siteID); err != nil {
		return fmt.Errorf("delete dns records for site %d: %w", siteID, err)
	}
	return nil
}

// DeleteDNSRecord removes one family's row, for example the AAAA row when the site's IPv6 address is cleared.
func (s *Store) DeleteDNSRecord(ctx context.Context, siteID int64, family string) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE site_id=? AND family=?", siteID, familyOf(family)); err != nil {
		return fmt.Errorf("delete %s record for site %d: %w", familyOf(family), siteID, err)
	}
	return nil
}

// The UI host's records live in ui_dns_record, one row per family (SiteID is unused).

func (s *Store) GetUIDNS(ctx context.Context, family string) (DNSRecord, error) {
	d := DNSRecord{Family: familyOf(family)}
	err := s.q.QueryRowContext(ctx, `SELECT COALESCE(cf_record_id,''), COALESCE(content,''), owned, state,
		COALESCE(error,''), COALESCE(synced_at,'') FROM ui_dns_record WHERE family=?`, d.Family).
		Scan(&d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get ui %s record: %w", d.Family, err)
	}
	return d, nil
}

func (s *Store) UpsertUIDNS(ctx context.Context, d DNSRecord) error {
	d.Family = familyOf(d.Family)
	_, err := s.q.ExecContext(ctx, `INSERT INTO ui_dns_record (family, cf_record_id, content, owned, state, error, synced_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(family) DO UPDATE SET cf_record_id=excluded.cf_record_id,
		content=excluded.content, owned=excluded.owned, state=excluded.state, error=excluded.error, synced_at=excluded.synced_at`,
		d.Family, nullStr(d.CFRecordID), nullStr(d.Content), d.Owned, d.State, nullStr(d.Error), nullStr(d.SyncedAt))
	if err != nil {
		return fmt.Errorf("upsert ui %s record: %w", d.Family, err)
	}
	return nil
}

// ListUIDNS returns the UI host's records, A before AAAA.
func (s *Store) ListUIDNS(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT family, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state,
		COALESCE(error,''), COALESCE(synced_at,'') FROM ui_dns_record ORDER BY family`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var d DNSRecord
		if err := rows.Scan(&d.Family, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUIDNS(ctx context.Context, family string) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM ui_dns_record WHERE family=?", familyOf(family)); err != nil {
		return fmt.Errorf("delete ui %s record: %w", familyOf(family), err)
	}
	return nil
}
