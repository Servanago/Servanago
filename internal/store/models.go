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

type Route struct {
	ID            int64
	DomainID      int64
	Subdomain     string
	Scheme        string // http | https
	UpstreamHost  string
	UpstreamPort  int
	TLSSkipVerify bool
	Enabled       bool
	RecordIP      string // "" = domain default
	RecordIP6     string // IPv6 override for this route's AAAA record; "" = domain default
	Allowlist     string // newline-separated CIDRs
	BasicUser     string
	BasicHash     string // bcrypt
	Stream        bool   // no response buffering (flush_interval -1)
	MaxBody       int64  // request body limit in bytes; 0 = Caddy default
	GateMode      string // "" | acl | open: the magic-link gate (gate.go)
}

// Record families: one DNS row per route (and one for the UI host) per family.
const (
	FamilyA    = "A"
	FamilyAAAA = "AAAA"
)

type DNSRecord struct {
	RouteID    int64
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

const routeCols = "id, domain_id, subdomain, scheme, upstream_host, upstream_port, tls_skip_verify, enabled, " +
	"COALESCE(record_ip,''), COALESCE(record_ip6,''), allowlist, COALESCE(basic_user,''), COALESCE(basic_hash,''), stream, max_body, gate_mode"

func scanRoute(r interface{ Scan(...any) error }) (Route, error) {
	var x Route
	err := r.Scan(&x.ID, &x.DomainID, &x.Subdomain, &x.Scheme, &x.UpstreamHost, &x.UpstreamPort, &x.TLSSkipVerify,
		&x.Enabled, &x.RecordIP, &x.RecordIP6, &x.Allowlist, &x.BasicUser, &x.BasicHash, &x.Stream, &x.MaxBody, &x.GateMode)
	return x, err
}

func (s *Store) CreateRoute(ctx context.Context, r Route) (Route, error) {
	res, err := s.q.ExecContext(ctx, `INSERT INTO routes (domain_id, subdomain, scheme, upstream_host, upstream_port,
		tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.DomainID, r.Subdomain, r.Scheme, r.UpstreamHost, r.UpstreamPort, r.TLSSkipVerify, r.Enabled,
		nullStr(r.RecordIP), nullStr(r.RecordIP6), r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode)
	if err != nil {
		return Route{}, fmt.Errorf("create route %s: %w", r.Subdomain, err)
	}
	id, _ := res.LastInsertId()
	return s.GetRoute(ctx, id)
}

func (s *Store) GetRoute(ctx context.Context, id int64) (Route, error) {
	r, err := scanRoute(s.q.QueryRowContext(ctx, "SELECT "+routeCols+" FROM routes WHERE id=?", id))
	if err != nil {
		return Route{}, fmt.Errorf("get route %d: %w", id, err)
	}
	return r, nil
}

// ListRoutes returns all routes ordered by domain then subdomain.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+routeCols+" FROM routes ORDER BY domain_id, subdomain")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateRoute(ctx context.Context, r Route) error {
	_, err := s.q.ExecContext(ctx, `UPDATE routes SET subdomain=?, scheme=?, upstream_host=?, upstream_port=?,
		tls_skip_verify=?, enabled=?, record_ip=?, record_ip6=?, allowlist=?, basic_user=?, basic_hash=?, stream=?, max_body=?, gate_mode=? WHERE id=?`,
		r.Subdomain, r.Scheme, r.UpstreamHost, r.UpstreamPort, r.TLSSkipVerify, r.Enabled, nullStr(r.RecordIP), nullStr(r.RecordIP6),
		r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode, r.ID)
	if err != nil {
		return fmt.Errorf("update route %d: %w", r.ID, err)
	}
	return nil
}

func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM routes WHERE id=?", id); err != nil {
		return fmt.Errorf("delete route %d: %w", id, err)
	}
	return nil
}

func familyOf(f string) string {
	if f == "" {
		return FamilyA
	}
	return f
}

// GetDNS returns the route's record of one family (FamilyA or FamilyAAAA).
func (s *Store) GetDNS(ctx context.Context, routeID int64, family string) (DNSRecord, error) {
	d := DNSRecord{Family: familyOf(family)}
	err := s.q.QueryRowContext(ctx, `SELECT route_id, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state,
		COALESCE(error,''), COALESCE(synced_at,'') FROM dns_records WHERE route_id=? AND family=?`, routeID, d.Family).
		Scan(&d.RouteID, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get %s record for route %d: %w", d.Family, routeID, err)
	}
	return d, nil
}

func (s *Store) UpsertDNS(ctx context.Context, d DNSRecord) error {
	d.Family = familyOf(d.Family)
	_, err := s.q.ExecContext(ctx, `INSERT INTO dns_records (route_id, family, cf_record_id, content, owned, state, error, synced_at)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(route_id, family) DO UPDATE SET cf_record_id=excluded.cf_record_id,
		content=excluded.content, owned=excluded.owned, state=excluded.state, error=excluded.error, synced_at=excluded.synced_at`,
		d.RouteID, d.Family, nullStr(d.CFRecordID), nullStr(d.Content), d.Owned, d.State, nullStr(d.Error), nullStr(d.SyncedAt))
	if err != nil {
		return fmt.Errorf("upsert %s record for route %d: %w", d.Family, d.RouteID, err)
	}
	return nil
}

const dnsCols = "route_id, family, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state, COALESCE(error,''), COALESCE(synced_at,'')"

// ListDNS returns every record, ordered by route then family (A before AAAA).
func (s *Store) ListDNS(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+dnsCols+" FROM dns_records ORDER BY route_id, family")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var d DNSRecord
		if err := rows.Scan(&d.RouteID, &d.Family, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDNS removes every record row of the route, whatever the family.
func (s *Store) DeleteDNS(ctx context.Context, routeID int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE route_id=?", routeID); err != nil {
		return fmt.Errorf("delete dns records for route %d: %w", routeID, err)
	}
	return nil
}

// DeleteDNSRecord removes one family's row, for example the AAAA row when the route's IPv6 address is cleared.
func (s *Store) DeleteDNSRecord(ctx context.Context, routeID int64, family string) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE route_id=? AND family=?", routeID, familyOf(family)); err != nil {
		return fmt.Errorf("delete %s record for route %d: %w", familyOf(family), routeID, err)
	}
	return nil
}

// The UI host's records live in ui_dns_record, one row per family (RouteID is unused).

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
