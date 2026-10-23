package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
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
	ID             int64
	Slug           string   // immutable; derived from the first hostname on create
	Kind           string   // proxy | static | node | php | frankenphp | fastcgi | cgi; "" means proxy on create
	Hostnames      []string // primary first; each is a free FQDN, unique across sites
	Scheme         string   // http | https (proxy)
	UpstreamHost   string   // proxy; fastcgi: a host, or an absolute socket path (then UpstreamPort is 0)
	UpstreamPort   int      // proxy only; node and frankenphp: the app's port (upstream_host stores 127.0.0.1)
	StaticRoot     string   // static, node, php, frankenphp, fastcgi and cgi: absolute directory served
	StartCommand   string   // node: the long-running start command, run by systemd as the site user
	InstallCommand string   // node: shown to the admin, who runs it by hand on the server
	BuildCommand   string   // node: same
	FPMVersion     string   // php: version of the detected php-fpm binary, e.g. 8.2
	TLSSkipVerify  bool
	Enabled        bool
	RecordIP       string // "" = domain default
	RecordIP6      string // IPv6 override for this site's AAAA record; "" = domain default
	Allowlist      string // newline-separated CIDRs
	BasicUser      string
	BasicHash      string   // bcrypt
	Stream         bool     // no response buffering (flush_interval -1)
	MaxBody        int64    // request body limit in bytes; 0 = Caddy default
	GateMode       string   // "" | acl | open: the magic-link gate (gate.go)
	GateProvider   string   // "" | smtp | postmark: how this site's magic links are mailed
	GateFrom       string   // sender address of the links
	GateSMTPHost   string   // smtp provider
	GateSMTPPort   int      // smtp provider
	GateSMTPUser   string   // smtp provider; "" = no authentication
	GateSecret     []byte   // secretbox blob: the SMTP password or the Postmark server token; nil = none
	ExtraRoutes    string   // one route per line, path=dial (internal/config.ParseExtraRoutes): Caddy proxies each path to its own upstream before the site's main handler
	PHPExtensions  string   // php: space-separated shared extensions from the allowlist; "" = the core set
	PHPHealthPath  string   // php: path requested after a PHP switch; "" = only check that the unit stays up
	SiteUser       string   // node, php, frankenphp, cgi, static: the Unix user it runs as (one site per user); "" = the generated sg-<slug>
	PublicDir      string   // php, frankenphp, fastcgi, static: the served folder inside StaticRoot; "" = StaticRoot itself
	Snippets       []string // attached snippet names, sorted; ListSites and GetSite fill it, Create and UpdateSite save it
	Notes          string   // admin notes for the Reference page, at most 10,000 characters
	UpdatedAt      string   // RFC3339 UTC time of the last save; set by CreateSite and UpdateSite, never by the caller
}

// MLHost is the magic-link host of a gated site, ml.<primary>; "" for an ungated site. It serves only the gate's own
// pages, so the emailed link opens there and the site host receives the session by a one-time handoff.
func (s Site) MLHost() string {
	if s.GateMode == "" || len(s.Hostnames) == 0 {
		return ""
	}
	return "ml." + s.Hostnames[0]
}

// GateMailReady is true when the site has a provider, a sender and a credential that the provider needs.
func (s Site) GateMailReady() bool {
	switch s.GateProvider {
	case "smtp":
		return s.GateFrom != "" && s.GateSMTPHost != ""
	case "postmark":
		return s.GateFrom != "" && s.GateSecret != nil
	}
	return false
}

func gatePort(p int) int {
	if p == 0 {
		return 587
	}
	return p
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// WebRoot is the folder Caddy or the app serves: StaticRoot, or its public folder.
func (s Site) WebRoot() string {
	if s.PublicDir == "" {
		return s.StaticRoot
	}
	return s.StaticRoot + "/" + s.PublicDir
}

// HasUpstream is true for kinds Caddy reaches over TCP (proxy, node, frankenphp): the ones whose upstream
// can be dialed and shown as up or down. Static and php sites have none.
func (s Site) HasUpstream() bool {
	return s.Kind == "" || s.Kind == "proxy" || s.Kind == "node" || s.Kind == "frankenphp"
}

// IsRuntime is true for kinds ServanaGo supervises as a unit under a site user (node, php, frankenphp, cgi), and
// for a static site that has its own user (Caddy proxies to a unit that serves the folder as that user).
func (s Site) IsRuntime() bool {
	return s.Kind == "node" || s.Kind == "php" || s.Kind == "frankenphp" || s.Kind == "cgi" || s.Kind == "static" && s.SiteUser != ""
}

// Record families: one DNS row per site (and one for the UI host) per family.
const (
	FamilyA    = "A"
	FamilyAAAA = "AAAA"
)

type DNSRecord struct {
	Hostname   string // the name the record is for; empty on the UI host's rows
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

const siteCols = "id, slug, kind, scheme, COALESCE(upstream_host,''), COALESCE(upstream_port,0), COALESCE(static_root,''), " +
	"start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, " +
	"COALESCE(record_ip,''), COALESCE(record_ip6,''), allowlist, COALESCE(basic_user,''), COALESCE(basic_hash,''), stream, max_body, gate_mode, " +
	"gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at"

func scanSite(r interface{ Scan(...any) error }) (Site, error) {
	var x Site
	err := r.Scan(&x.ID, &x.Slug, &x.Kind, &x.Scheme, &x.UpstreamHost, &x.UpstreamPort, &x.StaticRoot, &x.StartCommand,
		&x.InstallCommand, &x.BuildCommand, &x.FPMVersion, &x.TLSSkipVerify, &x.Enabled, &x.RecordIP, &x.RecordIP6,
		&x.Allowlist, &x.BasicUser, &x.BasicHash, &x.Stream, &x.MaxBody, &x.GateMode,
		&x.GateProvider, &x.GateFrom, &x.GateSMTPHost, &x.GateSMTPPort, &x.GateSMTPUser, &x.GateSecret, &x.ExtraRoutes, &x.PHPExtensions, &x.PHPHealthPath, &x.SiteUser, &x.PublicDir, &x.Notes, &x.UpdatedAt)
	return x, err
}

// CreateSite inserts the site with a slug derived from its first (primary) hostname.
func (s *Store) CreateSite(ctx context.Context, r Site) (Site, error) {
	if len(r.Hostnames) == 0 {
		return Site{}, fmt.Errorf("create site: at least one hostname is required")
	}
	var id int64
	err := s.Tx(ctx, func(tx *Store) error { // a taken hostname must not leave the site row behind
		slug, err := tx.newSlug(ctx, r.Hostnames[0])
		if err != nil {
			return err
		}
		if r.Kind == "" {
			r.Kind = "proxy"
		}
		if r.Scheme == "" && r.Kind != "proxy" { // meaningless outside proxy; the column is NOT NULL
			r.Scheme = "http"
		}
		res, err := tx.q.ExecContext(ctx, `INSERT INTO sites (slug, kind, scheme, upstream_host, upstream_port, static_root,
			start_command, install_command, build_command, fpm_version, tls_skip_verify, enabled, record_ip, record_ip6, allowlist, basic_user, basic_hash, stream, max_body, gate_mode, gate_provider, gate_from, gate_smtp_host, gate_smtp_port, gate_smtp_user, gate_secret, extra_routes, php_extensions, php_health_path, site_user, public_dir, notes, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, r.Kind, r.Scheme, nullStr(r.UpstreamHost), nullInt(r.UpstreamPort), nullStr(r.StaticRoot),
			r.StartCommand, r.InstallCommand, r.BuildCommand, r.FPMVersion, r.TLSSkipVerify, r.Enabled,
			nullStr(r.RecordIP), nullStr(r.RecordIP6), r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode,
			r.GateProvider, r.GateFrom, r.GateSMTPHost, gatePort(r.GateSMTPPort), r.GateSMTPUser, r.GateSecret, r.ExtraRoutes, r.PHPExtensions, r.PHPHealthPath, r.SiteUser, r.PublicDir, r.Notes, nowUTC())
		if err != nil {
			return fmt.Errorf("create site %s: %w", r.Hostnames[0], err)
		}
		id, _ = res.LastInsertId()
		if err := tx.setHostnames(ctx, id, r.Hostnames); err != nil {
			return err
		}
		return tx.setSnippets(ctx, id, r.Snippets)
	})
	if err != nil {
		return Site{}, err
	}
	return s.GetSite(ctx, id)
}

func (s *Store) GetSite(ctx context.Context, id int64) (Site, error) {
	r, err := scanSite(s.q.QueryRowContext(ctx, "SELECT "+siteCols+" FROM sites WHERE id=?", id))
	if err != nil {
		return Site{}, fmt.Errorf("get site %d: %w", id, err)
	}
	hs, err := s.hostnames(ctx)
	if err != nil {
		return Site{}, err
	}
	r.Hostnames = hs[id]
	sn, err := s.siteSnippets(ctx)
	if err != nil {
		return Site{}, err
	}
	r.Snippets = sn[id]
	return r, nil
}

// ListSites returns all sites ordered by primary hostname.
func (s *Store) ListSites(ctx context.Context) ([]Site, error) {
	hs, err := s.hostnames(ctx)
	if err != nil {
		return nil, err
	}
	sn, err := s.siteSnippets(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.QueryContext(ctx, "SELECT "+siteCols+` FROM sites
		ORDER BY (SELECT hostname FROM site_hostnames WHERE site_id=sites.id AND is_primary=1)`)
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
		r.Hostnames = hs[r.ID]
		r.Snippets = sn[r.ID]
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateSite saves every field except the slug, which never changes, and replaces the hostnames.
func (s *Store) UpdateSite(ctx context.Context, r Site) error {
	return s.Tx(ctx, func(tx *Store) error {
		_, err := tx.q.ExecContext(ctx, `UPDATE sites SET kind=?, scheme=?, upstream_host=?, upstream_port=?, static_root=?,
			start_command=?, install_command=?, build_command=?, fpm_version=?, tls_skip_verify=?, enabled=?, record_ip=?, record_ip6=?, allowlist=?, basic_user=?, basic_hash=?, stream=?, max_body=?, gate_mode=?, gate_provider=?, gate_from=?, gate_smtp_host=?, gate_smtp_port=?, gate_smtp_user=?, gate_secret=?, extra_routes=?, php_extensions=?, php_health_path=?, site_user=?, public_dir=?, notes=?, updated_at=? WHERE id=?`,
			r.Kind, r.Scheme, nullStr(r.UpstreamHost), nullInt(r.UpstreamPort), nullStr(r.StaticRoot),
			r.StartCommand, r.InstallCommand, r.BuildCommand, r.FPMVersion, r.TLSSkipVerify, r.Enabled,
			nullStr(r.RecordIP), nullStr(r.RecordIP6), r.Allowlist, nullStr(r.BasicUser), nullStr(r.BasicHash), r.Stream, r.MaxBody, r.GateMode,
			r.GateProvider, r.GateFrom, r.GateSMTPHost, gatePort(r.GateSMTPPort), r.GateSMTPUser, r.GateSecret, r.ExtraRoutes, r.PHPExtensions, r.PHPHealthPath, r.SiteUser, r.PublicDir, r.Notes, nowUTC(), r.ID)
		if err != nil {
			return fmt.Errorf("update site %d: %w", r.ID, err)
		}
		if err := tx.setHostnames(ctx, r.ID, r.Hostnames); err != nil {
			return err
		}
		return tx.setSnippets(ctx, r.ID, r.Snippets)
	})
}

// hostnames returns every site's hostnames keyed by site id, primary first.
func (s *Store) hostnames(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT site_id, hostname FROM site_hostnames ORDER BY site_id, is_primary DESC, hostname`)
	if err != nil {
		return nil, fmt.Errorf("list hostnames: %w", err)
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[id] = append(out[id], h)
	}
	return out, rows.Err()
}

// setHostnames replaces a site's hostnames; hs[0] becomes the primary. A hostname already used by another site fails.
func (s *Store) setHostnames(ctx context.Context, siteID int64, hs []string) error {
	if len(hs) == 0 {
		return fmt.Errorf("site %d: at least one hostname is required", siteID)
	}
	if _, err := s.q.ExecContext(ctx, `DELETE FROM site_hostnames WHERE site_id=?`, siteID); err != nil {
		return fmt.Errorf("clear hostnames of site %d: %w", siteID, err)
	}
	for i, h := range hs {
		if _, err := s.q.ExecContext(ctx, `INSERT INTO site_hostnames (site_id, hostname, is_primary) VALUES (?,?,?)`, siteID, h, i == 0); err != nil {
			return fmt.Errorf("hostname %s: %w", h, err)
		}
	}
	return nil
}

// ResolveDomain returns the domain whose name is the longest suffix of host (or host itself). ok=false means
// the hostname has no domain: no Cloudflare zone, no DNS sync, per-host certificates.
func ResolveDomain(domains []Domain, host string) (Domain, bool) {
	var best Domain
	found := false
	for _, d := range domains {
		if (host == d.Name || strings.HasSuffix(host, "."+d.Name)) && (!found || len(d.Name) > len(best.Name)) {
			best, found = d, true
		}
	}
	return best, found
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

// GetDNS returns the hostname's record of one family (FamilyA or FamilyAAAA).
func (s *Store) GetDNS(ctx context.Context, hostname, family string) (DNSRecord, error) {
	d := DNSRecord{Family: familyOf(family)}
	err := s.q.QueryRowContext(ctx, "SELECT "+dnsCols+" FROM dns_records WHERE hostname=? AND family=?", hostname, d.Family).
		Scan(&d.Hostname, &d.SiteID, &d.Family, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get %s record for %s: %w", d.Family, hostname, err)
	}
	return d, nil
}

func (s *Store) UpsertDNS(ctx context.Context, d DNSRecord) error {
	d.Family = familyOf(d.Family)
	_, err := s.q.ExecContext(ctx, `INSERT INTO dns_records (hostname, site_id, family, cf_record_id, content, owned, state, error, synced_at)
		VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(hostname, family) DO UPDATE SET site_id=excluded.site_id, cf_record_id=excluded.cf_record_id,
		content=excluded.content, owned=excluded.owned, state=excluded.state, error=excluded.error, synced_at=excluded.synced_at`,
		d.Hostname, d.SiteID, d.Family, nullStr(d.CFRecordID), nullStr(d.Content), d.Owned, d.State, nullStr(d.Error), nullStr(d.SyncedAt))
	if err != nil {
		return fmt.Errorf("upsert %s record for %s: %w", d.Family, d.Hostname, err)
	}
	return nil
}

const dnsCols = "hostname, site_id, family, COALESCE(cf_record_id,''), COALESCE(content,''), owned, state, COALESCE(error,''), COALESCE(synced_at,'')"

func scanDNSRows(rows *sql.Rows) ([]DNSRecord, error) {
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var d DNSRecord
		if err := rows.Scan(&d.Hostname, &d.SiteID, &d.Family, &d.CFRecordID, &d.Content, &d.Owned, &d.State, &d.Error, &d.SyncedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListDNS returns every record, ordered by site, hostname, then family (A before AAAA).
func (s *Store) ListDNS(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+dnsCols+" FROM dns_records ORDER BY site_id, hostname, family")
	if err != nil {
		return nil, err
	}
	return scanDNSRows(rows)
}

// ListSiteDNS returns one site's records, ordered by hostname then family.
func (s *Store) ListSiteDNS(ctx context.Context, siteID int64) ([]DNSRecord, error) {
	rows, err := s.q.QueryContext(ctx, "SELECT "+dnsCols+" FROM dns_records WHERE site_id=? ORDER BY hostname, family", siteID)
	if err != nil {
		return nil, err
	}
	return scanDNSRows(rows)
}

// DeleteDNS removes every record row of the site, whatever the hostname or family.
func (s *Store) DeleteDNS(ctx context.Context, siteID int64) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE site_id=?", siteID); err != nil {
		return fmt.Errorf("delete dns records for site %d: %w", siteID, err)
	}
	return nil
}

// DeleteDNSRecord removes one hostname's row of one family, for example the AAAA row when its IPv6 address is cleared.
func (s *Store) DeleteDNSRecord(ctx context.Context, hostname, family string) error {
	if _, err := s.q.ExecContext(ctx, "DELETE FROM dns_records WHERE hostname=? AND family=?", hostname, familyOf(family)); err != nil {
		return fmt.Errorf("delete %s record for %s: %w", familyOf(family), hostname, err)
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
