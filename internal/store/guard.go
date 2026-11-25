package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// SiteGuard is a site's protection settings (table site_guard). A site without a row has DefaultGuard.
type SiteGuard struct {
	BanOn         bool
	UAMode        string // "" | on | auto: under-attack challenge
	CHKind        string // pow | turnstile
	CHDifficulty  string // low | medium | high
	CHTTLMin      int
	UAAutoRPS     int // auto trigger: requests per second over the last 10 s; 0 = never
	UACooldownMin int
	QOn           bool
	QCapacity     int
	QActiveTTLs   int
	QMaxQueue     int
	Backends      string // proxy: extra "host:port" backends, one per line
}

// DefaultGuard is what a site without a site_guard row gets.
func DefaultGuard() SiteGuard {
	return SiteGuard{CHKind: "pow", CHDifficulty: "medium", CHTTLMin: 60, UACooldownMin: 10, QCapacity: 100, QActiveTTLs: 300, QMaxQueue: 5000}
}

// Layers is true when the site renders any guard layer of its own (ban, challenge, queue).
func (g SiteGuard) Layers() bool { return g.BanOn || g.UAMode != "" || g.QOn }

// SitePage is the content of a kind "page" site: a status page or a redirect.
type SitePage struct {
	Status   int
	Title    string
	Message  string
	HTML     string
	Target   string
	KeepPath bool
}

// IsRedirect is true for a 3xx status with a target.
func (p SitePage) IsRedirect() bool {
	switch p.Status {
	case 301, 302, 303, 307, 308:
		return p.Target != ""
	}
	return false
}

// DefaultPage is a 503 maintenance page.
func DefaultPage() SitePage { return SitePage{Status: 503, KeepPath: true} }

// X402Route is one paywalled path prefix of a site.
type X402Route struct {
	ID        int64
	Path      string
	Price     string // decimal USD
	Mode      string // all | bots
	GrantKind string // request | token
	TokenTTLs int
}

// Ban is one row of the bans table.
type Ban struct {
	Client    string
	SiteSlug  string
	Source    string // auto | manual
	Level     int
	Reason    string
	CreatedAt int64
	Until     int64
	CreatedBy string
}

// GuardSettings is the single guard_settings row.
type GuardSettings struct {
	BanCodes        string
	BanUnknownHost  bool
	BanThreshold    int
	BanWindowS      int
	BanStepsMin     string
	BanExempt       string
	LogDays         int
	RollupDays      int
	UAList          string
	X402Facilitator string
	X402Network     string
	X402PayTo       string
	X402APIKey      []byte // secretbox blob
}

// AlertDest is one alert destination; Target and Secret are secretbox blobs.
type AlertDest struct {
	ID          int64
	Name        string
	Kind        string
	Target      []byte
	Secret      []byte
	Events      string
	LastError   string
	LastErrorAt int64
	Enabled     bool
}

// loadProtection fills Guard, Page, X402 and AlertDests of the sites from their side tables.
func (s *Store) loadProtection(ctx context.Context, sites []*Site) error {
	if len(sites) == 0 {
		return nil
	}
	by := map[int64]*Site{}
	for _, x := range sites {
		g := DefaultGuard()
		x.Guard = &g
		x.Page = DefaultPage()
		x.X402 = nil
		x.AlertDests = nil
		by[x.ID] = x
	}
	rows, err := s.q.QueryContext(ctx, `SELECT site_id, ban_on, ua_mode, ch_kind, ch_difficulty, ch_ttl_min, ua_auto_rps, ua_cooldown_min,
		q_on, q_capacity, q_active_ttl_s, q_max_queue, backends FROM site_guard`)
	if err != nil {
		return fmt.Errorf("load site_guard: %w", err)
	}
	for rows.Next() {
		var id int64
		var g SiteGuard
		if err := rows.Scan(&id, &g.BanOn, &g.UAMode, &g.CHKind, &g.CHDifficulty, &g.CHTTLMin, &g.UAAutoRPS, &g.UACooldownMin,
			&g.QOn, &g.QCapacity, &g.QActiveTTLs, &g.QMaxQueue, &g.Backends); err != nil {
			_ = rows.Close()
			return err
		}
		if x := by[id]; x != nil {
			*x.Guard = g
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if rows, err = s.q.QueryContext(ctx, `SELECT site_id, status, title, message, html, target, keep_path FROM site_page`); err != nil {
		return fmt.Errorf("load site_page: %w", err)
	}
	for rows.Next() {
		var id int64
		var p SitePage
		if err := rows.Scan(&id, &p.Status, &p.Title, &p.Message, &p.HTML, &p.Target, &p.KeepPath); err != nil {
			_ = rows.Close()
			return err
		}
		if x := by[id]; x != nil {
			x.Page = p
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if rows, err = s.q.QueryContext(ctx, `SELECT id, site_id, path, price, mode, grant_kind, token_ttl_s FROM site_x402 ORDER BY site_id, path`); err != nil {
		return fmt.Errorf("load site_x402: %w", err)
	}
	for rows.Next() {
		var id int64
		var x X402Route
		if err := rows.Scan(&x.ID, &id, &x.Path, &x.Price, &x.Mode, &x.GrantKind, &x.TokenTTLs); err != nil {
			_ = rows.Close()
			return err
		}
		if st := by[id]; st != nil {
			st.X402 = append(st.X402, x)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if rows, err = s.q.QueryContext(ctx, `SELECT site_id, dest_id FROM site_alert_dests ORDER BY site_id, dest_id`); err != nil {
		return fmt.Errorf("load site_alert_dests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sid, did int64
		if err := rows.Scan(&sid, &did); err != nil {
			return err
		}
		if st := by[sid]; st != nil {
			st.AlertDests = append(st.AlertDests, did)
		}
	}
	return rows.Err()
}

// saveProtection replaces the site's protection rows from r.Guard, r.Page, r.X402 and r.AlertDests. It does nothing when
// r.Guard is nil: a caller that never loaded the protection set leaves it untouched.
func (s *Store) saveProtection(ctx context.Context, siteID int64, r Site) error {
	if r.Guard == nil {
		return nil
	}
	g := *r.Guard
	if _, err := s.q.ExecContext(ctx, `INSERT INTO site_guard (site_id, ban_on, ua_mode, ch_kind, ch_difficulty, ch_ttl_min, ua_auto_rps, ua_cooldown_min,
		q_on, q_capacity, q_active_ttl_s, q_max_queue, backends) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(site_id) DO UPDATE SET ban_on=excluded.ban_on, ua_mode=excluded.ua_mode, ch_kind=excluded.ch_kind, ch_difficulty=excluded.ch_difficulty,
		ch_ttl_min=excluded.ch_ttl_min, ua_auto_rps=excluded.ua_auto_rps, ua_cooldown_min=excluded.ua_cooldown_min, q_on=excluded.q_on,
		q_capacity=excluded.q_capacity, q_active_ttl_s=excluded.q_active_ttl_s, q_max_queue=excluded.q_max_queue, backends=excluded.backends`,
		siteID, g.BanOn, g.UAMode, g.CHKind, g.CHDifficulty, g.CHTTLMin, g.UAAutoRPS, g.UACooldownMin,
		g.QOn, g.QCapacity, g.QActiveTTLs, g.QMaxQueue, g.Backends); err != nil {
		return fmt.Errorf("save site_guard %d: %w", siteID, err)
	}
	if r.Kind == "page" {
		p := r.Page
		if _, err := s.q.ExecContext(ctx, `INSERT INTO site_page (site_id, status, title, message, html, target, keep_path) VALUES (?,?,?,?,?,?,?)
			ON CONFLICT(site_id) DO UPDATE SET status=excluded.status, title=excluded.title, message=excluded.message, html=excluded.html,
			target=excluded.target, keep_path=excluded.keep_path`, siteID, p.Status, p.Title, p.Message, p.HTML, p.Target, p.KeepPath); err != nil {
			return fmt.Errorf("save site_page %d: %w", siteID, err)
		}
	} else if _, err := s.q.ExecContext(ctx, `DELETE FROM site_page WHERE site_id=?`, siteID); err != nil {
		return err
	}
	if _, err := s.q.ExecContext(ctx, `DELETE FROM site_x402 WHERE site_id=?`, siteID); err != nil {
		return err
	}
	for _, x := range r.X402 {
		if _, err := s.q.ExecContext(ctx, `INSERT INTO site_x402 (site_id, path, price, mode, grant_kind, token_ttl_s) VALUES (?,?,?,?,?,?)`,
			siteID, x.Path, x.Price, x.Mode, x.GrantKind, x.TokenTTLs); err != nil {
			return fmt.Errorf("save x402 route %s: %w", x.Path, err)
		}
	}
	if _, err := s.q.ExecContext(ctx, `DELETE FROM site_alert_dests WHERE site_id=?`, siteID); err != nil {
		return err
	}
	for _, d := range r.AlertDests {
		if _, err := s.q.ExecContext(ctx, `INSERT OR IGNORE INTO site_alert_dests (site_id, dest_id) VALUES (?,?)`, siteID, d); err != nil {
			return fmt.Errorf("save site alert destination: %w", err)
		}
	}
	return nil
}

func (s *Store) GetGuardSettings(ctx context.Context) (GuardSettings, error) {
	var g GuardSettings
	err := s.q.QueryRowContext(ctx, `SELECT ban_codes, ban_unknown_host, ban_threshold, ban_window_s, ban_steps_min, ban_exempt, log_days, rollup_days,
		ua_list, x402_facilitator, x402_network, x402_pay_to, x402_api_key_sealed FROM guard_settings WHERE id=1`).
		Scan(&g.BanCodes, &g.BanUnknownHost, &g.BanThreshold, &g.BanWindowS, &g.BanStepsMin, &g.BanExempt, &g.LogDays, &g.RollupDays,
			&g.UAList, &g.X402Facilitator, &g.X402Network, &g.X402PayTo, &g.X402APIKey)
	if err != nil {
		return g, fmt.Errorf("read guard settings: %w", err)
	}
	return g, nil
}

func (s *Store) SaveGuardSettings(ctx context.Context, g GuardSettings) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE guard_settings SET ban_codes=?, ban_unknown_host=?, ban_threshold=?, ban_window_s=?, ban_steps_min=?, ban_exempt=?,
		log_days=?, rollup_days=?, ua_list=?, x402_facilitator=?, x402_network=?, x402_pay_to=?, x402_api_key_sealed=? WHERE id=1`,
		g.BanCodes, g.BanUnknownHost, g.BanThreshold, g.BanWindowS, g.BanStepsMin, g.BanExempt, g.LogDays, g.RollupDays,
		g.UAList, g.X402Facilitator, g.X402Network, g.X402PayTo, g.X402APIKey); err != nil {
		return fmt.Errorf("save guard settings: %w", err)
	}
	return nil
}

const banCols = "client, site_slug, source, level, reason, created_at, until, created_by"

func scanBans(rows *sql.Rows) ([]Ban, error) {
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		if err := rows.Scan(&b.Client, &b.SiteSlug, &b.Source, &b.Level, &b.Reason, &b.CreatedAt, &b.Until, &b.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListBans returns the bans whose until is at or after since, newest first (since 0 = every row, expired ones too).
func (s *Store) ListBans(ctx context.Context, since int64) ([]Ban, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+banCols+` FROM bans WHERE until >= ? ORDER BY created_at DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("list bans: %w", err)
	}
	return scanBans(rows)
}

// GetBan returns one client's row; sql.ErrNoRows wrapped when absent.
func (s *Store) GetBan(ctx context.Context, client string) (Ban, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+banCols+` FROM bans WHERE client=?`, client)
	if err != nil {
		return Ban{}, err
	}
	bs, err := scanBans(rows)
	if err != nil {
		return Ban{}, err
	}
	if len(bs) == 0 {
		return Ban{}, fmt.Errorf("get ban %s: %w", client, sql.ErrNoRows)
	}
	return bs[0], nil
}

func (s *Store) UpsertBan(ctx context.Context, b Ban) error {
	if _, err := s.q.ExecContext(ctx, `INSERT INTO bans (`+banCols+`) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(client) DO UPDATE SET site_slug=excluded.site_slug, source=excluded.source, level=excluded.level, reason=excluded.reason,
		created_at=excluded.created_at, until=excluded.until, created_by=excluded.created_by`,
		b.Client, b.SiteSlug, b.Source, b.Level, b.Reason, b.CreatedAt, b.Until, b.CreatedBy); err != nil {
		return fmt.Errorf("save ban %s: %w", b.Client, err)
	}
	return nil
}

func (s *Store) DeleteBan(ctx context.Context, client string) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM bans WHERE client=?`, client); err != nil {
		return fmt.Errorf("delete ban %s: %w", client, err)
	}
	return nil
}

// PruneBans removes rows that expired before the cutoff (they are kept 7 days so the next ban escalates).
func (s *Store) PruneBans(ctx context.Context, cutoff int64) error {
	_, err := s.q.ExecContext(ctx, `DELETE FROM bans WHERE until < ?`, cutoff)
	return err
}

const destCols = "id, name, kind, target_sealed, secret_sealed, events, last_error, last_error_at, enabled"

func scanDests(rows *sql.Rows) ([]AlertDest, error) {
	defer rows.Close()
	var out []AlertDest
	for rows.Next() {
		var d AlertDest
		if err := rows.Scan(&d.ID, &d.Name, &d.Kind, &d.Target, &d.Secret, &d.Events, &d.LastError, &d.LastErrorAt, &d.Enabled); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ListAlertDests(ctx context.Context) ([]AlertDest, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+destCols+` FROM alert_dests ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list alert destinations: %w", err)
	}
	return scanDests(rows)
}

func (s *Store) GetAlertDest(ctx context.Context, id int64) (AlertDest, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+destCols+` FROM alert_dests WHERE id=?`, id)
	if err != nil {
		return AlertDest{}, err
	}
	ds, err := scanDests(rows)
	if err != nil {
		return AlertDest{}, err
	}
	if len(ds) == 0 {
		return AlertDest{}, fmt.Errorf("get alert destination %d: %w", id, sql.ErrNoRows)
	}
	return ds[0], nil
}

func (s *Store) CreateAlertDest(ctx context.Context, d AlertDest) (AlertDest, error) {
	res, err := s.q.ExecContext(ctx, `INSERT INTO alert_dests (name, kind, target_sealed, secret_sealed, events, enabled) VALUES (?,?,?,?,?,?)`,
		d.Name, d.Kind, d.Target, d.Secret, d.Events, d.Enabled)
	if err != nil {
		return AlertDest{}, fmt.Errorf("create alert destination %s: %w", d.Name, err)
	}
	id, _ := res.LastInsertId()
	return s.GetAlertDest(ctx, id)
}

func (s *Store) SetAlertDestEnabled(ctx context.Context, id int64, on bool) error {
	_, err := s.q.ExecContext(ctx, `UPDATE alert_dests SET enabled=? WHERE id=?`, on, id)
	return err
}

// SetAlertDestError records the outcome of a send: "" clears the last error.
func (s *Store) SetAlertDestError(ctx context.Context, id int64, msg string, at int64) error {
	_, err := s.q.ExecContext(ctx, `UPDATE alert_dests SET last_error=?, last_error_at=? WHERE id=?`, msg, at, id)
	return err
}

func (s *Store) DeleteAlertDest(ctx context.Context, id int64) error {
	if _, err := s.q.ExecContext(ctx, `DELETE FROM alert_dests WHERE id=?`, id); err != nil {
		return fmt.Errorf("delete alert destination %d: %w", id, err)
	}
	return nil
}

// ErrNoRows reports whether err wraps sql.ErrNoRows.
func ErrNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// destinationsFor is the routing rule: a site with its own destination rows uses only those, any other site every enabled
// destination; either way the destination's events must include the event.
func RouteAlert(all []AlertDest, siteOnly []int64, event string) []AlertDest {
	only := map[int64]bool{}
	for _, id := range siteOnly {
		only[id] = true
	}
	var out []AlertDest
	for _, d := range all {
		if !d.Enabled || !strings.Contains(" "+d.Events+" ", " "+event+" ") {
			continue
		}
		if len(only) > 0 && !only[d.ID] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// SiteAlertDestIDs is the slug's alert destination override (empty = none).
func (s *Store) SiteAlertDestIDs(ctx context.Context, slug string) ([]int64, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT d.dest_id FROM site_alert_dests d JOIN sites ON sites.id = d.site_id WHERE sites.slug = ?`, slug)
	if err != nil {
		return nil, err
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
