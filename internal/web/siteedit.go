package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

type siteRow struct {
	store.Site
	Host  string
	DNS   []store.DNSRecord // the site's A and AAAA rows that exist, A first
	DNSOn bool              // Cloudflare is configured; otherwise the DNS column and actions are hidden
	// Virus scanning: ScanOn only gates the badge/button display; Scan is the newest run (any
	// state), ScanHits its hit count.
	ScanOn   bool
	Scan     store.ScanRun
	ScanHits int
	// Probed is false for disabled routes: nothing is served, so nothing is checked.
	Probed   bool
	Upstream string // up | down
	Cert     probe.CertStatus
	CertSoon bool   // issued but inside renewWindow: shown amber
	CertWait string // how long a pending certificate may take, from the propagation settings
	// Docker is the container a local proxy upstream points at; DockerErr is true when it could not be looked up.
	Docker    *helper.Container
	DockerErr bool
	// BackText is the newest backup run's when and result; "" when backups are off or not configured.
	BackText string
	BackOK   bool
	// UnitState is a runtime site's unit as the helper reports it (running | stopped | unknown; ""
	// for kinds without a unit). One helper call per runtime site per render, asked in parallel.
	UnitState string
}

// HasDNS is true once at least one of the site's records has been synced or attempted.
func (r siteRow) HasDNS() bool { return len(r.DNS) > 0 }

// DNSState is the worst state across the site's records (error, conflict, pending, synced); "" when none exist.
func (r siteRow) DNSState() string { return worstState(r.DNS) }

// OwnsRecord is true when ServanaGo created at least one of this site's records, the only kind it may delete.
func (r siteRow) OwnsRecord() bool { return len(ownedRecords(r.DNS)) > 0 }

// OwnedSummary lists the records the delete dialog offers to remove, such as "A 10.0.0.1, AAAA 2001:db8::1".
func (r siteRow) OwnedSummary() string { return recordSummary(ownedRecords(r.DNS)) }

// Aliases are the hostnames after the primary one.
func (r siteRow) Aliases() []string { return r.Hostnames[1:] }

// pill is one status pill of a site's header or row: Class = ok | warn | bad | info | dim.
type pill struct{ Class, Text string }

// StatusPills rolls the site's current facts into the header pills, in the order the header shows them.
func (r siteRow) StatusPills() []pill {
	var out []pill
	if !r.Enabled {
		out = append(out, pill{Class: "bad", Text: "disabled"})
	}
	if r.Probed {
		class := "ok"
		var text string
		switch r.Cert.State {
		case probe.StateIssued:
			if r.CertSoon {
				class = "warn"
			}
			text = r.Cert.Issuer + ", renews in " + fmt.Sprint(r.CertDays()) + " d"
		case probe.StatePending:
			class, text = "warn", "TLS pending"
		default:
			class, text = "bad", "TLS error"
		}
		out = append(out, pill{Class: class, Text: text})
	}
	if r.DNSOn && len(r.DNS) > 0 {
		st := r.DNSState()
		class := "ok"
		switch st {
		case "error":
			class = "bad"
		case "conflict", "pending":
			class = "warn"
		}
		out = append(out, pill{Class: class, Text: "DNS " + st})
	}
	if r.GateMode != "" {
		text := "Magic-link gate on"
		if r.GateMode == "acl" {
			text += ", allowlist"
		} else {
			text += ", any mail"
		}
		out = append(out, pill{Class: "info", Text: text})
	}
	if r.ScanOn && r.Scan.ID != 0 {
		switch {
		case r.Scan.State == "running":
			out = append(out, pill{Class: "info", Text: "scan running"})
		case r.ScanHits > 0:
			out = append(out, pill{Class: "bad", Text: fmt.Sprintf("%d scan hit%s", r.ScanHits, plural(r.ScanHits))})
		case r.Scan.FinishedAt != 0 && r.Scan.State == "ok":
			out = append(out, pill{Class: "ok", Text: "scan clean"})
		}
	}
	if r.BackText != "" {
		class := "ok"
		if !r.BackOK {
			class = "warn"
		}
		out = append(out, pill{Class: class, Text: "backup " + r.BackText})
	}
	return out
}

// CertDays is how many days the primary hostname's certificate still has (negative when expired).
func (r siteRow) CertDays() int { return int(time.Until(r.Cert.NotAfter).Hours() / 24) }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Running is true while the unit's active state reads active (or activating).
func (p unitPanel) Running() bool { return strings.HasPrefix(p.State, "active") }

// scanable is true when this site has a folder to walk (kinds without one are skipped).
func (r siteRow) Scanable() bool { return servedRootOf(r.Site) != "" }

func (s *Server) siteRows(r *http.Request) ([]siteRow, error) {
	rs, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
	return s.buildRows(r, rs)
}

// buildRows adds DNS state, live probes (upstream, certificate) and the newest scan to the given sites.
func (s *Server) buildRows(r *http.Request, rs []store.Site) ([]siteRow, error) {
	dns, err := s.deps.Store.ListDNS(r.Context())
	if err != nil {
		return nil, err
	}
	bySite := map[int64][]store.DNSRecord{} // ListDNS orders A before AAAA
	for _, d := range dns {
		bySite[d.SiteID] = append(bySite[d.SiteID], d)
	}
	st, serr := s.deps.Store.GetSettings(r.Context())
	runIDs := map[int64]store.ScanRun{} // newest run per site
	if serr == nil && st.ScanSocket != "" {
		if runs, err := s.deps.Store.ListScanRuns(r.Context(), 0, 500); err == nil {
			seen := map[int64]bool{}
			for _, run := range runs { // DESC: the first hit per site is its newest
				if !seen[run.SiteID] {
					seen[run.SiteID] = true
					runIDs[run.SiteID] = run
				}
			}
		}
	}
	rows := make([]siteRow, len(rs))
	for i, x := range rs {
		rows[i] = siteRow{Site: x, Host: x.Hostnames[0], DNS: bySite[x.ID], DNSOn: s.dnsOn(),
			ScanOn: st.ScanSocket != "", Scan: runIDs[x.ID]}
	}
	if set, err := s.deps.Store.GetBackupSettings(r.Context()); err == nil && set.Enabled {
		if last, _, err := s.deps.Store.LastRuns(r.Context()); err == nil {
			for i := range rows {
				if l, ok := last[rows[i].Slug]; ok {
					rows[i].BackText = when(l.Finished) + " · " + l.Status
					rows[i].BackOK = l.Status == "ok"
				}
			}
		}
	}
	var (
		hitIDs []int64
		hitBy  map[int64]int
	)
	for _, row := range rows {
		if row.Scan.ID != 0 {
			hitIDs = append(hitIDs, row.Scan.ID)
		}
	}
	if hitBy, err = s.deps.Store.CountRunsHits(r.Context(), hitIDs); err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].ScanHits = hitBy[rows[i].Scan.ID]
		rows[i].Probed = rows[i].Enabled && s.deps.Probe != nil
	}
	s.attachContainers(r.Context(), rows)
	// Probes wait on the network, so run them side by side; each goroutine writes only its own row.
	probe.Parallel(len(rows), func(i int) {
		row := &rows[i]
		if !row.Probed {
			return
		}
		if row.HasUpstream() { // static and php sites have no upstream to check
			u, known := s.deps.Probe.Upstream(row.Site)
			if !known {
				ctx, cancel := detached(r)
				u = s.deps.Probe.Check(ctx, row.Site)
				cancel()
			}
			row.Upstream = map[bool]string{true: "up", false: "down"}[u.Up]
		}
		row.Cert = s.deps.Probe.Cert(r.Context(), row.Host)
		row.CertSoon = certExpiringSoon(row.Cert, time.Now())
		row.CertWait = certWait(s.deps.Cfg.PropagationDelay, s.deps.Cfg.PropagationTimeout)
	})
	s.unitStates(r, rows)
	return rows, nil
}

// unitStates asks the helper for every runtime site's unit state in parallel. Failures read
// "unknown"; the list must render even when the helper is down.
func (s *Server) unitStates(r *http.Request, rows []siteRow) {
	var runtime []int
	for i := range rows {
		if rows[i].IsRuntime() {
			runtime = append(runtime, i)
		}
	}
	if len(runtime) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	hc := s.helperClient()
	probe.Parallel(len(runtime), func(j int) {
		row := &rows[runtime[j]]
		st, err := hc.Call(ctx, helper.ActionUnitStatus, helper.Spec{Slug: row.Slug})
		switch {
		case err != nil || st.Status == nil:
			row.UnitState = "unknown"
		case strings.HasPrefix(st.Status.ActiveState, "active"):
			row.UnitState = "running"
		default:
			row.UnitState = "stopped"
		}
	})
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	var target dnsTarget
	host := ""
	var deleted store.Site
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if cur, err := tx.GetSite(r.Context(), id); err == nil {
			target, _ = dnsTargetOf(r, tx, cur)
			host = cur.Hostnames[0]
			deleted = cur // runtime artifacts are torn down after the commit
		}
		return tx.DeleteSite(r.Context(), id)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "site.deleted", host)
	if deleted.IsRuntime() {
		s.runtimeRemove(r, deleted)
	}
	if r.FormValue("delete_dns") != "" { // the A record is kept unless the user asked; Remove skips adopted records
		s.removeRecord(r, target)
	}
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

// detached outlives the request: once the site change is committed, a closed tab must not strand the DNS record.
func detached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
}

// dnsTarget is the DNS rows of a site (every hostname, A before AAAA) with the zone each one lives in, kept so
// the records can still be deleted after the site row is gone.
type dnsTarget struct{ rows []targetRow }

type targetRow struct {
	store.DNSRecord
	zone string
}

func dnsTargetOf(r *http.Request, q *store.Store, rt store.Site) (dnsTarget, error) {
	ds, err := q.ListDomains(r.Context())
	if err != nil {
		return dnsTarget{}, err
	}
	all, err := q.ListSiteDNS(r.Context(), rt.ID)
	if err != nil {
		return dnsTarget{}, err
	}
	var t dnsTarget
	for _, row := range all {
		if d, ok := store.ResolveDomain(ds, row.Hostname); ok {
			t.rows = append(t.rows, targetRow{row, d.ZoneID})
		}
	}
	return t, nil
}

func (s *Server) reconcile(r *http.Request, siteID int64) {
	if !s.dnsOn() {
		return
	}
	ctx, cancel := detached(r)
	defer cancel()
	if err := s.deps.DNS.Reconcile(ctx, siteID); err != nil {
		slog.Error("dns reconcile", "site", siteID, "error", err)
	}
}

// removeRecord deletes the site's A and AAAA records when ServanaGo owns them; failures become one-time notices.
func (s *Server) removeRecord(r *http.Request, t dnsTarget) {
	if !s.dnsOn() {
		return
	}
	ctx, cancel := detached(r)
	defer cancel()
	for _, row := range t.rows {
		if _, err := s.deps.DNS.Remove(ctx, row.zone, row.DNSRecord); err != nil {
			slog.Error("dns remove", "record", row.Hostname, "family", row.Family, "error", err)
			s.flash(fmt.Sprintf("The %s record %s could not be removed: %v", row.Family, row.Hostname, err))
		}
	}
}

func (s *Server) resyncDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, "site.dns_resynced", s.deps.DNS.Reconcile)
}
func (s *Server) takeOverDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, "site.dns_taken_over", s.deps.DNS.TakeOver)
}

func (s *Server) dnsAction(w http.ResponseWriter, r *http.Request, action string, act func(context.Context, int64) error) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	if err := act(r.Context(), id); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if rt, err := s.deps.Store.GetSite(r.Context(), id); err == nil {
		s.audit(r, action, rt.Hostnames[0])
	}
	hxRedirect(w, backOf(r, "/"))
}

// renewWindow is when an issued certificate shows amber: Caddy renews about 30 days before expiry,
// so a cert this close to its end means renewal is overdue or failing.
const renewWindow = 21 * 24 * time.Hour

func certExpiringSoon(cs probe.CertStatus, now time.Time) bool {
	return cs.State == probe.StateIssued && cs.NotAfter.Sub(now) < renewWindow
}
