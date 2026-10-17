package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

type siteRow struct {
	store.Site
	Host  string
	DNS   []store.DNSRecord // the site's A and AAAA rows that exist, A first
	DNSOn bool              // Cloudflare is configured; otherwise the DNS column and actions are hidden
	// Probed is false for disabled routes: nothing is served, so nothing is checked.
	Probed   bool
	Upstream string // up | down
	Cert     probe.CertStatus
	CertSoon bool   // issued but inside renewWindow: shown amber
	CertWait string // how long a pending certificate may take, from the propagation settings
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

func (s *Server) siteRows(r *http.Request) ([]siteRow, error) {
	rs, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
	return s.buildRows(r, rs)
}

// buildRows adds DNS state and live probes (upstream, certificate) to the given sites.
func (s *Server) buildRows(r *http.Request, rs []store.Site) ([]siteRow, error) {
	dns, err := s.deps.Store.ListDNS(r.Context())
	if err != nil {
		return nil, err
	}
	bySite := map[int64][]store.DNSRecord{} // ListDNS orders A before AAAA
	for _, d := range dns {
		bySite[d.SiteID] = append(bySite[d.SiteID], d)
	}
	rows := make([]siteRow, len(rs))
	for i, x := range rs {
		rows[i] = siteRow{Site: x, Host: x.Hostnames[0], DNS: bySite[x.ID], DNSOn: s.dnsOn()}
		rows[i].Probed = x.Enabled && s.deps.Probe != nil
	}
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
	return rows, nil
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
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

// renewWindow is when an issued certificate shows amber: Caddy renews about 30 days before expiry,
// so a cert this close to its end means renewal is overdue or failing.
const renewWindow = 21 * 24 * time.Hour

func certExpiringSoon(cs probe.CertStatus, now time.Time) bool {
	return cs.State == probe.StateIssued && cs.NotAfter.Sub(now) < renewWindow
}
