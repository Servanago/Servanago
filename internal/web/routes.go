package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$`)

// parseRoute validates the route fields shared by create and edit.
func parseRoute(v url.Values) (store.Route, error) {
	var r store.Route
	var err error
	if r.DomainID, err = strconv.ParseInt(v.Get("domain_id"), 10, 64); err != nil {
		return r, errors.New("choose a domain")
	}
	r.Subdomain = strings.TrimSpace(v.Get("subdomain"))
	if err := config.ValidateLabel(r.Subdomain); err != nil {
		return r, fmt.Errorf("subdomain: %w", err)
	}
	if r.Scheme = v.Get("scheme"); r.Scheme != "http" && r.Scheme != "https" {
		return r, fmt.Errorf("scheme %q must be http or https", r.Scheme)
	}
	r.UpstreamHost = strings.TrimSpace(v.Get("upstream_host"))
	if _, ipErr := netip.ParseAddr(r.UpstreamHost); ipErr != nil && !hostnameRE.MatchString(r.UpstreamHost) {
		return r, fmt.Errorf("upstream host %q must be an IP address or a hostname", r.UpstreamHost)
	}
	if r.UpstreamPort, err = strconv.Atoi(strings.TrimSpace(v.Get("upstream_port"))); err != nil || r.UpstreamPort < 1 || r.UpstreamPort > 65535 {
		return r, fmt.Errorf("port %q must be 1-65535", v.Get("upstream_port"))
	}
	if r.RecordIP = strings.TrimSpace(v.Get("record_ip")); r.RecordIP != "" {
		if _, err := config.ValidateIP(r.RecordIP); err != nil {
			return r, fmt.Errorf("record IP: %w", err)
		}
	}
	if r.RecordIP6 = strings.TrimSpace(v.Get("record_ip6")); r.RecordIP6 != "" {
		if _, err := config.ValidateIP6(r.RecordIP6); err != nil {
			return r, fmt.Errorf("record IPv6: %w", err)
		}
	}
	r.TLSSkipVerify = v.Get("tls_skip_verify") != ""
	r.Enabled = v.Get("enabled") != ""
	return r, nil
}

type routeRow struct {
	store.Route
	Host  string
	DNS   []store.DNSRecord // the route's A and AAAA rows that exist, A first
	DNSOn bool              // Cloudflare is configured; otherwise the DNS column and actions are hidden
	// Probed is false for disabled routes: nothing is served, so nothing is checked.
	Probed   bool
	Upstream string // up | down
	Cert     probe.CertStatus
	CertSoon bool   // issued but inside renewWindow: shown amber
	CertWait string // how long a pending certificate may take, from the propagation settings
}

// HasDNS is true once at least one of the route's records has been synced or attempted.
func (r routeRow) HasDNS() bool { return len(r.DNS) > 0 }

// DNSState is the worst state across the route's records (error, conflict, pending, synced); "" when none exist.
func (r routeRow) DNSState() string { return worstState(r.DNS) }

// OwnsRecord is true when ServanaGo created at least one of this route's records, the only kind it may delete.
func (r routeRow) OwnsRecord() bool { return len(ownedRecords(r.DNS)) > 0 }

// OwnedSummary lists the records the delete dialog offers to remove, such as "A 10.0.0.1, AAAA 2001:db8::1".
func (r routeRow) OwnedSummary() string { return recordSummary(ownedRecords(r.DNS)) }

func (s *Server) routeRows(r *http.Request) ([]routeRow, error) {
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, d := range ds {
		names[d.ID] = d.Name
	}
	rs, err := s.deps.Store.ListRoutes(r.Context())
	if err != nil {
		return nil, err
	}
	dns, err := s.deps.Store.ListDNS(r.Context())
	if err != nil {
		return nil, err
	}
	byRoute := map[int64][]store.DNSRecord{} // ListDNS orders A before AAAA
	for _, d := range dns {
		byRoute[d.RouteID] = append(byRoute[d.RouteID], d)
	}
	rows := make([]routeRow, len(rs))
	for i, x := range rs {
		rows[i] = routeRow{Route: x, Host: x.Subdomain + "." + names[x.DomainID], DNS: byRoute[x.ID], DNSOn: s.dnsOn()}
		rows[i].Probed = x.Enabled && s.deps.Probe != nil
	}
	// Probes wait on the network, so run them side by side; each goroutine writes only its own row.
	probe.Parallel(len(rows), func(i int) {
		row := &rows[i]
		if !row.Probed {
			return
		}
		u, known := s.deps.Probe.Upstream(row.Route)
		if !known {
			ctx, cancel := detached(r)
			u = s.deps.Probe.Check(ctx, row.Route)
			cancel()
		}
		row.Upstream = map[bool]string{true: "up", false: "down"}[u.Up]
		row.Cert = s.deps.Probe.Cert(r.Context(), row.Host)
		row.CertSoon = certExpiringSoon(row.Cert, time.Now())
		row.CertWait = certWait(s.deps.Cfg.PropagationDelay, s.deps.Cfg.PropagationTimeout)
	})
	return rows, nil
}

type routeForm struct {
	Route         store.Route
	Edit          bool
	Domains       []store.Domain
	DeleteConfirm string
	DNSOn         bool   // Cloudflare is configured; otherwise the DNS record fields are hidden
	GateACL       string // textarea content for an existing ACL
	MailOK        bool   // email delivery configured; the gate section is shown only then
}

// recordWord names records by family: "A record", "AAAA record" or "A and AAAA records".
func recordWord(families []string) string {
	if len(families) > 1 {
		return strings.Join(families, " and ") + " records"
	}
	return families[0] + " record"
}

// deleteConfirm tells the user exactly what deleting the route does to its DNS records.
func deleteConfirm(t dnsTarget) string {
	var owned, adopted []string
	for _, row := range t.rows {
		switch {
		case row.CFRecordID == "":
		case row.Owned:
			owned = append(owned, row.Family)
		default:
			adopted = append(adopted, row.Family)
		}
	}
	msg := "Delete this route?"
	if len(owned) > 0 {
		msg += " This also deletes the " + recordWord(owned) + " " + t.name + " in Cloudflare."
	}
	if len(adopted) > 0 {
		verbs := "was adopted and is"
		if len(adopted) > 1 {
			verbs = "were adopted and are"
		}
		msg += " The existing " + recordWord(adopted) + " " + t.name + " " + verbs + " left in place."
	}
	return msg
}

func (s *Server) routeFormPage(w http.ResponseWriter, r *http.Request, rt store.Route, edit bool) {
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	title := "New route"
	if edit {
		title = "Edit route"
	}
	confirm := ""
	if edit {
		t, _ := dnsTargetOf(r, s.deps.Store, rt)
		confirm = deleteConfirm(t)
	}
	form := routeForm{Route: rt, Edit: edit, Domains: ds, DeleteConfirm: confirm, DNSOn: s.dnsOn(),
		MailOK: s.deps.Cfg.SMTPHost != "" && s.deps.Cfg.MailFrom != "" && s.deps.Cfg.SecretKey != ""}
	if edit {
		if gs, err := s.deps.Store.Grants(r.Context(), rt.ID); err == nil {
			form.GateACL = gateACLText(gs)
		}
	}
	s.render(w, "route", http.StatusOK, page{Title: title, Data: form})
}

// newRoutePage supports prefill via ?sub=&host=&port=.
func (s *Server) newRoutePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port, _ := strconv.Atoi(q.Get("port"))
	s.routeFormPage(w, r, store.Route{Scheme: "http", Enabled: true, Subdomain: q.Get("sub"), UpstreamHost: q.Get("host"), UpstreamPort: port}, false)
}

func (s *Server) editRoutePage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rt, err := s.deps.Store.GetRoute(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.routeFormPage(w, r, rt, true)
}

// checkRoute enforces domain existence and (domain, subdomain) uniqueness inside the apply transaction.
func (s *Server) checkRoute(r *http.Request, tx *store.Store, rt store.Route) error {
	d, err := tx.GetDomain(r.Context(), rt.DomainID)
	if err != nil {
		return errors.New("unknown domain")
	}
	if host := rt.Subdomain + "." + d.Name; host == s.deps.Cfg.Host {
		return fmt.Errorf("%s is the ServanaGo UI host; choose another subdomain", host)
	}
	all, err := tx.ListRoutes(r.Context())
	if err != nil {
		return err
	}
	for _, x := range all {
		if x.DomainID == rt.DomainID && x.Subdomain == rt.Subdomain && x.ID != rt.ID {
			return userError{http.StatusConflict, fmt.Sprintf("Subdomain %q already exists on that domain.", rt.Subdomain)}
		}
	}
	return nil
}

func (s *Server) createRoute(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rt, err := parseRoute(r.PostForm)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := applyControls(&rt, r.PostForm); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	grants, err := s.parseGate(rt, r.PostForm)
	if err != nil {
		failErr(w, err)
		return
	}
	var created store.Route
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if err := s.checkRoute(r, tx, rt); err != nil {
			return err
		}
		var err error
		created, err = tx.CreateRoute(r.Context(), rt)
		if err != nil {
			return err
		}
		return tx.ReplaceGrants(r.Context(), created.ID, grants)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.reconcile(r, created.ID)
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad route id")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	in, err := parseRoute(r.PostForm)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	grants, err := s.parseGate(in, r.PostForm)
	if err != nil {
		failErr(w, err)
		return
	}
	var old dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetRoute(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "route not found"}
		}
		old, _ = dnsTargetOf(r, tx, cur)
		// Overlay only the fields this form owns.
		cur.DomainID, cur.Subdomain, cur.Scheme = in.DomainID, in.Subdomain, in.Scheme
		cur.UpstreamHost, cur.UpstreamPort = in.UpstreamHost, in.UpstreamPort
		cur.TLSSkipVerify, cur.Enabled, cur.RecordIP, cur.RecordIP6 = in.TLSSkipVerify, in.Enabled, in.RecordIP, in.RecordIP6
		cur.GateMode = in.GateMode
		if err := applyControls(&cur, r.PostForm); err != nil {
			return err
		}
		if err := s.checkRoute(r, tx, cur); err != nil {
			return err
		}
		if err := tx.UpdateRoute(r.Context(), cur); err != nil {
			return err
		}
		return tx.ReplaceGrants(r.Context(), cur.ID, grants)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	// A rename or domain change moves the record: drop the old one (if owned), then sync the new name.
	if cur, err := s.deps.Store.GetRoute(r.Context(), id); err == nil {
		if now, err := dnsTargetOf(r, s.deps.Store, cur); err == nil && now.name != old.name {
			s.removeRecord(r, old)
			if err := s.deps.Store.DeleteDNS(r.Context(), id); err != nil {
				slog.Error("clear dns row", "route", id, "error", err)
			}
		}
	}
	s.reconcile(r, id)
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad route id")
		return
	}
	var target dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if cur, err := tx.GetRoute(r.Context(), id); err == nil {
			target, _ = dnsTargetOf(r, tx, cur)
		}
		return tx.DeleteRoute(r.Context(), id)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	if r.FormValue("delete_dns") != "" { // the A record is kept unless the user asked; Remove skips adopted records
		s.removeRecord(r, target)
	}
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

// detached outlives the request: once the route change is committed, a closed tab must not strand the DNS record.
func detached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
}

// dnsTarget is what a route's A and AAAA records looked like before the route changed or went away.
type dnsTarget struct {
	name, zone string
	rows       []store.DNSRecord // the rows that exist, A before AAAA
}

func dnsTargetOf(r *http.Request, q *store.Store, rt store.Route) (dnsTarget, error) {
	d, err := q.GetDomain(r.Context(), rt.DomainID)
	if err != nil {
		return dnsTarget{}, err
	}
	t := dnsTarget{name: rt.Subdomain + "." + d.Name, zone: d.ZoneID}
	for _, fam := range []string{store.FamilyA, store.FamilyAAAA} {
		if row, err := q.GetDNS(r.Context(), rt.ID, fam); err == nil {
			t.rows = append(t.rows, row)
		}
	}
	return t, nil
}

func (s *Server) reconcile(r *http.Request, routeID int64) {
	if !s.dnsOn() {
		return
	}
	ctx, cancel := detached(r)
	defer cancel()
	if err := s.deps.DNS.Reconcile(ctx, routeID); err != nil {
		slog.Error("dns reconcile", "route", routeID, "error", err)
	}
}

// removeRecord deletes the route's A and AAAA records when ServanaGo owns them; failures become one-time notices.
func (s *Server) removeRecord(r *http.Request, t dnsTarget) {
	if !s.dnsOn() {
		return
	}
	ctx, cancel := detached(r)
	defer cancel()
	for _, row := range t.rows {
		if _, err := s.deps.DNS.Remove(ctx, t.zone, row); err != nil {
			slog.Error("dns remove", "record", t.name, "family", row.Family, "error", err)
			s.flash(fmt.Sprintf("The %s record %s could not be removed: %v", row.Family, t.name, err))
		}
	}
}

func (s *Server) resyncDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, s.deps.DNS.Reconcile)
}
func (s *Server) takeOverDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, s.deps.DNS.TakeOver)
}

func (s *Server) dnsAction(w http.ResponseWriter, r *http.Request, act func(context.Context, int64) error) {
	if !s.dnsOn() {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad route id")
		return
	}
	if err := act(r.Context(), id); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
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
