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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$`)

// siteAddr is the full form's address: a managed domain and one label below it. The hostname is their join.
type siteAddr struct {
	DomainID  int64
	Subdomain string
}

// addrOf splits a site's primary hostname back into the full form's domain and subdomain.
func addrOf(domains []store.Domain, rt store.Site) siteAddr {
	if len(rt.Hostnames) == 0 {
		return siteAddr{}
	}
	d, ok := store.ResolveDomain(domains, rt.Hostnames[0])
	if !ok {
		return siteAddr{Subdomain: rt.Hostnames[0]}
	}
	return siteAddr{DomainID: d.ID, Subdomain: strings.TrimSuffix(rt.Hostnames[0], "."+d.Name)}
}

// parseSite validates the site fields shared by create and edit. The hostname is set later from the address.
func parseSite(v url.Values) (store.Site, siteAddr, error) {
	var r store.Site
	var a siteAddr
	var err error
	if a.DomainID, err = strconv.ParseInt(v.Get("domain_id"), 10, 64); err != nil {
		return r, a, errors.New("choose a domain")
	}
	a.Subdomain = strings.TrimSpace(v.Get("subdomain"))
	if err := config.ValidateLabel(a.Subdomain); err != nil {
		return r, a, fmt.Errorf("subdomain: %w", err)
	}
	if r.Scheme = v.Get("scheme"); r.Scheme != "http" && r.Scheme != "https" {
		return r, a, fmt.Errorf("scheme %q must be http or https", r.Scheme)
	}
	r.UpstreamHost = strings.TrimSpace(v.Get("upstream_host"))
	if _, ipErr := netip.ParseAddr(r.UpstreamHost); ipErr != nil && !hostnameRE.MatchString(r.UpstreamHost) {
		return r, a, fmt.Errorf("upstream host %q must be an IP address or a hostname", r.UpstreamHost)
	}
	if r.UpstreamPort, err = strconv.Atoi(strings.TrimSpace(v.Get("upstream_port"))); err != nil || r.UpstreamPort < 1 || r.UpstreamPort > 65535 {
		return r, a, fmt.Errorf("port %q must be 1-65535", v.Get("upstream_port"))
	}
	if r.RecordIP = strings.TrimSpace(v.Get("record_ip")); r.RecordIP != "" {
		if _, err := config.ValidateIP(r.RecordIP); err != nil {
			return r, a, fmt.Errorf("record IP: %w", err)
		}
	}
	if r.RecordIP6 = strings.TrimSpace(v.Get("record_ip6")); r.RecordIP6 != "" {
		if _, err := config.ValidateIP6(r.RecordIP6); err != nil {
			return r, a, fmt.Errorf("record IPv6: %w", err)
		}
	}
	r.TLSSkipVerify = v.Get("tls_skip_verify") != ""
	r.Enabled = v.Get("enabled") != ""
	return r, a, nil
}

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

func (s *Server) siteRows(r *http.Request) ([]siteRow, error) {
	rs, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
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
		if row.Kind != "static" { // a static site has no upstream to check
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

type siteEditForm struct {
	Site          store.Site
	Addr          siteAddr // the form's domain and subdomain, split from the primary hostname
	Edit          bool
	Domains       []store.Domain
	DeleteConfirm string
	DNSOn         bool   // Cloudflare is configured; otherwise the DNS record fields are hidden
	GateACL       string // textarea content for an existing ACL
	MailOK        bool   // email delivery and the session key work; otherwise the gate section is shown disabled
}

// recordWord names records by family: "A record", "AAAA record" or "A and AAAA records".
func recordWord(families []string) string {
	if len(families) > 1 {
		return strings.Join(families, " and ") + " records"
	}
	return families[0] + " record"
}

// deleteConfirm tells the user exactly what deleting the site does to its DNS records.
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
	msg := "Delete this site?"
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

func (s *Server) siteEditPage(w http.ResponseWriter, r *http.Request, rt store.Site, addr siteAddr, edit bool) {
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	title := "New site"
	if edit {
		title = "Edit site"
	}
	confirm := ""
	if edit {
		t, _ := dnsTargetOf(r, s.deps.Store, rt)
		confirm = deleteConfirm(t)
	}
	form := siteEditForm{Site: rt, Addr: addr, Edit: edit, Domains: ds, DeleteConfirm: confirm, DNSOn: s.dnsOn(),
		MailOK: s.gateUsable(r.Context())}
	if edit {
		if gs, err := s.deps.Store.Grants(r.Context(), rt.ID); err == nil {
			form.GateACL = gateACLText(gs)
		}
	}
	s.render(w, "siteedit", http.StatusOK, page{Title: title, Data: form})
}

// newSiteFullPage supports prefill via ?sub=&host=&port=.
func (s *Server) newSiteFullPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port, _ := strconv.Atoi(q.Get("port"))
	s.siteEditPage(w, r, store.Site{Scheme: "http", Enabled: true, UpstreamHost: q.Get("host"), UpstreamPort: port}, siteAddr{Subdomain: q.Get("sub")}, false)
}

func (s *Server) editSitePage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rt, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.siteEditPage(w, r, rt, addrOf(ds, rt), true)
}

// checkSite enforces domain existence and hostname uniqueness inside the apply transaction, then makes
// the address's hostname the site's primary one (other hostnames are kept).
func (s *Server) checkSite(r *http.Request, tx *store.Store, rt *store.Site, a siteAddr) error {
	d, err := tx.GetDomain(r.Context(), a.DomainID)
	if err != nil {
		return errors.New("unknown domain")
	}
	host := a.Subdomain + "." + d.Name
	if host == s.deps.Cfg.Host {
		return fmt.Errorf("%s is the ServanaGo UI host; choose another subdomain", host)
	}
	all, err := tx.ListSites(r.Context())
	if err != nil {
		return err
	}
	for _, x := range all {
		if x.ID != rt.ID && slices.Contains(x.Hostnames, host) {
			return userError{http.StatusConflict, fmt.Sprintf("Subdomain %q already exists on that domain.", a.Subdomain)}
		}
	}
	rest := rt.Hostnames
	if len(rest) > 0 {
		rest = rest[1:]
	}
	rt.Hostnames = append([]string{host}, rest...)
	return nil
}

func (s *Server) createSiteFull(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rt, addr, err := parseSite(r.PostForm)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := applyControls(&rt, r.PostForm); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	grants, err := s.parseGate(r.Context(), rt, r.PostForm)
	if err != nil {
		failErr(w, err)
		return
	}
	var created store.Site
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if err := s.checkSite(r, tx, &rt, addr); err != nil {
			return err
		}
		var err error
		created, err = tx.CreateSite(r.Context(), rt)
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

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	in, addr, err := parseSite(r.PostForm)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	grants, err := s.parseGate(r.Context(), in, r.PostForm)
	if err != nil {
		failErr(w, err)
		return
	}
	var old dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetSite(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "site not found"}
		}
		old, _ = dnsTargetOf(r, tx, cur)
		// Overlay only the fields this form owns.
		cur.Scheme = in.Scheme
		cur.UpstreamHost, cur.UpstreamPort = in.UpstreamHost, in.UpstreamPort
		cur.TLSSkipVerify, cur.Enabled, cur.RecordIP, cur.RecordIP6 = in.TLSSkipVerify, in.Enabled, in.RecordIP, in.RecordIP6
		cur.GateMode = in.GateMode
		if err := applyControls(&cur, r.PostForm); err != nil {
			return err
		}
		if err := s.checkSite(r, tx, &cur, addr); err != nil {
			return err
		}
		if err := tx.UpdateSite(r.Context(), cur); err != nil {
			return err
		}
		return tx.ReplaceGrants(r.Context(), cur.ID, grants)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	// A rename or domain change moves the record: drop the old one (if owned), then sync the new name.
	if cur, err := s.deps.Store.GetSite(r.Context(), id); err == nil {
		if now, err := dnsTargetOf(r, s.deps.Store, cur); err == nil && now.name != old.name {
			s.removeRecord(r, old)
			if err := s.deps.Store.DeleteDNS(r.Context(), id); err != nil {
				slog.Error("clear dns row", "site", id, "error", err)
			}
		}
	}
	s.reconcile(r, id)
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	var target dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if cur, err := tx.GetSite(r.Context(), id); err == nil {
			target, _ = dnsTargetOf(r, tx, cur)
		}
		return tx.DeleteSite(r.Context(), id)
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

// detached outlives the request: once the site change is committed, a closed tab must not strand the DNS record.
func detached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
}

// dnsTarget is what a site's A and AAAA records looked like before the site changed or went away.
type dnsTarget struct {
	name, zone string
	rows       []store.DNSRecord // the rows that exist, A before AAAA
}

func dnsTargetOf(r *http.Request, q *store.Store, rt store.Site) (dnsTarget, error) {
	ds, err := q.ListDomains(r.Context())
	if err != nil {
		return dnsTarget{}, err
	}
	d, ok := store.ResolveDomain(ds, rt.Hostnames[0])
	if !ok {
		return dnsTarget{}, errors.New("no domain matches " + rt.Hostnames[0])
	}
	t := dnsTarget{name: rt.Hostnames[0], zone: d.ZoneID}
	for _, fam := range []string{store.FamilyA, store.FamilyAAAA} {
		if row, err := q.GetDNS(r.Context(), rt.ID, fam); err == nil {
			t.rows = append(t.rows, row)
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
		fail(w, http.StatusBadRequest, "bad site id")
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
