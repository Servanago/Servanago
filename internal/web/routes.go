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

	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/presets"
	"github.com/caretakarr/caretakarr/internal/store"
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
	r.TLSSkipVerify = v.Get("tls_skip_verify") != ""
	r.Enabled = v.Get("enabled") != ""
	r.Preset = v.Get("preset")
	return r, nil
}

type routeRow struct {
	store.Route
	Host   string
	DNS    store.DNSRecord
	HasDNS bool
}

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
	byRoute := map[int64]store.DNSRecord{}
	for _, d := range dns {
		byRoute[d.RouteID] = d
	}
	rows := make([]routeRow, len(rs))
	for i, x := range rs {
		d, ok := byRoute[x.ID]
		rows[i] = routeRow{Route: x, Host: x.Subdomain + "." + names[x.DomainID], DNS: d, HasDNS: ok}
	}
	return rows, nil
}

type routeForm struct {
	Route         store.Route
	Edit          bool
	Domains       []store.Domain
	Presets       []presets.Preset
	DeleteConfirm string
}

// deleteConfirm tells the user exactly what deleting the route does to its A record.
func deleteConfirm(t dnsTarget) string {
	switch {
	case !t.hasRow || t.row.CFRecordID == "":
		return "Delete this route?"
	case t.row.Owned:
		return "Delete this route? This also deletes the A record " + t.name + " in Cloudflare."
	default:
		return "Delete this route? The existing A record " + t.name + " was adopted and is left in place."
	}
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
	s.render(w, "route", http.StatusOK, page{Title: title, Data: routeForm{rt, edit, ds, presets.All, confirm}})
}

func (s *Server) newRoutePage(w http.ResponseWriter, r *http.Request) {
	s.routeFormPage(w, r, store.Route{Scheme: "http", Enabled: true}, false)
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
func checkRoute(r *http.Request, tx *store.Store, rt store.Route) error {
	if _, err := tx.GetDomain(r.Context(), rt.DomainID); err != nil {
		return errors.New("unknown domain")
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
	var created store.Route
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if err := checkRoute(r, tx, rt); err != nil {
			return err
		}
		var err error
		created, err = tx.CreateRoute(r.Context(), rt)
		return err
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
	var old dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetRoute(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "route not found"}
		}
		old, _ = dnsTargetOf(r, tx, cur)
		// Overlay only the fields this form owns; DNS override, allowlist and auth are edited elsewhere.
		cur.DomainID, cur.Subdomain, cur.Scheme = in.DomainID, in.Subdomain, in.Scheme
		cur.UpstreamHost, cur.UpstreamPort = in.UpstreamHost, in.UpstreamPort
		cur.TLSSkipVerify, cur.Enabled, cur.Preset = in.TLSSkipVerify, in.Enabled, in.Preset
		if err := checkRoute(r, tx, cur); err != nil {
			return err
		}
		return tx.UpdateRoute(r.Context(), cur)
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
	s.removeRecord(r, target)
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

// detached outlives the request: once the route change is committed, a closed tab must not strand the DNS record.
func detached(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
}

// dnsTarget is what a route's A record looked like before the route changed or went away.
type dnsTarget struct {
	name, zone string
	row        store.DNSRecord
	hasRow     bool
}

func dnsTargetOf(r *http.Request, q *store.Store, rt store.Route) (dnsTarget, error) {
	d, err := q.GetDomain(r.Context(), rt.DomainID)
	if err != nil {
		return dnsTarget{}, err
	}
	t := dnsTarget{name: rt.Subdomain + "." + d.Name, zone: d.ZoneID}
	if row, err := q.GetDNS(r.Context(), rt.ID); err == nil {
		t.row, t.hasRow = row, true
	}
	return t, nil
}

func (s *Server) reconcile(r *http.Request, routeID int64) {
	ctx, cancel := detached(r)
	defer cancel()
	if err := s.deps.DNS.Reconcile(ctx, routeID); err != nil {
		slog.Error("dns reconcile", "route", routeID, "error", err)
	}
}

// removeRecord deletes the route's A record when Caretakarr owns it; failures become a one-time notice.
func (s *Server) removeRecord(r *http.Request, t dnsTarget) {
	if !t.hasRow {
		return
	}
	ctx, cancel := detached(r)
	defer cancel()
	if _, err := s.deps.DNS.Remove(ctx, t.zone, t.row); err != nil {
		slog.Error("dns remove", "record", t.name, "error", err)
		s.flash(fmt.Sprintf("The A record %s could not be removed: %v", t.name, err))
	}
}

func (s *Server) resyncDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, s.deps.DNS.Reconcile)
}
func (s *Server) takeOverDNS(w http.ResponseWriter, r *http.Request) {
	s.dnsAction(w, r, s.deps.DNS.TakeOver)
}

func (s *Server) dnsAction(w http.ResponseWriter, r *http.Request, act func(context.Context, int64) error) {
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
