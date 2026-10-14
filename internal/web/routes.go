package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

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
	Host string
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
	rows := make([]routeRow, len(rs))
	for i, x := range rs {
		rows[i] = routeRow{x, x.Subdomain + "." + names[x.DomainID]}
	}
	return rows, nil
}

type routeForm struct {
	Route   store.Route
	Edit    bool
	Domains []store.Domain
	Presets []presets.Preset
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
	s.render(w, "route", http.StatusOK, page{Title: title, Data: routeForm{rt, edit, ds, presets.All}})
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
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if err := checkRoute(r, tx, rt); err != nil {
			return err
		}
		_, err := tx.CreateRoute(r.Context(), rt)
		return err
	})
	if err != nil {
		failErr(w, err)
		return
	}
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
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetRoute(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "route not found"}
		}
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
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad route id")
		return
	}
	if err := s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error { return tx.DeleteRoute(r.Context(), id) }); err != nil {
		failErr(w, err)
		return
	}
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}
