package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// fail writes an HTML-escaped message: htmx swaps error bodies into the page as HTML.
// Known errors get a plain-language explanation first; the raw text is always kept.
func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, errorHTML(msg))
}

// userError carries an HTTP status out of a Mutate callback.
type userError struct {
	status int
	msg    string
}

func (e userError) Error() string { return e.msg }

func failErr(w http.ResponseWriter, err error) {
	var ue userError
	if errors.As(err, &ue) {
		fail(w, ue.status, ue.msg)
		return
	}
	fail(w, http.StatusUnprocessableEntity, err.Error())
}

type domainRow struct {
	store.Domain
	Sites int
}

func (s *Server) domainRows(r *http.Request) ([]domainRow, error) {
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		return nil, err
	}
	rs, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		return nil, err
	}
	counts := map[int64]int{}
	for _, x := range rs {
		if d, ok := store.ResolveDomain(ds, x.Hostnames[0]); ok {
			counts[d.ID]++
		}
	}
	rows := make([]domainRow, len(ds))
	for i, d := range ds {
		rows[i] = domainRow{d, counts[d.ID]}
	}
	return rows, nil
}

func (s *Server) domainsPage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.domainRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "domains", http.StatusOK, page{Title: "Domains", Data: struct {
		Rows  []domainRow
		DNSOn bool
	}{rows, s.dnsOn()}})
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	ip := strings.TrimSpace(r.PostFormValue("default_ip"))
	mode := r.PostFormValue("cert_mode")
	if mode == "" {
		mode = "wildcard"
		if !s.dnsOn() {
			mode = "per_host"
		}
	}
	if err := config.ValidateDomain(name); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if mode != "wildcard" && mode != "per_host" {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("cert_mode %q must be wildcard or per_host", mode))
		return
	}
	ip6 := strings.TrimSpace(r.PostFormValue("default_ip6"))
	zone := "" // without Cloudflare a domain has no zone, no default record IPs, and certificates are per host
	if s.dnsOn() {
		if _, err := config.ValidateIP(ip); err != nil {
			fail(w, http.StatusUnprocessableEntity, "default IP: "+err.Error())
			return
		}
		if ip6 != "" {
			if _, err := config.ValidateIP6(ip6); err != nil {
				fail(w, http.StatusUnprocessableEntity, "default IPv6: "+err.Error())
				return
			}
		}
		var err error
		if zone, err = s.deps.CF.ZoneID(r.Context(), name); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	} else {
		ip, ip6 = "", ""
		if mode == "wildcard" {
			fail(w, http.StatusUnprocessableEntity, "Wildcard certificates need Cloudflare DNS (set CLOUDFLARE_API_TOKEN). Use per_host, or leave the choice empty.")
			return
		}
	}
	err := s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		_, err := tx.CreateDomain(r.Context(), store.Domain{Name: name, ZoneID: zone, DefaultIP: ip, DefaultIP6: ip6, CertMode: mode})
		return err
	})
	if err != nil {
		failErr(w, err)
		return
	}
	w.Header().Set("HX-Redirect", "/domains")
	w.WriteHeader(http.StatusNoContent)
}

// updateDomain edits everything but the name: zone (looked up by name; blank keeps the stored one), default IPs
// and certificate mode. Existing DNS records are not touched; the site rows offer Resync.
func (s *Server) updateDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad domain id")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := r.PostFormValue("cert_mode")
	if mode != "wildcard" && mode != "per_host" {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("cert_mode %q must be wildcard or per_host", mode))
		return
	}
	ip, ip6 := strings.TrimSpace(r.PostFormValue("default_ip")), strings.TrimSpace(r.PostFormValue("default_ip6"))
	zone := strings.ToLower(strings.TrimSpace(r.PostFormValue("zone")))
	zoneID := ""
	if s.dnsOn() {
		if _, err := config.ValidateIP(ip); err != nil {
			fail(w, http.StatusUnprocessableEntity, "default IP: "+err.Error())
			return
		}
		if ip6 != "" {
			if _, err := config.ValidateIP6(ip6); err != nil {
				fail(w, http.StatusUnprocessableEntity, "default IPv6: "+err.Error())
				return
			}
		}
		if zone != "" {
			if zoneID, err = s.deps.CF.ZoneID(r.Context(), zone); err != nil {
				fail(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
		}
	} else {
		ip, ip6 = "", ""
		if mode == "wildcard" {
			fail(w, http.StatusUnprocessableEntity, "Wildcard certificates need Cloudflare DNS (set CLOUDFLARE_API_TOKEN). Use per_host.")
			return
		}
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		d, err := tx.GetDomain(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "domain not found"}
		}
		d.DefaultIP, d.DefaultIP6, d.CertMode = ip, ip6, mode
		if zoneID != "" {
			d.ZoneID = zoneID
		}
		return tx.UpdateDomain(r.Context(), d)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	w.Header().Set("HX-Redirect", "/domains")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad domain id")
		return
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		rs, err := tx.ListSites(r.Context())
		if err != nil {
			return err
		}
		ds, err := tx.ListDomains(r.Context())
		if err != nil {
			return err
		}
		n := 0
		for _, x := range rs {
			if d, ok := store.ResolveDomain(ds, x.Hostnames[0]); ok && d.ID == id {
				n++
			}
		}
		if n > 0 {
			return userError{http.StatusConflict, fmt.Sprintf("Delete its %d site(s) first.", n)}
		}
		return tx.DeleteDomain(r.Context(), id)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	w.Header().Set("HX-Redirect", "/domains")
	w.WriteHeader(http.StatusNoContent)
}
