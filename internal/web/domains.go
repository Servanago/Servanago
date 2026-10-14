package web

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/store"
)

// fail writes an HTML-escaped message: htmx swaps error bodies into the page as HTML.
func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, html.EscapeString(msg))
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
	Routes int
}

func (s *Server) domainRows(r *http.Request) ([]domainRow, error) {
	ds, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		return nil, err
	}
	rs, err := s.deps.Store.ListRoutes(r.Context())
	if err != nil {
		return nil, err
	}
	counts := map[int64]int{}
	for _, x := range rs {
		counts[x.DomainID]++
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
	s.render(w, "domains", http.StatusOK, page{Title: "Domains", Data: rows})
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PostFormValue("name")))
	ip := strings.TrimSpace(r.PostFormValue("default_ip"))
	mode := r.PostFormValue("cert_mode")
	if mode == "" {
		mode = "wildcard"
	}
	if err := config.ValidateDomain(name); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if a, err := netip.ParseAddr(ip); err != nil || !a.Is4() {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("default IP %q must be an IPv4 address (A record)", ip))
		return
	}
	if mode != "wildcard" && mode != "per_host" {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("cert_mode %q must be wildcard or per_host", mode))
		return
	}
	zone, err := s.deps.CF.ZoneID(r.Context(), name)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		_, err := tx.CreateDomain(r.Context(), store.Domain{Name: name, ZoneID: zone, DefaultIP: ip, CertMode: mode})
		return err
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
		rs, err := tx.ListRoutes(r.Context())
		if err != nil {
			return err
		}
		n := 0
		for _, x := range rs {
			if x.DomainID == id {
				n++
			}
		}
		if n > 0 {
			return userError{http.StatusConflict, fmt.Sprintf("Delete its %d route(s) first.", n)}
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
