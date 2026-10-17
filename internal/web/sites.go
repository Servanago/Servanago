package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

type addSiteData struct {
	Hostname, Host string
	Port           int
	ServerIP       string // where the A record will point; shown in the live preview
	DNSOn          bool   // Cloudflare is configured; otherwise there is no DNS record to preview
	MailOK         bool   // email delivery works: the magic-link controls are live
}

// newSitePage supports prefill via ?hostname=&host=&port=.
func (s *Server) newSitePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port, _ := strconv.Atoi(q.Get("port"))
	s.render(w, "site", http.StatusOK, page{Title: "Add site", Data: addSiteData{
		Hostname: q.Get("hostname"), Host: q.Get("host"), Port: port, ServerIP: s.deps.Cfg.HostIP, DNSOn: s.dnsOn(), MailOK: s.gateUsable(r.Context())}})
}

// addSite turns "oc.example.com -> 192.168.25.165:9200" into the managed domain (if new), the site and its A record.
// The backend address and port are separate fields, so the hostname/zone logic never has to parse a host:port.
func (s *Server) addSite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	hostname := strings.ToLower(strings.TrimSpace(r.PostFormValue("hostname")))
	if err := config.ValidateDomain(hostname); err != nil {
		fail(w, http.StatusUnprocessableEntity, "hostname: "+err.Error())
		return
	}
	v := r.PostForm
	v.Set("domain_id", "0") // placeholders: parseSite validates the rest; the real values are resolved below
	v.Set("subdomain", strings.SplitN(hostname, ".", 2)[0])
	rt, _, err := parseSite(v)
	if err == nil {
		err = applyControls(&rt, v)
	}
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	domains, err := s.deps.Store.ListDomains(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var managed *store.Domain // the longest managed domain that encloses the hostname
	for i, d := range domains {
		if strings.HasSuffix(hostname, "."+d.Name) && (managed == nil || len(d.Name) > len(managed.Name)) {
			managed = &domains[i]
		}
	}
	var newDomain store.Domain
	zoneName := ""
	if managed != nil {
		zoneName = managed.Name
	} else if !s.dnsOn() {
		// No Cloudflare, so no zone lookup: the hostname can only belong to a domain added by hand.
		for _, d := range domains {
			if hostname == d.Name {
				fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is a domain itself; use a subdomain such as app.%s", hostname, d.Name))
				return
			}
		}
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("No domain matches %s. Add its domain (for example %s) on the Domains page first; without a Cloudflare token ServanaGo cannot look it up.", hostname, suggestDomain(hostname)))
		return
	} else {
		if _, err := config.ValidateIP(s.deps.Cfg.HostIP); err != nil {
			fail(w, http.StatusUnprocessableEntity, "SERVANAGO_HOST_IP: "+err.Error())
			return
		}
		zoneID, zone, err := s.deps.CF.ZoneFor(r.Context(), hostname, "")
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		zoneName = zone
		newDomain = store.Domain{Name: zone, ZoneID: zoneID, DefaultIP: s.deps.Cfg.HostIP, DefaultIP6: s.deps.Cfg.HostIP6, CertMode: "wildcard"}
	}
	if hostname == zoneName {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is a zone itself; use a subdomain such as app.%s", hostname, zoneName))
		return
	}
	sub := strings.TrimSuffix(hostname, "."+zoneName)
	if strings.Contains(sub, ".") {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is more than one label below %s; a wildcard certificate would not cover it. Use name.%s", hostname, zoneName, zoneName))
		return
	}

	grants, err := s.parseGate(r.Context(), rt, v)
	if err != nil {
		failErr(w, err)
		return
	}

	var created store.Site
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		addr := siteAddr{Subdomain: sub}
		if managed != nil {
			addr.DomainID = managed.ID
		} else {
			d, err := tx.CreateDomain(r.Context(), newDomain)
			if err != nil {
				return err
			}
			addr.DomainID = d.ID
		}
		if err := s.checkSite(r, tx, &rt, addr); err != nil {
			return err
		}
		var cerr error
		created, cerr = tx.CreateSite(r.Context(), rt)
		if cerr != nil {
			return cerr
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

// suggestDomain is the hostname minus its first label: a hint for the "add the domain first" message, not a zone lookup.
func suggestDomain(hostname string) string {
	if _, rest, ok := strings.Cut(hostname, "."); ok && strings.Contains(rest, ".") {
		return rest
	}
	return hostname
}
