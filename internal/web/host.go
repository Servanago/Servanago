package web

import (
	"context"
	"net/http"

	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/store"
)

// hostCard is the dashboard card for SERVANAGO_HOST's own A (and optional AAAA) record.
type hostCard struct {
	Spec dnssync.HostSpec
	DNS  []store.DNSRecord // one row per configured family, A first; a pending placeholder until the first sync
}

// State is the worst state across the host's records.
func (c hostCard) State() string { return worstState(c.DNS) }

// Error is the first record error, for the card and the checklist.
func (c hostCard) Error() string {
	for _, r := range c.DNS {
		if r.Error != "" {
			return r.Error
		}
	}
	return ""
}

func (s *Server) hostCard(ctx context.Context) *hostCard {
	if s.deps.DNS == nil || s.deps.DNS.Host.Name == "" {
		return nil
	}
	spec := s.deps.DNS.Host
	c := &hostCard{Spec: spec}
	for _, fam := range []string{store.FamilyA, store.FamilyAAAA} {
		ip := map[string]string{store.FamilyA: spec.IP, store.FamilyAAAA: spec.IP6}[fam]
		row, err := s.deps.Store.GetUIDNS(ctx, fam)
		switch {
		case err == nil:
			c.DNS = append(c.DNS, row)
		case ip != "": // configured but not synced yet
			c.DNS = append(c.DNS, store.DNSRecord{Family: fam, Content: ip, State: "pending"})
		}
	}
	return c
}

func (s *Server) hostDNS(takeOver bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.dnsOn() {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := detached(r)
		defer cancel()
		if err := s.deps.DNS.ReconcileHost(ctx, takeOver); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		action := "host.dns_resynced"
		if takeOver {
			action = "host.dns_taken_over"
		}
		s.audit(r, action, s.deps.Cfg.Host)
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
	}
}
