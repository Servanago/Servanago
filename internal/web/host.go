package web

import (
	"context"
	"net/http"

	"github.com/caretakarr/caretakarr/internal/dnssync"
	"github.com/caretakarr/caretakarr/internal/store"
)

// hostCard is the dashboard card for CARETAKARR_HOST's own A record.
type hostCard struct {
	Spec dnssync.HostSpec
	DNS  store.DNSRecord
}

func (s *Server) hostCard(ctx context.Context) *hostCard {
	if s.deps.DNS == nil || s.deps.DNS.Host.Name == "" {
		return nil
	}
	c := &hostCard{Spec: s.deps.DNS.Host, DNS: store.DNSRecord{State: "pending"}}
	if row, err := s.deps.Store.GetUIDNS(ctx); err == nil {
		c.DNS = row
	}
	return c
}

func (s *Server) hostDNS(takeOver bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := detached(r)
		defer cancel()
		if err := s.deps.DNS.ReconcileHost(ctx, takeOver); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
	}
}
