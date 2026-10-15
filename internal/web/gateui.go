// Site access gate management in the web UI: the Security page listing and revoke.
package web

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/caretakarr/caretakarr/internal/gatelogic"
)

// gateIdentityView is one row of the Security page's gate listing.
type gateIdentityView struct {
	Email    string
	Rules    string
	LastSeen string
	Expire   string
}

// gateIdentitiesData lists magic-link identities with their grants for the Security page.
func (s *Server) gateIdentitiesData(ctx context.Context) ([]gateIdentityView, error) {
	gs, err := s.deps.Store.GateIdentities(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]gateIdentityView, len(gs))
	for i, g := range gs {
		out[i] = gateIdentityView{Email: g.Email, Rules: g.Rules, LastSeen: g.LastSeen, Expire: g.Expire}
	}
	return out, nil
}

// revokeGateIdentity deletes one identity, cutting its session on every gated route at once.
func (s *Server) revokeGateIdentity(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	email, err := gatelogic.NormalizeEmail(r.PostFormValue("email"))
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.deps.Store.DeleteIdentity(r.Context(), email); err != nil {
		failErr(w, err)
		return
	}
	slog.Info("gate revoke", "event", "gate.revoke")
	w.Header().Set("HX-Redirect", "/security")
	w.WriteHeader(http.StatusNoContent)
}
