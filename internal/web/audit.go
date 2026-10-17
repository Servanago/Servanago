package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/servanago/servanago/internal/store"
)

// audit records an action by the signed-in admin of r (or "open mode" when the UI has no users).
// It never fails the action: a database error is logged and the request carries on.
func (s *Server) audit(r *http.Request, action, target string) {
	actor := "open mode" // not a valid username, so it cannot be mistaken for one
	if u, ok := currentUser(r); ok {
		actor = u.Username
	}
	s.auditAs(r, actor, action, target)
}

// auditAs records an action for an explicit actor: sign-ins, where the session does not exist yet, and failed
// attempts, where the name is whatever was typed. The text is cleaned and bounded; secrets never come through here.
func (s *Server) auditAs(r *http.Request, actor, action, target string) {
	if s.deps.Store == nil {
		return
	}
	e := store.AuditEntry{At: s.auth.now().UTC().Format(time.RFC3339), Actor: tidy(actor, 64), Action: action, Target: tidy(target, 200), IP: clientIP(r)}
	// The row is written after the action succeeded, so a closed browser tab must not drop it.
	if err := s.deps.Store.AddAudit(context.WithoutCancel(r.Context()), e); err != nil {
		slog.Error("write audit row", "action", action, "error", err)
	}
}

// tidy drops control characters and cuts s to at most max runes.
func tidy(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	rows, err := s.deps.Store.ListAudit(r.Context(), 200)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, "audit", http.StatusOK, page{Title: "Audit", Data: rows})
}
