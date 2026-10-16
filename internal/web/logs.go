package web

import (
	"log/slog"
	"net/http"

	"github.com/servanago/servanago/internal/caddylog"
)

type logView struct {
	Level   string
	Levels  []string
	Entries []caddylog.Entry
}

func (s *Server) logsPage(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	s.render(w, "logs", http.StatusOK, page{Title: "Logs", Data: logView{level, []string{"debug", "info", "warn", "error"}, s.deps.Logs.Entries(level)}})
}

// logRows is the fragment the Logs page polls.
func (s *Server) logRows(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages["logs"].ExecuteTemplate(w, "logrows", s.deps.Logs.Entries(r.URL.Query().Get("level"))); err != nil {
		slog.Error("render log rows", "error", err)
	}
}
