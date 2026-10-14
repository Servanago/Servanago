// Package web is the server-rendered admin UI (html/template + htmx).
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/caretakarr/caretakarr/internal/apply"
	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/store"
)

//go:embed templates static
var assets embed.FS

type Deps struct {
	Cfg   config.Config
	Store *store.Store
	Apply *apply.Service
}

type Server struct {
	deps       Deps
	pages      map[string]*template.Template
	auth       *authn
	startupErr func() error
}

func New(d Deps) *Server {
	s := &Server{deps: d, pages: map[string]*template.Template{}, auth: newAuthn(d.Cfg.AdminPassword)}
	for _, p := range []string{"dashboard", "login"} {
		s.pages[p] = template.Must(template.ParseFS(assets, "templates/layout.html", "templates/"+p+".html"))
	}
	if d.Apply != nil {
		s.startupErr = d.Apply.StartupError
	}
	if d.Cfg.AdminPassword == "" {
		slog.Warn("ADMIN_PASSWORD is not set: the web UI is open to anyone who can reach it")
	}
	return s
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /{$}", s.protected(s.dashboard))
	return s.csrf(mux)
}

type page struct {
	Title      string
	Open       bool // no ADMIN_PASSWORD: UI is unauthenticated
	StartupErr string
	LoggedIn   bool
}

func (s *Server) render(w http.ResponseWriter, name string, status int, p page) {
	p.Open = !s.auth.enabled()
	if s.startupErr != nil {
		if err := s.startupErr(); err != nil {
			p.StartupErr = err.Error()
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[name].ExecuteTemplate(w, "layout", p); err != nil {
		slog.Error("render page", "page", name, "error", err)
	}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, "dashboard", http.StatusOK, page{Title: "Dashboard", LoggedIn: s.auth.enabled()})
}
