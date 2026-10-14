// Package web is the server-rendered admin UI (html/template + htmx).
package web

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/caretakarr/caretakarr/internal/cfdns"
	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/dnssync"
	"github.com/caretakarr/caretakarr/internal/store"
)

//go:embed templates static
var assets embed.FS

// Applier is the apply service: every config change goes through Mutate.
type Applier interface {
	Mutate(ctx context.Context, fn func(tx *store.Store) error) error
	StartupError() error
}

type Deps struct {
	Cfg   config.Config
	Store *store.Store
	Apply Applier
	CF    *cfdns.Client
	DNS   *dnssync.Syncer
}

type Server struct {
	deps       Deps
	pages      map[string]*template.Template
	auth       *authn
	startupErr func() error
	cfErr      atomic.Value // string; set by VerifyToken

	flashMu sync.Mutex
	flashes []string // one-time notices shown on the next page render
}

func (s *Server) flash(msg string) {
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	s.flashes = append(s.flashes, msg)
}

func (s *Server) takeFlashes() []string {
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	f := s.flashes
	s.flashes = nil
	return f
}

func New(d Deps) *Server {
	s := &Server{deps: d, pages: map[string]*template.Template{}, auth: newAuthn(d.Cfg.AdminPassword)}
	for _, p := range []string{"dashboard", "login", "domains", "route"} {
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

// VerifyToken checks the Cloudflare token once and records a failure for the UI banner.
func (s *Server) VerifyToken(ctx context.Context) {
	if err := s.deps.CF.VerifyToken(ctx); err != nil {
		slog.Error("cloudflare token check failed", "error", err)
		s.cfErr.Store(err.Error())
		return
	}
	s.cfErr.Store("")
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /{$}", s.protected(s.dashboard))
	mux.Handle("GET /domains", s.protected(s.domainsPage))
	mux.Handle("POST /domains", s.protected(s.addDomain))
	mux.Handle("DELETE /domains/{id}", s.protected(s.deleteDomain))
	mux.Handle("GET /routes/new", s.protected(s.newRoutePage))
	mux.Handle("POST /routes", s.protected(s.createRoute))
	mux.Handle("GET /routes/{id}", s.protected(s.editRoutePage))
	mux.Handle("PUT /routes/{id}", s.protected(s.updateRoute))
	mux.Handle("DELETE /routes/{id}", s.protected(s.deleteRoute))
	mux.Handle("POST /routes/{id}/dns/resync", s.protected(s.resyncDNS))
	mux.Handle("POST /routes/{id}/dns/takeover", s.protected(s.takeOverDNS))
	return s.csrf(mux)
}

type page struct {
	Title      string
	Open       bool // no ADMIN_PASSWORD: UI is unauthenticated
	StartupErr string
	CFErr      string
	Flash      []string
	LoggedIn   bool
	Data       any
}

func (s *Server) render(w http.ResponseWriter, name string, status int, p page) {
	p.Open = !s.auth.enabled()
	p.LoggedIn = s.auth.enabled()
	p.Flash = s.takeFlashes()
	if s.startupErr != nil {
		if err := s.startupErr(); err != nil {
			p.StartupErr = err.Error()
		}
	}
	if v, ok := s.cfErr.Load().(string); ok {
		p.CFErr = v
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[name].ExecuteTemplate(w, "layout", p); err != nil {
		slog.Error("render page", "page", name, "error", err)
	}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	domains, err := s.domainRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	routes, err := s.routeRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "dashboard", http.StatusOK, page{Title: "Dashboard", Data: struct {
		Domains []domainRow
		Routes  []routeRow
	}{domains, routes}})
}
