// Package web is the server-rendered admin UI (html/template + htmx).
package web

import (
	"bytes"
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/caddylog"
	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/store"
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
	Probe *probe.Monitor
	Logs  *caddylog.Ring
	// HelperSocket and Exec are test seams for node/php sites: the helper's socket (empty = helper.SocketPath)
	// and the runtime detector (nil = the real host).
	HelperSocket string
	Exec         runtimes.RunExec
	// HTTPGet fetches the php.net release feed (nil = a plain https client). A test seam.
	HTTPGet func(ctx context.Context, url string) ([]byte, error)
}

type Server struct {
	deps       Deps
	pages      map[string]*template.Template
	auth       *authn
	startupErr func() error
	cfErr      atomic.Value // string; set by VerifyToken

	backupWarn atomic.Value // string; stale or failed backups for the banner (backups.go)
	downloads  sync.Map     // one-use archive download links: token -> downloadGrant

	flashMu sync.Mutex
	flashes []string // one-time notices shown on the next page render

	docker dockerCache // the helper's container list (docker.go)

	// PHP (php.go): timings and network seams, overridden by tests.
	phpSettle time.Duration // wait after starting a switched site before judging it
	phpPoll   time.Duration // how often a running build is polled
	phpWatch  atomic.Bool   // one build watcher at a time
	healthGet func(ctx context.Context, host, path string) (int, error)
	sendMail  func(from, to, subject, body string) error
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
	s := &Server{deps: d, pages: map[string]*template.Template{}, auth: newAuthn(), phpSettle: 3 * time.Second, phpPoll: 5 * time.Second}
	s.healthGet, s.sendMail = s.localHealthGet, s.smtpMail
	for _, p := range []string{"dashboard", "login", "login_totp", "security", "users", "audit", "settings", "domains", "siteedit", "snippets", "logs", "help", "php", "reference", "backups"} {
		s.pages[p] = template.Must(template.New(p).Funcs(helpFuncs).ParseFS(assets, "templates/layout.html", "templates/deletedlg.html", "templates/"+p+".html"))
	}
	if d.Apply != nil {
		s.startupErr = d.Apply.StartupError
	}
	s.initUsers()
	s.warnUnreadableSeed()
	return s
}

// initUsers wires the session lookup and decides whether the UI is open. With no users and ADMIN_PASSWORD set,
// the first admin is created from it; once any user exists the variable is ignored. No users and no password
// keeps the UI open, as before.
func (s *Server) initUsers() {
	if s.deps.Store == nil {
		return
	}
	ctx := context.Background()
	s.auth.lookup = func(id int64) (store.User, bool) {
		u, err := s.deps.Store.GetUser(ctx, id)
		return u, err == nil
	}
	n, err := s.deps.Store.CountUsers(ctx)
	if err != nil {
		slog.Error("count users", "error", err)
		return
	}
	pw := strings.TrimSpace(s.deps.Cfg.AdminPassword) // like every stored password: no edge whitespace
	switch {
	case n == 0 && pw != "":
		name := normalizeUsername(s.deps.Cfg.AdminUser)
		if name == "" {
			name = "admin"
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err == nil {
			_, err = s.deps.Store.CreateUser(ctx, name, string(hash))
		}
		if err != nil {
			slog.Error("create the first admin from ADMIN_PASSWORD", "error", err)
			return
		}
		slog.Info("created the first admin from ADMIN_PASSWORD", "user", name)
		n = 1
	case n > 0 && pw != "":
		slog.Info("ADMIN_PASSWORD is ignored: administrators already exist (manage them under Users)")
	}
	s.auth.on.Store(n > 0)
	if n == 0 {
		slog.Warn("no administrator exists and ADMIN_PASSWORD is not set: the web UI is open to anyone who can reach it")
		if s.deps.Cfg.TurnstileSecret != "" || s.deps.Cfg.SecretKey != "" {
			slog.Warn("2FA, passkeys and Turnstile are inactive while the UI is open")
		}
	}
}

// dnsOn reports whether Cloudflare is configured. Without it there is no zone lookup, no A-record sync and no DNS column.
func (s *Server) dnsOn() bool { return s.deps.CF != nil && s.deps.DNS != nil }

// VerifyToken checks the Cloudflare token once and records a failure for the UI banner.
func (s *Server) VerifyToken(ctx context.Context) {
	if !s.dnsOn() {
		return
	}
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
	mux.HandleFunc("GET /login/totp", s.loginTOTPPage)
	mux.HandleFunc("POST /login/totp", s.loginTOTPSubmit)
	mux.HandleFunc("POST /login/passkey/begin", s.passkeyLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", s.passkeyLoginFinish)
	mux.Handle("GET /security", s.security(s.securityPage, true))
	mux.Handle("POST /security/totp/begin", s.security(s.totpBegin, true))
	mux.Handle("POST /security/totp/confirm", s.security(s.totpConfirm, true))
	mux.Handle("POST /security/totp/disable", s.security(s.totpDisable, false))
	mux.Handle("POST /security/backup-codes", s.security(s.backupRegenerate, false))
	mux.Handle("POST /security/passkeys/begin", s.security(s.passkeyRegisterBegin, true))
	mux.Handle("POST /security/passkeys/finish", s.security(s.passkeyRegisterFinish, true))
	mux.Handle("DELETE /security/passkeys/{id}", s.security(s.passkeyDelete, false))
	mux.Handle("POST /security/gate/revoke", s.security(s.revokeGateIdentity, false))
	mux.Handle("GET /audit", s.protected(s.auditPage))
	mux.Handle("GET /users", s.security(s.usersPage, false))
	mux.Handle("POST /users", s.security(s.addUser, false))
	mux.Handle("POST /users/{id}/password", s.security(s.setPassword, false))
	mux.Handle("POST /users/{id}/reset-2fa", s.security(s.resetSecondFactor, false))
	mux.Handle("POST /users/{id}/delete", s.security(s.removeUser, false))
	mux.Handle("GET /{$}", s.protected(s.dashboard))
	mux.Handle("GET /help", s.protected(s.helpPage))
	mux.Handle("GET /settings", s.protected(s.settingsPage))
	mux.Handle("POST /settings/smtp", s.protected(s.saveSMTP))
	mux.Handle("GET /backups", s.protected(s.backupsPage))
	mux.Handle("POST /backups/settings", s.protected(s.saveBackupSettings))
	mux.Handle("POST /backups/run", s.protected(s.runBackup))
	mux.Handle("POST /backups/sites/{id}", s.protected(s.saveSiteBackup))
	mux.Handle("POST /backups/sites/{id}/profiles", s.protected(s.addBackupProfile))
	mux.Handle("POST /backups/sites/{id}/profiles/delete", s.protected(s.deleteBackupProfile))
	mux.Handle("POST /backups/sites/{id}/volumes", s.protected(s.addBackupVolume))
	mux.Handle("POST /backups/sites/{id}/volumes/delete", s.protected(s.deleteBackupVolume))
	mux.Handle("POST /backups/download", s.protected(s.startDownload))
	mux.Handle("GET /backups/file/{token}", s.protected(s.downloadFile))
	mux.Handle("POST /backups/restore", s.protected(s.restoreBackup))
	mux.Handle("GET /status", s.protected(s.status))
	mux.Handle("GET /php", s.protected(s.phpPage))
	mux.Handle("GET /php/job", s.protected(s.phpJobPanel))
	mux.Handle("POST /php/builds", s.protected(s.phpBuild))
	mux.Handle("POST /php/builds/install", s.protected(s.phpInstall))
	mux.Handle("POST /php/builds/{label}/delete", s.protected(s.phpPrune))
	mux.Handle("POST /php/switch", s.protected(s.phpSwitch))
	mux.Handle("POST /php/defaults", s.protected(s.phpDefault))
	mux.Handle("POST /php/check", s.protected(s.phpCheckNow))
	mux.Handle("POST /php/composer", s.protected(s.phpComposer))
	mux.Handle("GET /logs", s.protected(s.logsPage))
	mux.Handle("GET /logs/rows", s.protected(s.logRows))
	mux.Handle("GET /domains", s.protected(s.domainsPage))
	mux.Handle("POST /domains", s.protected(s.addDomain))
	mux.Handle("PUT /domains/{id}", s.protected(s.updateDomain))
	mux.Handle("DELETE /domains/{id}", s.protected(s.deleteDomain))
	mux.Handle("GET /reference", s.protected(s.referencePage))
	mux.Handle("GET /snippets", s.protected(s.snippetsPage))
	mux.Handle("POST /snippets", s.protected(s.addSnippet))
	mux.Handle("PUT /snippets/{id}", s.protected(s.updateSnippet))
	mux.Handle("DELETE /snippets/{id}", s.protected(s.deleteSnippet))
	mux.Handle("GET /sites/new", s.protected(s.newSitePage))
	mux.Handle("POST /sites", s.protected(s.createSite))
	mux.Handle("GET /sites/{id}", s.protected(s.editSitePage))
	mux.Handle("PUT /sites/{id}", s.protected(s.updateSite))
	mux.Handle("DELETE /sites/{id}", s.protected(s.deleteSite))
	mux.Handle("POST /host/dns/resync", s.protected(s.hostDNS(false)))
	mux.Handle("POST /host/dns/takeover", s.protected(s.hostDNS(true)))
	mux.Handle("POST /sites/{id}/toggle", s.protected(s.toggleSite))
	mux.Handle("POST /sites/{id}/gate/grants", s.protected(s.addGateGrant))
	mux.Handle("POST /sites/{id}/gate/grants/delete", s.protected(s.removeGateGrant))
	mux.Handle("POST /sites/{id}/gate/test", s.protected(s.testGateMail))
	mux.Handle("POST /sites/{id}/dns/resync", s.protected(s.resyncDNS))
	mux.Handle("POST /sites/{id}/dns/takeover", s.protected(s.takeOverDNS))
	// /mcp authenticates with its own bearer token and carries no cookie, so the cookie-era CSRF check does not apply.
	top := http.NewServeMux()
	top.Handle("/mcp", s.mcpHandler())
	top.Handle("/", s.csrf(mux))
	return top
}

type page struct {
	Title      string
	Open       bool // no ADMIN_PASSWORD: UI is unauthenticated
	StartupErr string
	CFErr      string
	Flash      []string
	LoggedIn   bool
	Bare       bool   // sign-in pages: brand only, no app navigation
	Nav        string // sidebar entry to mark current: the page name, with the site editor under "dashboard"
	BackupWarn string
	Data       any
}

func (s *Server) render(w http.ResponseWriter, name string, status int, p page) {
	p.Open = !s.auth.enabled()
	p.LoggedIn = s.auth.enabled()
	p.Bare = name == "login" || name == "login_totp"
	if p.Nav = name; name == "siteedit" {
		p.Nav = "dashboard"
	}
	p.Flash = s.takeFlashes()
	if !p.Bare {
		p.BackupWarn = s.backupWarnText()
	}
	if s.startupErr != nil {
		if err := s.startupErr(); err != nil {
			p.StartupErr = err.Error()
		}
	}
	if v, ok := s.cfErr.Load().(string); ok {
		p.CFErr = v
	}
	var buf bytes.Buffer // a template error must not leave the browser with half a page and a 200
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		slog.Error("render page", "page", name, "error", err)
		http.Error(w, "This page failed to render. The error is in the ServanaGo log.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// status renders just the routes table; the dashboard polls it every 10s.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	routes, err := s.siteRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.pages["dashboard"].ExecuteTemplate(w, "sites", routes); err != nil {
		slog.Error("render status", "error", err)
	}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	domains, err := s.domainRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	routes, err := s.siteRows(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	host := s.hostCard(r.Context())
	items := s.checklist(r.Context(), routes, host)
	s.render(w, "dashboard", http.StatusOK, page{Title: "Dashboard", Data: struct {
		Domains   []domainRow
		Sites     []siteRow
		Host      *hostCard
		Checklist []checkItem
		SetupDone bool
		DNSOn     bool
		Runtimes  runtimes.Report
	}{domains, routes, host, items, setupDone(items), s.dnsOn(), s.detect(r.Context())}})
}
