// Command servanago runs the admin UI and an embedded Caddy configured from SQLite.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/caddy-dns/cloudflare"
	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/servanago/servanago/internal/apply"
	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/caddygate"
	"github.com/servanago/servanago/internal/caddylog"
	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/smtpx"
	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/web"
)

func main() {
	cmd := run
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "import":
			cmd = func() error { return runImport(os.Args[2:], os.Stdout) }
		case "2fa-reset":
			cmd = func() error { return runReset(os.Stdout) }
		}
	}
	if err := cmd(); err != nil {
		slog.Error("servanago failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "servanago.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	uiUpstream, err := loopbackDial(cfg.UIListen)
	if err != nil {
		return err
	}
	issuer := caddycfg.ACME
	if cfg.Issuer == "internal" { // ACME_ISSUER=internal: self-signed, used by e2e and offline setups
		issuer = caddycfg.Internal
	}
	// The gate module reads SQLite directly in the Caddy request path; without an installed
	// service every gated route fails closed with 503, never open.
	caddygate.Install(caddygate.New(st, smtpx.Dialer{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Pass: cfg.SMTPPass,
	}, cfg.MailFrom, cfg.SecretKey, cfg.HTTPSPort))
	svc := apply.New(st, caddycfg.Options{
		UIHost: cfg.Host, UIUpstream: uiUpstream, Email: cfg.ACMEEmail, Staging: cfg.Staging,
		HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort, StoragePath: filepath.Join(cfg.DataDir, "caddy"),
		PropagationDelay: cfg.PropagationDelay, PropagationTimeout: cfg.PropagationTimeout, Resolvers: cfg.Resolvers,
		Issuer: issuer, HTTP01: !cfg.DNSEnabled(),
	})
	if err := svc.Start(context.Background()); err != nil {
		return err
	}
	defer func() { _ = caddy.Stop() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mon := probe.NewMonitor(st, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.HTTPSPort)))
	mon.LogError = caddylog.Sink.LastError
	go mon.Run(ctx, 30*time.Second)
	// Cloudflare is optional: with no token there is no zone lookup and no DNS sync, and certificates use the default ACME challenges.
	var cf *cfdns.Client
	var dns *dnssync.Syncer
	if cfg.DNSEnabled() {
		var cfOpts []option.RequestOption
		if cfg.CFBaseURL != "" {
			cfOpts = append(cfOpts, option.WithBaseURL(cfg.CFBaseURL))
		}
		cf = cfdns.New(cfg.CloudflareToken, cfOpts...)
		dns = dnssync.New(cf, st)
		dns.Host = dnssync.HostSpec{Name: cfg.Host, IP: cfg.HostIP, Zone: cfg.HostZone}
		go func() { // never blocks startup; failures show on the dashboard card
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := dns.ReconcileHost(ctx, false); err != nil {
				slog.Error("ui host dns", "error", err)
			}
		}()
	} else {
		slog.Info("CLOUDFLARE_API_TOKEN is not set: no DNS management, certificates use HTTP-01/TLS-ALPN (ports 80 and 443 must be reachable from the internet)")
	}
	ui := web.New(web.Deps{Cfg: cfg, Store: st, Apply: svc, CF: cf, DNS: dns, Probe: mon, Logs: caddylog.Sink})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ui.VerifyToken(ctx)
	}()
	srv := newUIServer(cfg.UIListen, ui.Handler())
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("servanago started", "ui_listen", cfg.UIListen, "host", cfg.Host)

	select {
	case err := <-errc:
		return fmt.Errorf("ui server: %w", err)
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("ui shutdown: %w", err)
	}
	return nil
}

// newUIServer bounds every phase of a connection: UI_LISTEN can be exposed for recovery, where a
// slow client must not hold a connection open forever. WriteTimeout leaves room for a probe round.
func newUIServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
}

// loopbackDial turns a listen address (maybe 0.0.0.0:8080) into the dial address Caddy proxies to.
func loopbackDial(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("UI_LISTEN %q: %w", listen, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
