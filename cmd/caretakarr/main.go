// Command caretakarr runs the admin UI and an embedded Caddy configured from SQLite.
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

	"github.com/caretakarr/caretakarr/internal/apply"
	"github.com/caretakarr/caretakarr/internal/caddycfg"
	_ "github.com/caretakarr/caretakarr/internal/caddylog"
	"github.com/caretakarr/caretakarr/internal/cfdns"
	"github.com/caretakarr/caretakarr/internal/config"
	"github.com/caretakarr/caretakarr/internal/discovery"
	"github.com/caretakarr/caretakarr/internal/dnssync"
	"github.com/caretakarr/caretakarr/internal/probe"
	"github.com/caretakarr/caretakarr/internal/store"
	"github.com/caretakarr/caretakarr/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("caretakarr failed", "error", err)
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
	st, err := store.Open(filepath.Join(cfg.DataDir, "caretakarr.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	uiUpstream, err := loopbackDial(cfg.UIListen)
	if err != nil {
		return err
	}
	svc := apply.New(st, caddycfg.Options{
		UIHost: cfg.Host, UIUpstream: uiUpstream, Email: cfg.ACMEEmail, Staging: cfg.Staging,
		HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort, StoragePath: filepath.Join(cfg.DataDir, "caddy"),
		PropagationDelay: cfg.PropagationDelay, PropagationTimeout: cfg.PropagationTimeout, Resolvers: cfg.Resolvers,
	})
	if err := svc.Start(context.Background()); err != nil {
		return err
	}
	defer func() { _ = caddy.Stop() }()

	var cfOpts []option.RequestOption
	if cfg.CFBaseURL != "" {
		cfOpts = append(cfOpts, option.WithBaseURL(cfg.CFBaseURL))
	}
	cf := cfdns.New(cfg.CloudflareToken, cfOpts...)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mon := probe.NewMonitor(st, net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.HTTPSPort)))
	go mon.Run(ctx, 30*time.Second)
	ui := web.New(web.Deps{Cfg: cfg, Store: st, Apply: svc, CF: cf, DNS: dnssync.New(cf, st), Probe: mon,
		Docker: discovery.New(cfg.DockerSocket)})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ui.VerifyToken(ctx)
	}()
	srv := &http.Server{Addr: cfg.UIListen, Handler: ui.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("caretakarr started", "ui_listen", cfg.UIListen, "host", cfg.Host)

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
