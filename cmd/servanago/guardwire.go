package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/servanago/servanago/internal/alerts"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/trafficdb"
	"github.com/servanago/servanago/internal/turnstile"
)

// guardRuntime is everything the protection layers need at runtime; main installs it before Caddy loads.
type guardRuntime struct {
	Svc      *guard.Service
	Traffic  *trafficdb.DB // nil when traffic.db could not be opened: traffic features degrade, nothing else
	Notifier *alerts.Notifier
	Sender   *alerts.Sender
}

func wireGuard(cfg config.Config, st *store.Store) *guardRuntime {
	rt := &guardRuntime{Svc: guard.New(cfg.SecretKey, st)}
	if db, err := trafficdb.Open(filepath.Join(cfg.DataDir, "traffic.db")); err != nil {
		slog.Error("traffic.db unavailable: request log and rollups are off", "error", err)
	} else {
		rt.Traffic = db
		rt.Svc.UseDB(db)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rt.Svc.Reload(ctx, st, cfg.SecretKey); err != nil {
		slog.Error("guard settings", "error", err)
	}
	if err := rt.Svc.LoadBans(ctx); err != nil {
		slog.Error("load bans", "error", err)
	}
	rt.Svc.TurnstileSiteKey = cfg.TurnstileSiteKey
	if cfg.TurnstileSecret != "" && cfg.TurnstileSiteKey != "" {
		rt.Svc.Turnstile = func(ctx context.Context, token, ip, host string) error {
			return turnstile.Verify(ctx, cfg.TurnstileBaseURL, cfg.TurnstileSecret, token, ip, "challenge", host)
		}
	}
	rt.Svc.OnAudit = func(action, target string) {
		e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: "system", Action: action, Target: target}
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := st.AddAudit(c, e); err != nil {
			slog.Warn("audit write failed", "action", action, "error", err)
		}
	}
	rt.Sender = &alerts.Sender{Mail: alerts.MailSource(st, cfg.SecretKey)}
	rt.Notifier = alerts.NewNotifier(rt.Sender)
	rt.Notifier.Resolve = alerts.StoreResolver(st, cfg.SecretKey)
	rt.Notifier.Result = alerts.StoreResult(st)
	rt.Svc.OnAlert = func(e guard.Event) {
		rt.Notifier.Notify(alerts.Event{Kind: e.Kind, Site: e.Site, Key: e.Key, Text: e.Text})
	}
	guard.Install(rt.Svc)
	return rt
}

func (rt *guardRuntime) start(ctx context.Context) {
	go rt.Svc.Run(ctx)
	go rt.Notifier.Run(ctx)
}
