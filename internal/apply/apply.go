// Package apply is the only path that changes configuration: tx, render, caddy.Load, commit or roll back.
package apply

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/store"
)

type Service struct {
	// ponytail: global mutex; per-domain locks if concurrent admin edits ever matter.
	mu         sync.Mutex
	store      *store.Store
	opts       caddycfg.Options
	load       func(cfg []byte, force bool) error // caddy.Load; replaced in tests to count calls
	current    []byte
	startupErr error
	// lastGood holds the last successfully loaded config; startup prefers it over bootstrap-only.
	lastGood string
}

func New(s *store.Store, o caddycfg.Options) *Service {
	return &Service{store: s, opts: o, load: caddy.Load, lastGood: lastGoodPath(o)}
}

// lastGoodPath puts the file beside Caddy's storage dir, inside the data directory.
func lastGoodPath(o caddycfg.Options) string {
	return filepath.Join(filepath.Dir(o.StoragePath), "caddy-last-good.json")
}

// StartupError is non-nil when the DB-rendered config was rejected; the config now live is the
// last known good one, or the bootstrap-only one.
func (s *Service) StartupError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startupErr
}

// Start reconciles host state to the DB: it renders and loads the stored config, falling back to
// the last known good file, then to bootstrap-only. It returns an error only if even the
// bootstrap config cannot be loaded.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.render(ctx, s.store)
	if err == nil {
		err = s.loadCfg(cfg)
	}
	if err == nil {
		s.startupErr = nil
		return nil
	}
	slog.Error("stored config rejected", "error", err)
	// The DB config is unusable: try the last known good file before stripping every site.
	if restored := s.restoreLKG(); restored {
		s.startupErr = fmt.Errorf("stored config rejected: %w. Serving the last known-good configuration; fix or remove the entries below before saving again.", err)
		s.audit(ctx, "config.restored")
		return nil
	}
	s.startupErr = err
	b, rerr := caddycfg.Render(caddycfg.State{}, s.opts)
	if rerr != nil {
		return fmt.Errorf("render bootstrap config: %w", rerr)
	}
	if lerr := s.load(b, false); lerr != nil {
		return fmt.Errorf("load bootstrap config: %w", lerr)
	}
	s.current = b
	s.audit(ctx, "config.bootstrapped")
	return nil
}

// Mutate runs fn inside a transaction, then renders and loads the resulting config.
// If Caddy rejects it the transaction is rolled back and the previous config stays live.
func (s *Service) Mutate(ctx context.Context, fn func(tx *store.Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := false
	rejected := ""
	err := s.store.Tx(ctx, func(tx *store.Store) error {
		if err := fn(tx); err != nil {
			return err
		}
		cfg, err := s.render(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.loadCfg(cfg); err != nil {
			rejected = err.Error()
			return fmt.Errorf("caddy rejected config: %w", err)
		}
		loaded = true
		return nil
	})
	if rejected != "" {
		s.audit(ctx, "config.rejected")
	} else if err == nil && loaded {
		s.audit(ctx, "config.changed")
	}
	if err != nil && loaded {
		// Commit failed after a successful Load: put Caddy back in line with the DB.
		if cfg, rerr := s.render(ctx, s.store); rerr == nil {
			if lerr := s.loadCfg(cfg); lerr != nil {
				slog.Error("restore config after failed commit", "error", lerr)
			}
		}
	}
	return err
}

func (s *Service) render(ctx context.Context, q *store.Store) ([]byte, error) {
	ds, err := q.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := q.ListSites(ctx)
	if err != nil {
		return nil, err
	}
	return caddycfg.Render(caddycfg.State{Domains: ds, Sites: rs}, s.opts)
}

// loadCfg skips Caddy when the config is byte-identical to the live one.
func (s *Service) loadCfg(cfg []byte) error {
	if bytes.Equal(cfg, s.current) {
		return nil
	}
	if err := s.load(cfg, false); err != nil {
		return err
	}
	s.current = cfg
	s.saveLKG(cfg)
	return nil
}

// saveLKG records the last successfully loaded config; failures are logged, never fatal:
// a lost file costs only the bootstrap fallback.
func (s *Service) saveLKG(cfg []byte) {
	tmp := s.lastGood + ".tmp"
	if err := os.WriteFile(tmp, cfg, 0o644); err != nil {
		slog.Error("write last-known-good", "path", s.lastGood, "error", err)
		return
	}
	if err := os.Rename(tmp, s.lastGood); err != nil {
		slog.Error("commit last-known-good", "path", s.lastGood, "error", err)
	}
}

// restoreLKG loads the last-known-good config; false when it cannot be read or loaded.
func (s *Service) restoreLKG() bool {
	b, err := os.ReadFile(s.lastGood)
	if err != nil {
		return false
	}
	if err := s.load(b, false); err != nil {
		slog.Error("load last-known-good", "path", s.lastGood, "error", err)
		return false
	}
	s.current = b
	return true
}

// audit writes a system event to the audit log (the web UI writes its own rows); write failures
// are logged, never fail the configuration change itself.
func (s *Service) audit(ctx context.Context, action string) {
	e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: "system", Action: action, Target: "caddy"}
	if err := s.store.AddAudit(context.WithoutCancel(ctx), e); err != nil {
		slog.Error("write system audit row", "action", action, "error", err)
	}
}
