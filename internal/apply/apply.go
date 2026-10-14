// Package apply is the only path that changes configuration: tx, render, caddy.Load, commit or roll back.
package apply

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/caddyserver/caddy/v2"

	"github.com/caretakarr/caretakarr/internal/caddycfg"
	"github.com/caretakarr/caretakarr/internal/store"
)

type Service struct {
	// ponytail: global mutex; per-domain locks if concurrent admin edits ever matter.
	mu         sync.Mutex
	store      *store.Store
	opts       caddycfg.Options
	load       func(cfg []byte, force bool) error // caddy.Load; replaced in tests to count calls
	current    []byte
	startupErr error
}

func New(s *store.Store, o caddycfg.Options) *Service {
	return &Service{store: s, opts: o, load: caddy.Load}
}

// StartupError is non-nil when the DB-rendered config was rejected and only the bootstrap config is live.
func (s *Service) StartupError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startupErr
}

// Start loads the config rendered from the DB, falling back to the bootstrap-only config on failure.
// It returns an error only if even the bootstrap config cannot be loaded.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.render(ctx, s.store)
	if err == nil {
		err = s.loadCfg(cfg)
	}
	if err == nil {
		return nil
	}
	slog.Error("stored config rejected, loading bootstrap config", "error", err)
	s.startupErr = err
	boot, rerr := caddycfg.Render(caddycfg.State{}, s.opts)
	if rerr != nil {
		return fmt.Errorf("render bootstrap config: %w", rerr)
	}
	if lerr := s.loadCfg(boot); lerr != nil {
		return fmt.Errorf("load bootstrap config: %w", lerr)
	}
	return nil
}

// Mutate runs fn inside a transaction, then renders and loads the resulting config.
// If Caddy rejects it the transaction is rolled back and the previous config stays live.
func (s *Service) Mutate(ctx context.Context, fn func(tx *store.Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded := false
	err := s.store.Tx(ctx, func(tx *store.Store) error {
		if err := fn(tx); err != nil {
			return err
		}
		cfg, err := s.render(ctx, tx)
		if err != nil {
			return err
		}
		if err := s.loadCfg(cfg); err != nil {
			return fmt.Errorf("caddy rejected config: %w", err)
		}
		loaded = true
		return nil
	})
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
	rs, err := q.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	return caddycfg.Render(caddycfg.State{Domains: ds, Routes: rs}, s.opts)
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
	return nil
}
