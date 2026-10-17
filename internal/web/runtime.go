package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/store"
)

// runtime.go: the privileged steps a node/php site needs, sent to the helper after the DB change.
// Every step is best-effort: a failure is a one-time notice and an audit row, never a stuck form —
// the site stays in SQLite as desired state and the next start reconciles the host.

// helperClient dials the helper at its socket (Deps.HelperSocket overrides it in tests).
func (s *Server) helperClient() *helper.Client {
	if s.deps.HelperSocket != "" {
		return helper.NewClient(s.deps.HelperSocket)
	}
	return helper.NewClient(helper.SocketPath)
}

// detect reports the host's runtimes through Deps.Exec (nil = the real host).
func (s *Server) detect(ctx context.Context) runtimes.Report {
	if s.deps.Exec != nil {
		return runtimes.Detect(ctx, s.deps.Exec)
	}
	return runtimes.Detect(ctx, runtimes.OsExec{})
}

// runtimeApply installs (and starts, when enabled) a runtime site's user and unit.
func (s *Server) runtimeApply(r *http.Request, rt store.Site) error {
	if rt.Kind != "node" && rt.Kind != "php" {
		return nil
	}
	hc := s.helperClient()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 60*time.Second)
	defer cancel()
	install := helper.Spec{Slug: rt.Slug, Kind: rt.Kind, Root: rt.StaticRoot}
	if rt.Kind == "node" {
		install.Port, install.Start = rt.UpstreamPort, rt.StartCommand
	} else { // the helper needs the exact binary; the version label was validated against detection
		rep := s.detect(ctx)
		for _, v := range rep.PHP {
			if v.Version == rt.FPMVersion {
				install.FPMBin, install.FPMVersion = v.Path, v.Version
				break
			}
		}
		if install.FPMBin == "" {
			return fmt.Errorf("php-fpm %s is not installed on this host", rt.FPMVersion)
		}
	}
	if _, err := hc.Call(ctx, helper.ActionUserAdd, helper.Spec{Slug: rt.Slug, Root: rt.StaticRoot}); err != nil {
		return fmt.Errorf("site user: %w", err)
	}
	if _, err := hc.Call(ctx, helper.ActionUnitInstall, install); err != nil {
		return err
	}
	if !rt.Enabled { // a disabled runtime site has a stopped unit
		if _, err := hc.Call(ctx, helper.ActionUnitStop, helper.Spec{Slug: rt.Slug}); err != nil {
			return err
		}
		return nil
	}
	if _, err := hc.Call(ctx, helper.ActionUnitStart, helper.Spec{Slug: rt.Slug}); err != nil {
		return err
	}
	return nil
}

// runtimeRemove tears down a runtime site's unit and user; missing files are fine.
func (s *Server) runtimeRemove(r *http.Request, rt store.Site) {
	if rt.Kind != "node" && rt.Kind != "php" {
		return
	}
	hc := s.helperClient()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
	defer cancel()
	if _, err := hc.Call(ctx, helper.ActionUnitRemove, helper.Spec{Slug: rt.Slug}); err != nil {
		slog.Error("remove site unit", "slug", rt.Slug, "error", err)
		s.flash(fmt.Sprintf("Could not remove the unit for %s: %v", rt.Hostnames[0], err))
		return
	}
	if _, err := hc.Call(ctx, helper.ActionUserRemove, helper.Spec{Slug: rt.Slug}); err != nil {
		slog.Error("remove site user", "slug", rt.Slug, "error", err)
		s.flash(fmt.Sprintf("Could not remove the site user for %s: %v", rt.Hostnames[0], err))
	}
}
