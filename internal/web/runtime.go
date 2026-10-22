package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 60*time.Second)
	defer cancel()
	mk := userMake{}
	if rt.SiteUser != "" && r.PostForm.Get("user_mode") == "create" { // only a new user needs the home and shell choice
		if mk.Home = strings.TrimSpace(r.PostForm.Get("user_home")); mk.Home == "" {
			mk.Home = "/home/" + rt.SiteUser
		}
		mk.Shell = r.PostForm.Get("shell_login") != ""
	}
	return s.applyRuntimeWith(ctx, rt, nil, mk)
}

// userMake is what creating a site's user needs beyond the site: its home and whether it gets a login shell.
type userMake struct {
	Home  string
	Shell bool
}

// applyRuntime is runtimeApply without a request. A php site normally runs the build its label resolves to;
// force names another one (a PHP switch and its revert).
func (s *Server) applyRuntime(ctx context.Context, rt store.Site, force *runtimes.PHPVersion) error {
	return s.applyRuntimeWith(ctx, rt, force, userMake{})
}

func (s *Server) applyRuntimeWith(ctx context.Context, rt store.Site, force *runtimes.PHPVersion, mk userMake) error {
	if !rt.IsRuntime() {
		return nil
	}
	hc := s.helperClient()
	install := helper.Spec{Slug: rt.Slug, Kind: rt.Kind, Root: rt.StaticRoot, User: rt.SiteUser, Public: rt.PublicDir}
	switch rt.Kind {
	case "static": // nothing more than the user and folders
	case "node":
		install.Port, install.Start = rt.UpstreamPort, rt.StartCommand
	case "frankenphp":
		fr := s.detect(ctx).Franken
		if !fr.Installed {
			return errors.New("frankenphp is not installed on this host")
		}
		install.Port, install.FrankenBin = rt.UpstreamPort, fr.Path
	case "cgi":
		fw := s.detect(ctx).FCGIWrap
		if !fw.Installed {
			return errors.New("fcgiwrap is not installed on this host")
		}
		install.FCGIBin = fw.Path
	default: // the helper needs the exact binary; the pinned label resolves to one (a pruned build falls back to its branch)
		v := runtimes.PHPVersion{}
		if force != nil {
			v = *force
		} else {
			var ok bool
			if v, _, ok = runtimes.Resolve(rt.FPMVersion, s.detect(ctx).PHP); !ok {
				return fmt.Errorf("php-fpm %s is not installed on this host", rt.FPMVersion)
			}
		}
		install.FPMBin, install.FPMVersion = v.Path, v.Version
		if v.Source { // distro builds keep their own php.ini, so the selection only applies to ServanaGo's builds
			install.Extensions = strings.Fields(rt.PHPExtensions)
		}
	}
	added, err := hc.Call(ctx, helper.ActionUserAdd, helper.Spec{Slug: rt.Slug, Root: rt.StaticRoot, User: rt.SiteUser, Home: mk.Home, Shell: mk.Shell, Public: rt.PublicDir})
	if err != nil {
		return fmt.Errorf("site user: %w", err)
	}
	if _, err := hc.Call(ctx, helper.ActionUnitInstall, install); err != nil {
		return err
	}
	// A php site's user gets the site's PHP on the command line (when the user can log in). A failure here is
	// reported after the unit is started: the site itself is fine.
	var cliErr error
	if rt.Kind == "php" && rt.SiteUser != "" && added.User != nil && added.User.Login {
		if _, err := hc.Call(ctx, helper.ActionPHPUserDefault, helper.Spec{User: rt.SiteUser, PHPVersion: rt.FPMVersion, Slug: rt.Slug}); err != nil {
			cliErr = fmt.Errorf("command-line php for %s: %w", rt.SiteUser, err)
		}
	}
	if !rt.Enabled { // a disabled runtime site has a stopped unit
		if _, err := hc.Call(ctx, helper.ActionUnitStop, helper.Spec{Slug: rt.Slug}); err != nil {
			return err
		}
		return cliErr
	}
	if _, err := hc.Call(ctx, helper.ActionUnitStart, helper.Spec{Slug: rt.Slug}); err != nil {
		return err
	}
	return cliErr
}

// unitPanel is what the edit page shows for a node or php site: the unit's state and its journal tail.
type unitPanel struct {
	State string   // "active (running)"
	PID   string   // main process id, "" when none
	Logs  []string // newest last; the app's own output, so it is only ever rendered escaped
	Err   string   // why the panel is empty: helper unreachable or unit unknown
}

// unitPanelFor asks the helper for the unit's status and journal tail. Any failure becomes a note in the
// panel: the edit page must render even when the helper is down.
func (s *Server) unitPanelFor(r *http.Request, rt store.Site) *unitPanel {
	if !rt.IsRuntime() {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	hc := s.helperClient()
	st, err := hc.Call(ctx, helper.ActionUnitStatus, helper.Spec{Slug: rt.Slug})
	if err != nil || st.Status == nil {
		return &unitPanel{Err: fmt.Sprintf("The ServanaGo helper could not report this unit's state (%v). Check `systemctl status servanago-helper`.", err)}
	}
	p := &unitPanel{State: st.Status.ActiveState + " (" + st.Status.SubState + ")"}
	if st.Status.PID != "" && st.Status.PID != "0" {
		p.PID = st.Status.PID
	}
	if lg, err := hc.Call(ctx, helper.ActionUnitLogs, helper.Spec{Slug: rt.Slug, Lines: 30}); err == nil {
		p.Logs = lg.Logs
	}
	return p
}

// runtimeRemove tears down a runtime site's unit and user; missing files are fine.
func (s *Server) runtimeRemove(r *http.Request, rt store.Site) {
	if !rt.IsRuntime() {
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
	if rt.SiteUser != "" { // a named user stays for the admin to remove; only its command-line php is cleared
		if rt.Kind == "php" {
			if _, err := hc.Call(ctx, helper.ActionPHPUserDefault, helper.Spec{User: rt.SiteUser}); err != nil {
				slog.Warn("clear command-line php", "user", rt.SiteUser, "error", err) // a user without a login shell never had one
			}
		}
		return
	}
	if _, err := hc.Call(ctx, helper.ActionUserRemove, helper.Spec{Slug: rt.Slug}); err != nil {
		slog.Error("remove site user", "slug", rt.Slug, "error", err)
		s.flash(fmt.Sprintf("Could not remove the site user for %s: %v", rt.Hostnames[0], err))
	}
}
