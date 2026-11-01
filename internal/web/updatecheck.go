package web

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/servanago/servanago/internal/buildinfo"
	"github.com/servanago/servanago/internal/update"
)

// updatecheck.go: the weekly look for a newer ServanaGo release. It reads the signed manifest GitHub serves with
// the latest release, keeps the verified result and tells the admin. It installs nothing.

const updateCheckEvery = 7 * 24 * time.Hour

// updateResult is what the settings row keeps between checks.
type updateResult struct {
	Manifest update.Manifest `json:"manifest"`
	Notified string          `json:"notified,omitempty"` // the version already mailed
}

func (s *Server) runningVersion() string {
	if s.deps.Version != "" {
		return s.deps.Version
	}
	return buildinfo.Version
}

func (s *Server) updateKeys() []ed25519.PublicKey {
	if s.deps.UpdateKeys != nil {
		return s.deps.UpdateKeys
	}
	return update.Keys
}

func (s *Server) loadUpdate(ctx context.Context) (updateResult, int64) {
	js, at, err := s.deps.Store.UpdateCheck(ctx)
	var res updateResult
	if err != nil || js == "" || json.Unmarshal([]byte(js), &res) != nil {
		return updateResult{}, 0
	}
	return res, at
}

// runUpdateCheck fetches and verifies the latest manifest, stores it, and mails the admin once per new version.
func (s *Server) runUpdateCheck(ctx context.Context) error {
	if !s.deps.Cfg.UpdateCheck {
		return errors.New("the update check is turned off (SERVANAGO_UPDATE_CHECK=false)")
	}
	mf, err := s.httpGet(ctx, update.ManifestURL)
	if err != nil {
		return fmt.Errorf("release manifest: %w", err)
	}
	sig, err := s.httpGet(ctx, update.SigURL)
	if err != nil {
		return fmt.Errorf("release manifest signature: %w", err)
	}
	m, err := update.Verify(s.updateKeys(), mf, sig)
	if err != nil {
		return err
	}
	prev, _ := s.loadUpdate(ctx)
	res := updateResult{Manifest: m, Notified: prev.Notified}
	if update.Newer(s.runningVersion(), m.Version) && prev.Notified != m.Version {
		if err := s.mailRelease(ctx, m); err != nil {
			slog.Warn("update mail not sent", "error", err) // the page still shows it; try again at the next check
		} else {
			res.Notified = m.Version
		}
	}
	js, _ := json.Marshal(res)
	if err := s.deps.Store.SaveUpdateCheck(ctx, string(js), time.Now().Unix()); err != nil {
		return err
	}
	if prev.Manifest.Version != m.Version {
		s.auditSystem(ctx, "update.check", m.Version)
	}
	return nil
}

func (s *Server) mailRelease(ctx context.Context, m update.Manifest) error {
	set, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return err
	}
	if !set.MailReady() {
		return errors.New("email delivery is not set up")
	}
	body := fmt.Sprintf("ServanaGo %s is available (this host runs %s).\n\nRelease notes: %s\n\nOpen the Updates page in ServanaGo for the details. Nothing was changed.\n", m.Version, s.runningVersion(), m.NotesURL)
	// ponytail: as in the PHP notice, there is no admin address, so it goes to the MAIL FROM mailbox
	return s.sendMail(set.MailFrom, set.MailFrom, "ServanaGo: version "+m.Version+" is available", body)
}

// RunUpdateChecks checks once a week (and at start when the last check is older) until ctx ends. Off = no request.
func (s *Server) RunUpdateChecks(ctx context.Context) {
	if !s.deps.Cfg.UpdateCheck {
		return
	}
	for {
		if _, at := s.loadUpdate(ctx); time.Since(time.Unix(at, 0)) >= updateCheckEvery {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			if err := s.runUpdateCheck(cctx); err != nil {
				slog.Warn("update check failed", "error", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour): // the check itself only runs when a week has passed
		}
	}
}

type updatesView struct {
	Running, Latest string
	Manifest        update.Manifest
	Newer, Dev      bool
	Enabled         bool
	CheckedAt       string
}

func (s *Server) updatesPage(w http.ResponseWriter, r *http.Request) {
	res, at := s.loadUpdate(r.Context())
	v := updatesView{Running: s.runningVersion(), Manifest: res.Manifest, Latest: res.Manifest.Version, Enabled: s.deps.Cfg.UpdateCheck}
	v.Dev = v.Running == "dev"
	v.Newer = update.Newer(v.Running, v.Latest)
	if at > 0 {
		v.CheckedAt = time.Unix(at, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	s.render(w, "updates", http.StatusOK, page{Title: "Updates", Data: v})
}

func (s *Server) updatesCheckNow(w http.ResponseWriter, r *http.Request) {
	if err := s.runUpdateCheck(r.Context()); err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	hxRedirect(w, "/updates")
}
