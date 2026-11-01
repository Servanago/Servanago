package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/store"
	"github.com/servanago/servanago/internal/update"
	"github.com/servanago/servanago/internal/updatejob"
)

// upgrade.go: the Upgrade button and what comes back from the job. The panel starts nothing itself: it asks the helper
// (action update-start), which verifies the signed release again and starts the root job. The job reports through
// state.json (progress) and result.json (the outcome, audited here at the next start).

const staleJob = 2 * time.Hour // a state file older than this with no result is a dead job, not a running one

func (s *Server) updateDir() string {
	if s.deps.UpdateDir != "" {
		return s.deps.UpdateDir
	}
	return helper.UpdateJobDir
}

func readJSON(path string, v any) bool {
	b, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(b, v) == nil
}

// upgradeState reports the job's progress file and whether a job is still running.
func (s *Server) upgradeState() (st updatejob.State, running bool) {
	if !readJSON(filepath.Join(s.updateDir(), "state.json"), &st) {
		return st, false
	}
	started, err := time.Parse(time.RFC3339, st.Started)
	return st, st.Phase != "done" && st.Phase != "failed" && err == nil && time.Since(started) < staleJob
}

// lastUpgrade is the newest outcome: not yet audited (result.json) or already audited (result.json.seen).
func (s *Server) lastUpgrade() (res updatejob.Result, ok bool) {
	for _, n := range []string{"result.json", "result.json.seen"} {
		if readJSON(filepath.Join(s.updateDir(), n), &res) {
			return res, true
		}
	}
	return res, false
}

// startUpgrade is the check shared by the button and the MCP tool. The status is the HTTP code for a refusal.
func (s *Server) startUpgrade(ctx context.Context, version string, ack bool, actor string) (int, error) {
	running := s.runningVersion()
	if !update.Newer("0.0.0", running) { // not X.Y.Z (or 0.0.0): a source build
		return http.StatusBadRequest, errors.New("this is a build from source; it is never upgraded from here")
	}
	res, _ := s.loadUpdate(ctx)
	m := res.Manifest
	if m.Version == "" || version != m.Version {
		return http.StatusConflict, fmt.Errorf("the latest checked release is %q, not %q: use Check now first", m.Version, version)
	}
	if !update.Newer(running, m.Version) {
		return http.StatusConflict, fmt.Errorf("%s is not newer than the running %s", m.Version, running)
	}
	if (m.SchemaChange || m.Breaking) && !ack {
		return http.StatusBadRequest, errors.New("this release changes the database or needs an action from you: read the release notes and tick the box to confirm")
	}
	if _, busy := s.upgradeState(); busy {
		return http.StatusConflict, errors.New("an upgrade is already running")
	}
	if _, err := s.helperClient().Call(ctx, helper.ActionUpdateStart, helper.Spec{UpdateVersion: m.Version, Actor: actor}); err != nil {
		return http.StatusBadGateway, err
	}
	return 0, nil
}

func (s *Server) upgradeNow(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.confirm(w, r) {
		return
	}
	version := r.PostFormValue("version")
	if code, err := s.startUpgrade(r.Context(), version, r.PostFormValue("ack") != "", helperActor(r)); err != nil {
		fail(w, code, err.Error())
		return
	}
	s.audit(r, "update.start", version)
	s.flash("Upgrade to " + version + " started. The panel restarts in a minute; this page shows the progress.")
	hxRedirect(w, "/updates")
}

// ResumeUpdate turns a finished job's result into an audit row, once. It runs at start, because the upgrade (or the
// rollback) restarted this process: the log then shows what really happened, not what was intended.
func (s *Server) ResumeUpdate(ctx context.Context) {
	path := filepath.Join(s.updateDir(), "result.json")
	var res updatejob.Result
	if s.deps.Store == nil || !readJSON(path, &res) {
		return
	}
	action := "update.failed"
	switch {
	case res.OK:
		action = "update.completed"
	case res.NeedsHands:
		action = "update.needs_hands"
	case res.RolledBack:
		action = "update.rolledback"
	}
	actor := res.Actor
	if actor == "" {
		actor = "system"
	}
	e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action, Target: tidy(res.From+" to "+res.To, 200)}
	if err := s.deps.Store.AddAudit(context.WithoutCancel(ctx), e); err != nil {
		slog.Error("write audit row", "action", action, "error", err)
		return // the file stays; the next start tries again
	}
	if err := os.Rename(path, path+".seen"); err != nil {
		slog.Error("mark the upgrade result as seen", "error", err)
	}
}
