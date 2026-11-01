package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/updatejob"
)

// upgradeRig is an update server (latest 0.19.0, with a schema change) whose helper records update-start requests.
type upgradeRig struct {
	*Server
	cookie *http.Cookie
	mu     sync.Mutex
	asked  []helper.Spec
}

func newUpgradeRig(t *testing.T, running string) *upgradeRig {
	t.Helper()
	s, _, c := updateServer(t, running, "0.19.0")
	r := &upgradeRig{Server: s, cookie: c}
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "h.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go helper.Serve(ln, func(helper.Peer) bool { return true }, map[string]helper.Action{
		helper.ActionUpdateStart: func(q helper.Request) helper.Response {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.asked = append(r.asked, q.Vals)
			return helper.Response{OK: true}
		},
	})
	s.deps.HelperSocket = ln.Addr().String()
	s.deps.UpdateDir = t.TempDir()
	if err := s.runUpdateCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *upgradeRig) upgrade(kv ...string) *httptest.ResponseRecorder {
	return r.do(req{method: "POST", path: "/updates/upgrade", body: form(kv...).Encode(), hdr: htmxPost, cookies: []*http.Cookie{r.cookie}})
}

func (r *upgradeRig) page() string {
	return r.do(req{path: "/updates", cookies: []*http.Cookie{r.cookie}}).Body.String()
}

func (r *upgradeRig) requests() []helper.Spec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]helper.Spec(nil), r.asked...)
}

func (r *upgradeRig) writeState(t *testing.T, name string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(filepath.Join(r.deps.UpdateDir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeAsksTheHelperAndAudits(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	w := r.upgrade("version", "0.19.0", "password", "pw", "ack", "1")
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/updates" {
		t.Fatalf("%d %s %v", w.Code, w.Body.String(), w.Header())
	}
	got := r.requests()
	if len(got) != 1 || got[0].UpdateVersion != "0.19.0" || got[0].Actor != "admin" {
		t.Fatalf("helper asked %+v", got)
	}
	found := false
	for _, e := range auditRows(t, r.Server) {
		found = found || (e.Action == "update.start" && e.Target == "0.19.0" && e.Actor == "admin")
	}
	if !found {
		t.Fatal("no update.start audit row")
	}
}

func TestUpgradeRefusals(t *testing.T) {
	cases := []struct {
		name    string
		running string
		setup   func(t *testing.T, r *upgradeRig)
		kv      []string
		code    int
		want    string
	}{
		{"no password", "0.18.0", nil, []string{"version", "0.19.0", "ack", "1"}, 401, "Wrong password"},
		{"wrong password", "0.18.0", nil, []string{"version", "0.19.0", "ack", "1", "password", "nope"}, 401, "Wrong password"},
		{"schema change without the box ticked", "0.18.0", nil, []string{"version", "0.19.0", "password", "pw"}, 400, "tick the box"},
		{"a version that is not the latest checked", "0.18.0", nil, []string{"version", "0.20.0", "password", "pw", "ack", "1"}, 409, "latest checked release"},
		{"no version", "0.18.0", nil, []string{"password", "pw", "ack", "1"}, 409, "latest checked release"},
		{"already on it", "0.19.0", nil, []string{"version", "0.19.0", "password", "pw", "ack", "1"}, 409, "not newer"},
		{"build from source", "dev", nil, []string{"version", "0.19.0", "password", "pw", "ack", "1"}, 400, "from source"},
		{"a job is running", "0.18.0", func(t *testing.T, r *upgradeRig) {
			r.writeState(t, "state.json", updatejob.State{Phase: "install", From: "0.18.0", To: "0.19.0", Started: time.Now().UTC().Format(time.RFC3339)})
		}, []string{"version", "0.19.0", "password", "pw", "ack", "1"}, 409, "already running"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newUpgradeRig(t, c.running)
			if c.setup != nil {
				c.setup(t, r)
			}
			w := r.upgrade(c.kv...)
			if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
				t.Fatalf("%d %q, want %d containing %q", w.Code, w.Body.String(), c.code, c.want)
			}
			if n := len(r.requests()); n != 0 {
				t.Fatalf("the helper was asked %d times", n)
			}
		})
	}
}

func TestStaleStateIsNotAJob(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	r.writeState(t, "state.json", updatejob.State{Phase: "install", Started: time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)})
	if w := r.upgrade("version", "0.19.0", "password", "pw", "ack", "1"); w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestUpdatesPageOffersTheButton(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	body := r.page()
	for _, want := range []string{"Upgrade to 0.19.0", `name="ack"`, `name="password"`, `name="version" value="0.19.0"`, "</form>", "</article>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(r.Server.runningVersion(), "dev") {
		t.Fatal("test setup")
	}
}

func TestUpdatesPageOnASourceBuildHasNoButton(t *testing.T) {
	r := newUpgradeRig(t, "dev")
	if body := r.page(); strings.Contains(body, "Upgrade to") || !strings.Contains(body, "</article>") {
		t.Fatalf("source build page:\n%s", body)
	}
}

func TestUpdatesPageShowsProgressAndOutcome(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	r.writeState(t, "state.json", updatejob.State{Phase: "download", Message: "downloading 0.19.0", From: "0.18.0", To: "0.19.0", Started: time.Now().UTC().Format(time.RFC3339)})
	body := r.page()
	if !strings.Contains(body, "Upgrading to 0.19.0") || !strings.Contains(body, `hx-trigger="every 3s"`) || strings.Contains(body, "Upgrade to 0.19.0") {
		t.Fatalf("progress page:\n%s", body)
	}
	for res, want := range map[string]string{
		`{"ok":true,"from":"0.18.0","to":"0.19.0","at":"t"}`:                            "finished",
		`{"ok":false,"rolledback":true,"from":"0.18.0","to":"0.19.0","error":"health"}`: "was put back",
		`{"ok":false,"needs_hands":true,"from":"0.18.0","to":"0.19.0","error":"x"}`:     "NEEDS_HANDS.txt",
		`{"ok":false,"from":"0.18.0","to":"0.19.0","error":"no rollback possible"}`:     "nothing was changed",
	} {
		_ = os.Remove(filepath.Join(r.deps.UpdateDir, "state.json"))
		if err := os.WriteFile(filepath.Join(r.deps.UpdateDir, "result.json"), []byte(res), 0o600); err != nil {
			t.Fatal(err)
		}
		if body := r.page(); !strings.Contains(body, want) || !strings.Contains(body, "</article>") {
			t.Errorf("result %s: page lacks %q:\n%s", res, want, body)
		}
	}
}

func TestResumeUpdateAuditsTheOutcomeOnce(t *testing.T) {
	cases := []struct{ result, action, actor string }{
		{`{"ok":true,"from":"0.18.0","to":"0.19.0","actor":"brian"}`, "update.completed", "brian"},
		{`{"ok":false,"rolledback":true,"from":"0.18.0","to":"0.19.0","actor":"brian","error":"e"}`, "update.rolledback", "brian"},
		{`{"ok":false,"needs_hands":true,"from":"0.18.0","to":"0.19.0","error":"e"}`, "update.needs_hands", "system"},
		{`{"ok":false,"from":"0.18.0","to":"0.19.0","actor":"brian","error":"e"}`, "update.failed", "brian"},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			r := newUpgradeRig(t, "0.18.0")
			path := filepath.Join(r.deps.UpdateDir, "result.json")
			if err := os.WriteFile(path, []byte(c.result), 0o600); err != nil {
				t.Fatal(err)
			}
			before := len(auditRows(t, r.Server))
			r.ResumeUpdate(context.Background())
			r.ResumeUpdate(context.Background()) // the second start must not log it again
			rows := auditRows(t, r.Server)
			if len(rows) != before+1 {
				t.Fatalf("want one new row, got %d: %+v", len(rows)-before, rows)
			}
			if e := rows[0]; e.Action != c.action || e.Actor != c.actor || e.Target != "0.18.0 to 0.19.0" {
				t.Fatalf("row %+v", e)
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatal("result.json not renamed")
			}
			if _, err := os.Stat(path + ".seen"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResumeUpdateWithoutAResultDoesNothing(t *testing.T) {
	r := newUpgradeRig(t, "0.18.0")
	before := len(auditRows(t, r.Server))
	r.ResumeUpdate(context.Background())
	if len(auditRows(t, r.Server)) != before {
		t.Fatal("a row appeared from nothing")
	}
}
