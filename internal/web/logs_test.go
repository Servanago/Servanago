package web

import (
	"strings"
	"testing"

	"github.com/caretakarr/caretakarr/internal/caddylog"
)

func TestLogsPageAndFilter(t *testing.T) {
	s, _, _ := newDNSServer(t)
	ring := caddylog.NewRing(10)
	_, _ = ring.Write([]byte(`{"level":"info","ts":1791978000,"logger":"http","msg":"server running"}` + "\n"))
	_, _ = ring.Write([]byte(`{"level":"error","ts":1791978001,"logger":"tls.obtain","msg":"will retry","error":"dns challenge <failed>"}` + "\n"))
	s.deps.Logs = ring

	page := s.do(req{path: "/logs"}).Body.String()
	for _, want := range []string{"server running", "will retry", "tls.obtain", `hx-get="/logs/rows"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(page, "<failed>") || !strings.Contains(page, "&lt;failed&gt;") {
		t.Error("log text must be HTML-escaped")
	}

	rows := s.do(req{path: "/logs/rows?level=error", hdr: map[string]string{"HX-Request": "true"}}).Body.String()
	if strings.Contains(rows, "<html") || strings.Contains(rows, "server running") || !strings.Contains(rows, "will retry") {
		t.Errorf("filter wrong: %s", rows)
	}
}

func TestLogsRequireLogin(t *testing.T) {
	s := newServer(t, "pw")
	for _, p := range []string{"/logs", "/logs/rows"} {
		if w := s.do(req{path: p}); w.Code != 303 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
}
