package web

import (
	"context"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/dnssync"
	"github.com/servanago/servanago/internal/store"
)

func hostServer(t *testing.T) (*Server, *cfFake) {
	t.Helper()
	s, cf, _ := newDNSServer(t)
	s.deps.DNS.Host = dnssync.HostSpec{Name: "servanago.example.com", IP: "192.168.25.165"}
	return s, cf
}

func TestHostCardHiddenWhenUnconfigured(t *testing.T) {
	s, _, _ := newDNSServer(t)
	if body := s.do(req{path: "/"}).Body.String(); strings.Contains(body, "UI host") {
		t.Error("card shown without SERVANAGO_HOST_IP")
	}
}

func TestHostCardShowsStateAndResyncs(t *testing.T) {
	s, cf := hostServer(t)
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, "servanago.example.com") || !strings.Contains(body, "192.168.25.165") || !strings.Contains(body, "pending") {
		t.Fatalf("pending card: %s", body)
	}
	if w := s.do(req{method: "POST", path: "/host/dns/resync", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("resync: %d %q", w.Code, w.Body.String())
	}
	if recs := cf.dns.Records(); len(recs) != 1 || recs[0].Name != "servanago.example.com" || recs[0].Content != "192.168.25.165" {
		t.Fatalf("%+v", recs)
	}
	if body := s.do(req{path: "/"}).Body.String(); !strings.Contains(body, "synced") {
		t.Errorf("card not synced: %s", body)
	}
}

func TestHostConflictTakeOver(t *testing.T) {
	s, cf := hostServer(t)
	cf.dns.Seed("servanago.example.com", "192.168.25.99")
	s.do(req{method: "POST", path: "/host/dns/resync", hdr: htmxPost})
	body := s.do(req{path: "/"}).Body.String()
	if !strings.Contains(body, "conflict") || !strings.Contains(body, "/host/dns/takeover") {
		t.Fatalf("conflict card: %s", body)
	}
	if w := s.do(req{method: "POST", path: "/host/dns/takeover", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("takeover: %d", w.Code)
	}
	row, err := s.deps.Store.GetUIDNS(context.Background(), store.FamilyA)
	if err != nil || row.State != "synced" || !row.Owned || cf.dns.Records()[0].Content != "192.168.25.165" {
		t.Fatalf("%+v %v", row, err)
	}
}

func TestHostEndpointsNeedLoginAndCSRF(t *testing.T) {
	s := newServer(t, "pw")
	if w := s.do(req{method: "POST", path: "/host/dns/resync", hdr: htmxPost}); w.Code != 401 && w.Code != 303 {
		t.Errorf("unauthenticated: %d", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/host/dns/resync"}); w.Code != 403 {
		t.Errorf("no HX-Request: %d", w.Code)
	}
}
