package web

import (
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

func okRow() siteRow {
	return siteRow{
		Site:     store.Site{Enabled: true, Hostnames: []string{"a.example.net"}},
		Host:     "a.example.net",
		Probed:   true,
		Upstream: "up",
		Cert:     probe.CertStatus{State: probe.StateIssued, NotAfter: time.Now().Add(90 * 24 * time.Hour)},
	}
}

func TestSiteHealthRollsUpTheWorstProblem(t *testing.T) {
	dns := func(state string) []store.DNSRecord { return []store.DNSRecord{{State: state}} }
	tests := []struct {
		name  string
		edit  func(*siteRow)
		level string
		label string
	}{
		{"all good", func(*siteRow) {}, "ok", "Healthy"},
		{"disabled hides every other problem", func(r *siteRow) { r.Enabled = false; r.Cert.State = probe.StateError }, "off", "Disabled"},
		{"certificate error", func(r *siteRow) { r.Cert.State = probe.StateError }, "bad", "Certificate error"},
		{"dns error", func(r *siteRow) { r.DNS = dns("error") }, "bad", "DNS error"},
		{"upstream down", func(r *siteRow) { r.Upstream = "down" }, "bad", "Upstream down"},
		{"container stopped", func(r *siteRow) { r.Docker = &helper.Container{State: "exited"} }, "bad", "Container down"},
		{"dns conflict", func(r *siteRow) { r.DNS = dns("conflict") }, "warn", "DNS conflict"},
		{"certificate pending", func(r *siteRow) { r.Cert.State = probe.StatePending }, "warn", "Waiting for certificate"},
		{"dns pending", func(r *siteRow) { r.DNS = dns("pending") }, "warn", "Waiting for DNS"},
		{"certificate expiring", func(r *siteRow) { r.CertSoon = true }, "warn", "Certificate expiring"},
		{"error outranks conflict", func(r *siteRow) { r.DNS = dns("conflict"); r.Upstream = "down" }, "bad", "Upstream down"},
		{"not probed yet", func(r *siteRow) { r.Probed = false; r.Cert = probe.CertStatus{} }, "wait", "Checking"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := okRow()
			tc.edit(&r)
			if h := r.Health(); h.Level != tc.level || h.Label != tc.label {
				t.Errorf("got %+v, want level %q label %q", h, tc.level, tc.label)
			}
		})
	}
}

func TestNeedsAttentionListsOnlyWarnAndBad(t *testing.T) {
	bad, warn, off := okRow(), okRow(), okRow()
	bad.Upstream = "down"
	warn.CertSoon = true
	off.Enabled = false
	got := needsAttention([]siteRow{okRow(), bad, warn, off})
	if len(got) != 2 || got[0].Upstream != "down" || !got[1].CertSoon {
		t.Errorf("got %d rows: %+v", len(got), got)
	}
}

func TestDashboardListsProblemsAndKeepsRowsOpenAcrossThePoll(t *testing.T) {
	s, _, d := newDNSServer(t)
	addRoute(t, s, d) // the fake dial refuses: the upstream is down
	body := s.do(req{path: "/"}).Body.String()
	for _, want := range []string{`class="attn"`, "Upstream down", `class="srow"`, "htmx:afterSwap", ">1 site<", ">Add site</a>", "</html>"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
}
