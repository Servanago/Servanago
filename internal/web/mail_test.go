package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/servanago/servanago/internal/cfdns/cftest"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// pmStub is the Postmark account stub for the provisioning tests.
type pmStub struct {
	srv     *httptest.Server
	servers string // GET /servers body
	domains string // GET /domains body
	verifyD bool
	seen    map[string]string // last request bodies, by "METHOD path"; PUT /servers/{id} appends
	calls   []string          // every "METHOD path" in order
}

func newPMStub(t *testing.T, servers, domains string, verifyD bool) *pmStub {
	st := &pmStub{servers: servers, domains: domains, verifyD: verifyD, seen: map[string]string{}}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		st.calls = append(st.calls, key)
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/servers/") { // two server PUTs land here
			if st.seen[key] != "" {
				st.seen[key] += " | " + string(b)
			} else {
				st.seen[key] = string(b)
			}
		} else {
			st.seen[key] = string(b)
		}
		switch {
		case r.URL.Path == "/servers" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(st.servers))
		case r.URL.Path == "/servers" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"ID":500,"Name":"mail-mail.example.com","InboundAddress":"abc@inbound.postmarkapp.com"}`))
		case strings.HasPrefix(r.URL.Path, "/servers/") && r.Method == http.MethodPut:
			_, _ = w.Write([]byte(`{"ID":500}`))
		case r.URL.Path == "/domains" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(st.domains))
		case r.URL.Path == "/domains" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"ID":700,"Name":"mail.example.com","ReturnPathDomain":"pm-bounces.mail.example.com","DKIMPendingHost":"sel1._domainkey.mail.example.com","DKIMPendingTextValue":"v=DKIM1 p=PENDING"}`))
		case strings.HasPrefix(r.URL.Path, "/domains/700") && strings.Contains(r.URL.Path, "verifyReturnPath"):
			_, _ = w.Write([]byte(`{"ID":700,"ReturnPathDomainVerified":true}`))
		case strings.HasPrefix(r.URL.Path, "/domains/700") && strings.Contains(r.URL.Path, "verifyDkim"):
			_, _ = w.Write([]byte(`{"ID":700,"DKIMVerified":` + boolJSON(st.verifyD) + `}`))
		case strings.HasPrefix(r.URL.Path, "/domains/700"):
			_, _ = w.Write([]byte(`{"ID":700,"Name":"mail.example.com","ReturnPathDomain":"pm-bounces.mail.example.com","DKIMPendingHost":"sel1._domainkey.mail.example.com","DKIMPendingTextValue":"v=DKIM1 p=PENDING"}`))
		default:
			t.Errorf("unexpected Postmark call: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(st.srv.Close)
	return st
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// mailHarness is an open-mode server with the fake Cloudflare and a stubbed Postmark.
func mailHarness(t *testing.T, pm *pmStub) (*Server, *cftest.Fake) {
	t.Helper()
	cf := &cfFake{zones: dnsZonesBody}
	s := cfgServer(t, cf, config.Config{Host: "panel.example.test", SecretKey: strings.Repeat("k", 32)})
	s.pmBase = pm.srv.URL
	s.applyInline = true
	s.mailPoll, s.mailTries = time.Millisecond, 3
	ctx := context.Background()
	tok, err := secretbox.Seal(s.deps.Cfg.SecretKey, []byte("acctoken"))
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := s.deps.Store.GetSettings(ctx)
	cur.MailToken = tok
	if err := s.deps.Store.SaveSettings(ctx, cur); err != nil {
		t.Fatal(err)
	}
	return s, cf.dns
}

func mailSeedRow(t *testing.T, s *Server, md store.MailDomain) int64 {
	t.Helper()
	id, created, err := s.deps.Store.UpsertMailDomain(context.Background(), md)
	if err != nil || !created {
		t.Fatalf("seed row: created=%v %v", created, err)
	}
	return id
}

func TestMailPageEmptyAndWithoutCloudflare(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true)
	s, _ := mailHarness(t, pm)
	w := s.do(req{path: "/mail"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "No mail domains provisioned yet") {
		t.Fatalf("empty page: %d %s", w.Code, w.Body.String()[:minOf(len(w.Body.String()), 400)])
	}

	// no Cloudflare at all: the page explains what is missing (open mode, no CF wired)
	plain, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plain.Close() })
	none := New(Deps{Store: plain, Cfg: config.Config{}})
	w = none.do(req{path: "/mail"})
	if !strings.Contains(w.Body.String(), "needs the Cloudflare DNS feature") {
		t.Fatalf("no-CF page: %d %s", w.Code, w.Body.String()[:minOf(len(w.Body.String()), 400)])
	}
}

func minOf(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestMailProvisionCreatesEverything(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true)
	s, fd := mailHarness(t, pm)
	ctx := context.Background()

	w := s.do(req{method: "POST", path: "/mail/provision", body: postMailForm("mail.example.com", ""), hdr: htmxPost})
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/mail" {
		t.Fatalf("provision: %d %s %v", w.Code, w.Body.String(), w.Header())
	}
	if d, err := s.deps.Store.GetMailDomain(ctx, "mail.example.com"); err != nil || d.PMServerID != 500 || d.PMDomainID != 700 {
		t.Fatalf("row: %+v %v", d, err)
	} else if !strings.HasPrefix(d.HookUser, "mail") || len(d.HookPassHash) < 40 {
		t.Fatalf("credential: user %q hash %q", d.HookUser, d.HookPassHash)
	}
	// the shown-once flash carries the full URL with credentials and the password
	page := s.do(req{path: "/mail"}).Body.String()
	if !strings.Contains(page, "shown once") || !strings.Contains(page, "/_mailbridge/hook/mail.example.com") {
		t.Fatalf("flash missing the credential: %s", page)
	}
	if page2 := s.do(req{path: "/mail"}).Body.String(); strings.Contains(page2, "shown once") {
		t.Fatal("the credential flashed twice")
	}

	// the settings push carried the hooks
	push := pm.seen["PUT /servers/500"]
	for _, want := range []string{`"InboundHookUrl"`, `"RawEmailEnabled":true`, `"BounceHookUrl"`, `"IncludeBounceContentInHook":true`, `"EnableSmtpApiErrorHooks":true`} {
		if !strings.Contains(push, want) {
			t.Fatalf("server patch missing %s: %s", want, push)
		}
	}
	// the four DNS rows are written through the CRUD fake
	waitFor(t, 500*time.Millisecond, func() bool {
		rows, _ := s.deps.Store.GetMailDomain(ctx, "mail.example.com")
		return rows.DNSSetup != ""
	})
	wantTypes := map[string]bool{"MX": false, "CNAME": false, "TXT": false}
	for _, rec := range fd.Records() {
		switch rec.Type {
		case "MX":
			wantTypes["MX"] = rec.Content == "inbound.postmarkapp.com"
		case "CNAME":
			wantTypes["CNAME"] = rec.Content == "pm.mtasv.net"
		case "TXT":
			if strings.HasPrefix(rec.Name, "sel1.") {
				wantTypes["TXT"] = rec.Content == "v=DKIM1 p=PENDING"
			}
		}
	}
	if !wantTypes["MX"] || !wantTypes["CNAME"] || !wantTypes["TXT"] {
		t.Fatalf("dns rows: %+v", fd.Records())
	}
	// verification states land verified
	waitFor(t, 500*time.Millisecond, func() bool {
		d, _ := s.deps.Store.GetMailDomain(ctx, "mail.example.com")
		return d.DKIMState == "verified" && d.RPState == "verified"
	})
}

// d2hash was never a thing: dropped.

func TestMailProvisionRequiresAdoptOnExisting(t *testing.T) {
	existing := `{"TotalCount":1,"Servers":[{"ID":123,"Name":"mail-mail.example.com","InboundAddress":"x@inbound.postmarkapp.com"}]}`
	pm := newPMStub(t, existing, `{"TotalCount":0,"Domains":[]}`, true)
	s, _ := mailHarness(t, pm)
	w := s.do(req{method: "POST", path: "/mail/provision", body: postMailForm("mail.example.com", ""), hdr: htmxPost})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "mail-mail.example.com") || !strings.Contains(w.Body.String(), "adopt") {
		t.Fatalf("no-adopt: %d %s", w.Code, w.Body.String())
	}
	// with adopt the flow reuses the server id and creates the domain
	w = s.do(req{method: "POST", path: "/mail/provision", body: postMailForm("mail.example.com", "") + "&mail_adopt=on", hdr: htmxPost})
	if w.Code != 204 {
		t.Fatalf("adopt: %d %s", w.Code, w.Body.String())
	}
	d, _ := s.deps.Store.GetMailDomain(context.Background(), "mail.example.com")
	if d.PMServerID != 123 || d.PMDomainID != 700 {
		t.Fatalf("adopt row: %+v", d)
	}
}

func TestMailDomainVerifySaveRemove(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":1,"Domains":[{"ID":700,"Name":"mail.example.com"}]}`, true)
	s, _ := mailHarness(t, pm)
	ctx := context.Background()
	mailSeedRow(t, s, store.MailDomain{Name: "mail.example.com", PMDomainID: 700, PMServerID: 1})

	if w := s.do(req{method: "POST", path: "/mail/domains/mail.example.com/verify", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	d, _ := s.deps.Store.GetMailDomain(ctx, "mail.example.com")
	if d.DKIMState != "verified" || d.RPState != "verified" || d.LastVerify == 0 {
		t.Fatalf("after verify: %+v", d)
	}

	if w := s.do(req{method: "POST", path: "/mail/domains/mail.example.com/lmtp", body: "lmtp_addr=1.2.3.4:2424&", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("lmtp save: %d %s", w.Code, w.Body.String())
	}
	d, _ = s.deps.Store.GetMailDomain(ctx, "mail.example.com")
	if d.LMTPAddr != "1.2.3.4:2424" {
		t.Fatalf("lmtp: %+v", d)
	}
	if w := s.do(req{method: "POST", path: "/mail/domains/mail.example.com/lmtp", body: "lmtp_addr=bad", hdr: htmxPost}); w.Code != 422 {
		t.Fatalf("bad lmtp: %d", w.Code)
	}

	if w := s.do(req{method: "POST", path: "/mail/domains/mail.example.com/delete", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if _, err := s.deps.Store.GetMailDomain(ctx, "mail.example.com"); err == nil {
		t.Fatal("row must be gone")
	}
}

func TestSaveMailSettings(t *testing.T) {
	pm := newPMStub(t, `{"TotalCount":0,"Servers":[]}`, `{"TotalCount":0,"Domains":[]}`, true)
	s, _ := mailHarness(t, pm) // already has a sealed token from the harness
	ctx := context.Background()

	body := "mail_lmtp=10.0.0.9:2424&mail_tls=on&mail_user=relay&mail_pass=secretLMTP&mail_token=ACCTOK"
	if w := s.do(req{method: "POST", path: "/settings/mail", body: body + "&", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	st, _ := s.deps.Store.GetSettings(ctx)
	if st.MailLMTP != "10.0.0.9:2424" || st.MailTLS != "starttls" || st.MailUser != "relay" || st.MailPass == nil || st.MailToken == nil {
		t.Fatalf("saved: %+v", st)
	}
	plain, err := secretbox.Open(s.deps.Cfg.SecretKey, st.MailPass)
	if err != nil || string(plain) != "secretLMTP" {
		t.Fatalf("sealed pass: %q %v", plain, err)
	}
	tokplain, _ := secretbox.Open(s.deps.Cfg.SecretKey, st.MailToken)
	if string(tokplain) != "ACCTOK" {
		t.Fatalf("sealed token: %q", tokplain)
	}

	// a save from the Scan screen (its own Settings fieldset) keeps the mail columns
	if w := s.do(req{method: "POST", path: "/settings/scan", body: "scan_socket=/run/x&scan_hour=3&scan_ntfy=&scan_ntfy_token=&", hdr: htmxPost}); w.Code != 204 {
		t.Fatalf("scan save: %d %s", w.Code, w.Body.String())
	}
	if got, _ := s.deps.Store.GetSettings(ctx); got.MailLMTP != "10.0.0.9:2424" || got.MailTLS != "starttls" || got.MailPass == nil {
		t.Fatalf("lost on the scan save: %+v", got)
	}
}

func postMailForm(domain, lmtp string) string {
	return "mail_domain=" + domain + "&mail_lmtp=" + lmtp
}

func waitFor(t *testing.T, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition never became true")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestTmpDumpCalls(t *testing.T) { _ = 0 }
