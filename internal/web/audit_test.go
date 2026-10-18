package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/servanago/servanago/internal/store"
)

func auditRows(t *testing.T, s *Server) []store.AuditEntry {
	t.Helper()
	rows, err := s.deps.Store.ListAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// expectAudit checks that exactly one row was added since before, and returns it.
func expectAudit(t *testing.T, s *Server, before int, actor, action, targetHas string) store.AuditEntry {
	t.Helper()
	rows := auditRows(t, s)
	if len(rows) != before+1 {
		t.Fatalf("%s: want exactly one new audit row, got %d: %+v", action, len(rows)-before, rows)
	}
	e := rows[0]
	if e.Actor != actor || e.Action != action || !strings.Contains(e.Target, targetHas) || e.At == "" {
		t.Fatalf("audit row %+v, want actor %q action %q target containing %q", e, actor, action, targetHas)
	}
	return e
}

// stepper runs requests as a signed-in admin and asserts the single audit row each one leaves.
type stepper struct {
	t     *testing.T
	s     *Server
	actor string
	ck    []*http.Cookie
}

func (p stepper) do(action, targetHas string, wantCode int, r req) {
	p.t.Helper()
	before := len(auditRows(p.t, p.s))
	r.cookies = p.ck
	if r.hdr == nil {
		r.hdr = htmxPost
	}
	if got := p.s.do(r); got.Code != wantCode {
		p.t.Fatalf("%s: %d %s", action, got.Code, got.Body)
	}
	expectAudit(p.t, p.s, before, p.actor, action, targetHas)
}

func postTo(path string, kv ...string) req {
	return req{method: "POST", path: path, body: form(kv...).Encode()}
}

func TestSiteDomainAndSettingsActionsLeaveOneAuditRow(t *testing.T) {
	s := cfgServer(t, &cfFake{zones: zonesOK}, gateCfg())
	ctx := context.Background()
	w := login(s, "pw", nil, "")
	if w.Code != 204 {
		t.Fatalf("login: %d", w.Code)
	}
	if e := expectAudit(t, s, 0, "admin", "login", "password"); e.IP == "" {
		t.Error("the sign-in row has no client IP")
	}
	p := stepper{t, s, "admin", cookiesOf(t, w)}

	p.do("domain.added", "example.com", 204, req{method: "POST", path: "/domains", body: url.Values{"name": {"example.com"}, "default_ip": {"10.0.0.1"}, "cert_mode": {"wildcard"}}.Encode()})
	d, _ := s.deps.Store.ListDomains(ctx)
	p.do("domain.updated", "example.com", 204, req{method: "PUT", path: "/domains/" + itoa(d[0].ID), body: url.Values{"default_ip": {"10.0.0.2"}, "cert_mode": {"wildcard"}}.Encode()})
	p.do("site.created", "sonarr.example.com", 204, postTo("/sites", "enabled", "on"))
	rs, _ := s.deps.Store.ListSites(ctx)
	site := "/sites/" + itoa(rs[0].ID)
	p.do("site.updated", "sonarr.example.com", 200, req{method: "PUT", path: site, body: form("enabled", "on").Encode()})
	p.do("site.toggled", "sonarr.example.com", 204, postTo(site+"/toggle"))
	p.do("site.dns_resynced", "sonarr.example.com", 204, postTo(site+"/dns/resync"))
	p.do("site.dns_taken_over", "sonarr.example.com", 204, postTo(site+"/dns/takeover"))
	p.do("settings.smtp", "", 204, postTo("/settings/smtp", "smtp_host", "mail.example.com", "mail_from", "a@example.com"))
	p.do("site.deleted", "sonarr.example.com", 204, req{method: "DELETE", path: site})
	p.do("domain.deleted", "example.com", 204, req{method: "DELETE", path: "/domains/" + itoa(d[0].ID)})
	if err := s.deps.Store.UpsertIdentity(ctx, "visitor@example.net", "n1", "h1", "2026-10-17T10:00:00Z", time.Hour); err != nil {
		t.Fatal(err)
	}
	p.do("gate.revoked", "visitor@example.net", 204, postTo("/security/gate/revoke", "email", "visitor@example.net"))
	p.do("logout", "", 204, postTo("/logout"))
}

func TestUserManagementActionsNameTheActingAdmin(t *testing.T) {
	s := newServer(t, "pw")
	p := stepper{t, s, "admin", cookiesOf(t, login(s, "pw", nil, ""))}
	p.do("user.added", "carol", 204, postTo("/users", "password", "pw", "username", "carol", "new_password", uniquePass))
	carol := "/users/" + itoa(userID(t, s, "carol"))
	p.do("user.password", "carol", 204, postTo(carol+"/password", "password", "pw", "new_password", uniquePass+"x"))
	p.do("user.2fa_reset", "carol", 204, postTo(carol+"/reset-2fa", "password", "pw"))
	p.do("user.removed", "carol", 204, postTo(carol+"/delete", "password", "pw"))
	// Changing your own password is recorded against yourself.
	p.do("user.password", "admin", 204, postTo("/users/"+itoa(userID(t, s, "admin"))+"/password", "password", "pw", "new_password", uniquePass+"y"))
}

const uniquePass = "Zq9-unique-pass-7"

func TestSecurityEventsAreAudited(t *testing.T) {
	s, now := newServerCfg(t, cfg2fa())
	ck := cookiesOf(t, login(s, "pw", nil, ""))
	before := len(auditRows(t, s))
	secret, backups, upgraded := enrollTOTP(t, s, now, ck)
	if upgraded != nil {
		ck = []*http.Cookie{upgraded}
	}
	if rows := auditRows(t, s); len(rows) != before+1 || rows[0].Action != "totp.enabled" || rows[0].Actor != "admin" {
		t.Fatalf("enrolling: %+v", rows)
	}
	p := stepper{t, s, "admin", ck}
	code, _ := totp.GenerateCode(secret, *now)
	n := len(auditRows(t, s))
	regen := s.do(req{method: "POST", path: "/security/backup-codes", body: form("password", "pw", "code", code).Encode(), hdr: htmxPost, cookies: ck})
	if regen.Code != 200 {
		t.Fatalf("regenerate: %d %s", regen.Code, regen.Body)
	}
	expectAudit(t, s, n, "admin", "backup_codes.regenerated", "")
	backups = backups[:0] // the old codes are void now; take the new ones
	for _, m := range backupRE.FindAllStringSubmatch(regen.Body.String(), -1) {
		backups = append(backups, m[1])
	}
	*now = now.Add(30 * time.Second)

	// Signing in with a TOTP code and with a backup code both read "login", with the method as the target.
	loginWith := func(code string, peer string) {
		h := map[string]string{"X-Forwarded-For": peer}
		n := len(auditRows(t, s))
		pend := pendingOf(t, login(s, "pw", h, ""))
		n++ // the password step alone is not a sign-in
		if len(auditRows(t, s)) != n-1 {
			t.Fatalf("the password step wrote an audit row: %+v", auditRows(t, s))
		}
		if w := postForm(s, "/login/totp", url.Values{"code": {code}}, pend, h); w.Code != 204 {
			t.Fatalf("second step: %d %s", w.Code, w.Body)
		}
	}
	totpCode, _ := totp.GenerateCode(secret, *now)
	loginWith(totpCode, "10.7.0.1")
	if e := auditRows(t, s)[0]; e.Action != "login" || e.Target != "totp" || e.Actor != "admin" {
		t.Fatalf("totp sign-in row: %+v", e)
	}
	loginWith(backups[0], "10.7.0.2")
	if e := auditRows(t, s)[0]; e.Action != "login" || e.Target != "backup-code" {
		t.Fatalf("backup-code sign-in row: %+v", e)
	}

	*now = now.Add(30 * time.Second)
	code, _ = totp.GenerateCode(secret, *now)
	p.do("totp.disabled", "", 204, postTo("/security/totp/disable", "password", "pw", "code", code))
}

func TestFailedSignInsAndReauthAreAuditedWithoutSecrets(t *testing.T) {
	s := newServer(t, "pw")
	loginAs(s, "admin", "wrong-"+uniquePass, map[string]string{"X-Forwarded-For": "10.8.0.1"}, "")
	e := expectAudit(t, s, 0, "admin", "login.failed", "password")
	if e.IP != "10.8.0.1" {
		t.Errorf("client IP: %q", e.IP)
	}
	// An unknown name is recorded as typed (so probing is visible), truncated and with no control characters.
	long := "bob" + strings.Repeat("x", 100) + "\x00\n<script>"
	loginAs(s, long, "x", map[string]string{"X-Forwarded-For": "10.8.0.2"}, "")
	e = auditRows(t, s)[0]
	if e.Action != "login.failed" || len(e.Actor) > 64 || strings.ContainsAny(e.Actor, "\x00\n") {
		t.Fatalf("unknown-name row: %+v", e)
	}

	ck := cookiesOf(t, login(s, "pw", map[string]string{"X-Forwarded-For": "10.8.0.3"}, ""))
	p := stepper{t, s, "admin", ck}
	p.do("reauth.failed", "/users", 401, postTo("/users", "password", "nope-"+uniquePass, "username", "carol", "new_password", uniquePass))

	for _, row := range auditRows(t, s) {
		for _, field := range []string{row.Actor, row.Action, row.Target, row.IP} {
			if strings.Contains(field, uniquePass) {
				t.Fatalf("a password reached the audit log: %+v", row)
			}
		}
	}
}

func TestAuditPageListsRowsEscapedAndNewestFirst(t *testing.T) {
	s := newServer(t, "pw")
	loginAs(s, "<b>evil</b>", "x", map[string]string{"X-Forwarded-For": "10.9.0.1"}, "")
	ck := cookiesOf(t, login(s, "pw", map[string]string{"X-Forwarded-For": "10.9.0.2"}, ""))
	body := s.do(req{path: "/audit", cookies: ck}).Body.String()
	if strings.Contains(body, "<b>evil</b>") || !strings.Contains(body, "&lt;b&gt;evil&lt;/b&gt;") {
		t.Errorf("actor not escaped: %s", body)
	}
	if i, j := strings.Index(body, ">login<"), strings.Index(body, "login.failed"); i < 0 || j < 0 || i > j {
		t.Errorf("newest first: login at %d, login.failed at %d", i, j)
	}
	if w := s.do(req{path: "/audit"}); w.Code != 303 {
		t.Errorf("audit page without a session: %d", w.Code)
	}
}

// A failed re-authentication says why in the audit row, so "it won't take my password" can be told apart from
// "the form sent no password". Only the byte length of a wrong password is recorded, never its text.
func TestReauthFailureRowSaysWhy(t *testing.T) {
	s := newServer(t, "pw")
	ck := cookiesOf(t, login(s, "pw", map[string]string{"X-Forwarded-For": "10.8.1.1"}, ""))
	p := stepper{t, s, "admin", ck}
	p.do("reauth.failed", "/users: no password sent", 401, postTo("/users", "username", "carol", "new_password", "x"))
	p.do("reauth.failed", "/users: password mismatch, 7 bytes", 401, postTo("/users", "password", "nope123", "username", "carol", "new_password", "x"))
}
