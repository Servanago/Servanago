package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

// lmtpWeb is the scripted LMTP for webhook tests: fixed replies and a transcript.
type lmtpWeb struct {
	rcpt, data string // replies; defaults filled by listen
	sawFrom    string // MAIL FROM envelope
	sawRcpt    string // RCPT TO envelope
	body       strings.Builder
	commands   strings.Builder // every line the client wrote, for failure dumps
	sessions   int
}

func (f *lmtpWeb) listen(t *testing.T) string {
	t.Helper()
	if f.rcpt == "" {
		f.rcpt = "250 ok"
	}
	if f.data == "" {
		f.data = "250 2.0.0 OK"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveLMTPWeb(ln, f)
	return ln.Addr().String()
}

func serveLMTPWeb(ln net.Listener, f *lmtpWeb) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.sessions++
		serveOneWeb(conn, f)
	}
}

func serveOneWeb(conn net.Conn, f *lmtpWeb) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	_, _ = fmt.Fprint(conn, "220 fake\r\n")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		f.commands.WriteString(">" + line + "\n")
		switch {
		case line == "QUIT":
			_, _ = fmt.Fprint(conn, "221 bye\r\n")
			return
		case strings.HasPrefix(line, "MAIL FROM:"):
			f.sawFrom = strings.Trim(line[len("MAIL FROM:"):], "<>")
			_, _ = fmt.Fprint(conn, "250 ok\r\n")
		case strings.HasPrefix(line, "RCPT TO:"):
			f.sawRcpt = strings.Trim(line[len("RCPT TO:"):], "<>")
			_, _ = fmt.Fprint(conn, f.rcpt+"\r\n")
			if strings.HasPrefix(f.rcpt, "5") || strings.HasPrefix(f.rcpt, "4") {
				return
			}
		case strings.HasPrefix(line, "DATA"):
			_, _ = fmt.Fprint(conn, "354 go\r\n")
			for {
				l, err := br.ReadString('\n')
				if err != nil || strings.TrimSuffix(strings.TrimSuffix(l, "\n"), "\r") == "." {
					break
				}
				f.body.WriteString(l)
			}
			_, _ = fmt.Fprint(conn, f.data+"\r\n")
			if !strings.HasPrefix(f.data, "2") {
				return
			}
		default:
			_, _ = fmt.Fprint(conn, "250 ok\r\n")
		}
	}
}

func mailTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(Deps{Cfg: config.Config{AdminPassword: "pw", Host: "panel.example.test", SecretKey: strings.Repeat("k", 32)}, Store: st})
	h, _ := bcrypt.GenerateFromPassword([]byte("hookpw"), bcrypt.MinCost)
	_, created, err := s.deps.Store.UpsertMailDomain(context.Background(), store.MailDomain{
		Name: "mail.test", HookUser: "mailx", HookPassHash: string(h), PMServerID: 5, PMDomainID: 7})
	if err != nil || !created {
		t.Fatalf("seed mail domain: created=%v %v", created, err)
	}
	return s
}

func setMailLMTPForTest(t *testing.T, s *Server, addr string) {
	t.Helper()
	ctx := context.Background()
	cur, _ := s.deps.Store.GetSettings(ctx)
	cur.MailLMTP = addr
	if err := s.deps.Store.SaveSettings(ctx, cur); err != nil {
		t.Fatal(err)
	}
}

func postHook(s *Server, path, user, pass string, body any) int {
	b, _ := json.Marshal(body)
	return postRaw(s, path, user, pass, string(b))
}

func postRaw(s *Server, path, user, pass, body string) int {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

func inboundFix(id, rcpt, raw string) map[string]any {
	m := map[string]any{"From": "sender@origin.test", "FromFull": map[string]string{"Email": "sender@origin.test"},
		"MessageID": id, "Subject": "hi", "ToFull": []map[string]string{{"Email": rcpt, "Name": ""}}}
	if raw != "" {
		m["RawEmail"] = raw
	}
	return m
}

func TestMailHookDeliversOverLMTP(t *testing.T) {
	s := mailTestServer(t)
	f := &lmtpWeb{}
	setMailLMTPForTest(t, s, f.listen(t))
	ctx := context.Background()
	raw := "Subject: hi\r\nFrom: s@x\r\n\r\nbody\r\n"
	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", inboundFix("m1", "a@mail.test", raw)); code != 200 {
		t.Fatalf("hook answered %d, transcript:\n%s", code, f.commands.String())
	}
	if f.sawRcpt != "a@mail.test" || f.sawFrom != "sender@origin.test" || !strings.Contains(f.body.String(), "Subject: hi") {
		t.Fatalf("lmtp transcript: from %q rcpt %q body %q", f.sawFrom, f.sawRcpt, f.body.String())
	}
	d, _ := s.deps.Store.GetMailDomain(ctx, "mail.test")
	if d.Recv != 1 || d.Delivered != 1 || d.Deduped != 0 || d.LastInbound == 0 {
		t.Fatalf("counters: %+v", d)
	}

	// the same message twice: deduped, no second delivery
	first := f.sessions
	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", inboundFix("m1", "a@mail.test", raw)); code != 200 {
		t.Fatalf("retry answered %d", code)
	}
	d, _ = s.deps.Store.GetMailDomain(ctx, "mail.test")
	if d.Deduped != 1 || d.Delivered != 1 || f.sessions != first {
		t.Fatalf("dedupe after retry: counters %+v sessions %d", d, f.sessions)
	}
}

func TestMailHookRejectedPaths(t *testing.T) {
	s := mailTestServer(t)
	f := &lmtpWeb{}
	setMailLMTPForTest(t, s, f.listen(t))
	ctx := context.Background()

	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "wrong", inboundFix("m1", "a@mail.test", "")); code != 401 {
		t.Fatalf("bad credential: %d", code)
	}
	if code := postRaw(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", "{not json"); code != 400 {
		t.Fatalf("bad json: %d", code)
	}
	if code := postHook(s, "/_mailbridge/hook/other.test", "mailx", "hookpw", inboundFix("m1", "a@mail.test", "")); code != 404 {
		t.Fatalf("unknown domain: %d", code)
	}
	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", inboundFix("m1", "a@OTHER.test", "")); code != 403 {
		t.Fatalf("domain mismatch: %d", code)
	}
	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", map[string]any{"From": "x"}); code != 400 {
		t.Fatalf("missing MessageID: %d", code)
	}
	d, _ := s.deps.Store.GetMailDomain(ctx, "mail.test")
	if d.Rejected != 1 { // only the domain mismatch counts
		t.Fatalf("counter: %+v", d)
	}
}

func TestMailHookLMTPClasses(t *testing.T) {
	t.Run("temp", func(t *testing.T) {
		s := mailTestServer(t)
		setMailLMTPForTest(t, s, (&lmtpWeb{rcpt: "451 come back"}).listen(t))
		if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", inboundFix("m1", "a@mail.test", "Subject: x\r\n\r\nb")); code != 503 {
			t.Fatalf("temp: %d", code)
		}
	})
	t.Run("perm", func(t *testing.T) {
		s := mailTestServer(t)
		setMailLMTPForTest(t, s, (&lmtpWeb{rcpt: "550 no mailbox"}).listen(t))
		if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", inboundFix("m1", "a@mail.test", "Subject: x\r\n\r\nb")); code != 403 {
			t.Fatalf("perm: %d", code)
		}
		d, _ := s.deps.Store.GetMailDomain(context.Background(), "mail.test")
		if d.Rejected != 1 || d.Delivered != 0 {
			t.Fatalf("counters: %+v", d)
		}
	})
}

func TestMailHookRebuildFallback(t *testing.T) {
	s := mailTestServer(t)
	f := &lmtpWeb{}
	setMailLMTPForTest(t, s, f.listen(t))
	body := map[string]any{"From": "sender@origin.test", "MessageID": "m2", "Subject": "no raw",
		"ToFull": []map[string]string{{"Email": "a@mail.test", "Name": ""}}, "TextBody": "plain text"}
	if code := postHook(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", body); code != 200 {
		t.Fatalf("rebuild: %d", code)
	}
	d, _ := s.deps.Store.GetMailDomain(context.Background(), "mail.test")
	if d.Fallbacks != 1 || d.Delivered != 1 || !strings.Contains(f.body.String(), "plain text") {
		t.Fatalf("fallback: %+v body %q", d, f.body.String())
	}
}

func TestMailEventsStoreAndDSN(t *testing.T) {
	s := mailTestServer(t)
	f := &lmtpWeb{}
	setMailLMTPForTest(t, s, f.listen(t))
	ctx := context.Background()

	if code := postHook(s, "/_mailbridge/events/mail.test", "mailx", "hookpw",
		map[string]any{"RecordType": "Delivery", "MessageID": "m1", "DeliveredAt": 1730000000}); code != 200 {
		t.Fatalf("delivery event: %d", code)
	}
	bounce := map[string]any{"RecordType": "Bounce", "ID": 42, "MessageID": "m1", "Type": "HardBounce",
		"From": "sender@origin.test", "Description": "dead"}
	if code := postHook(s, "/_mailbridge/events/mail.test", "mailx", "hookpw", bounce); code != 200 {
		t.Fatalf("bounce event: %d", code)
	}
	if f.sawRcpt != "sender@origin.test" || f.sawFrom != "MAILER-DAEMON@mail.test" {
		t.Fatalf("dsn: from %q rcpt %q", f.sawFrom, f.sawRcpt)
	}
	// Postmark's own retry of the bounce POST: another event row, no second DSN
	if r := postHook(s, "/_mailbridge/events/mail.test", "mailx", "hookpw", bounce); r != 200 {
		t.Fatalf("retry: %d", r)
	}
	if f.sessions != 1 {
		t.Fatalf("LMTP sessions: %d", f.sessions)
	}
	evs, _ := s.deps.Store.ListMailEvents(ctx, 0, 10)
	if len(evs) != 3 || evs[0].RecordType != "Bounce" {
		t.Fatalf("events: %+v", evs)
	}
	dsn, sent := 0, 0
	for _, e := range evs {
		if e.RecordType == "Bounce" {
			dsn++
			if e.DSNSent != 0 {
				sent++
			}
		}
	}
	if dsn != 2 || sent != 1 { // Postmark's own retry: another event row, one DSN only
		t.Fatalf("bounce rows %d, dsn-sent %d", dsn, sent)
	}

	if code := postHook(s, "/_mailbridge/events/mail.test", "mailx", "hookpw",
		map[string]any{"RecordType": "SpamComplaint", "ID": 43}); code != 200 {
		t.Fatalf("spam: %d", code)
	}
	if evs, _ = s.deps.Store.ListMailEvents(ctx, 0, 10); len(evs) != 4 {
		t.Fatalf("count: %d", len(evs))
	}
}

func TestMailEventsAuthAndShape(t *testing.T) {
	s := mailTestServer(t)
	if code := postHook(s, "/_mailbridge/events/mail.test", "mailx", "wrong", map[string]any{"RecordType": "Delivery"}); code != 401 {
		t.Fatalf("auth: %d", code)
	}
	if code := postRaw(s, "/_mailbridge/events/mail.test", "mailx", "hookpw", `{"RecordType":""}`); code != 400 {
		t.Fatalf("no RecordType: %d", code)
	}
}

func TestMailHookMaxBody(t *testing.T) {
	s := mailTestServer(t)
	body := `{"MessageID":"x","RawEmail":"` + strings.Repeat("a", 101<<20) + `"}`
	if code := postRaw(s, "/_mailbridge/hook/mail.test", "mailx", "hookpw", body); code != 413 {
		t.Fatalf("huge body: %d", code)
	}
}
