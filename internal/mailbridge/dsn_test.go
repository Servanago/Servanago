package mailbridge

import (
	"net/mail"
	"strings"
	"testing"
)

func TestBuildDSN(t *testing.T) {
	e := Event{RecordType: "Bounce", ID: 9, MessageID: "m-1", Type: "HardBounce", TypeCode: 1,
		From: "a@b.test", Email: "a@b.test", Subject: "The subject",
		Description: "Could not be delivered", Details: "ErrorCode: 408",
		Content: "From: a@b.test\r\nSubject: The subject\r\n\r\nbody\r\n"}
	raw, err := BuildDSN("example.test", e)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"From: MAILER-DAEMON@example.test",
		"To: <a@b.test>",
		"multipart/report; report-type=delivery-status",
		"Content-Type: message/delivery-status",
		"Reporting-MTA: dns; example.test",
		"Final-Recipient: rfc822; a@b.test",
		"Action: failed",
		"Status: 5.0.0",
		"Diagnostic-Code: X-Postmark; Could not be delivered - ErrorCode: 408",
		"Content-Type: message/rfc822",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}

	// the report must parse and expose its parts
	m, err := mail.ReadMessage(strings.NewReader(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ct := m.Header.Get("Content-Type")
	if !strings.Contains(ct, "multipart/report") || !strings.Contains(ct, "boundary=") {
		t.Fatal(ct)
	}
	for _, p := range []string{"text/plain", "message/delivery-status", "message/rfc822"} {
		if !strings.Contains(s, "--") || !strings.Contains(s, "Content-Type: "+p) {
			t.Errorf("part %s missing", p)
		}
	}

	soft := Event{Type: "SoftBounce", From: "x@y.test"}
	raw, err = BuildDSN("d.test", soft)
	if err != nil || !strings.Contains(string(raw), "Status: 4.0.0") {
		t.Fatalf("soft status: %v %v", err, raw == nil)
	}
}

func TestBuildDSNGuards(t *testing.T) {
	if _, err := BuildDSN("d.test", Event{ID: 1}); err == nil {
		t.Fatal("a bounce without From must refuse")
	}
	raw, err := BuildDSN("d.test", Event{ID: 2, From: "mailer-daemon@loop.test"})
	if err != nil { // building is allowed; the caller consults mailerDaemonLoop before sending
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "mailer-daemon@loop.test") {
		t.Fatal("the From should still be the recipient")
	}
	if !mailerDaemonLoop("MAILER-DAEMON@loop.test") || mailerDaemonLoop("user@loop.test") {
		t.Fatal("loop guard")
	}
}
