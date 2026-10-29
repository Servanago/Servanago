package mailbridge

import (
	"encoding/base64"
	"strings"
	"testing"
)

const fixtureRaw = "Received: by fake.postmarkapp.com (Postfix)\nX-Spam-Status: No\nX-Spam-Score: 1.2\n\nplain body\r\nsecond line\r\n"

// encodeBase64 wraps base64 for the fixtures.
func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestDecodeRaw(t *testing.T) {
	raw, plain, ok := DecodeRaw(fixtureRaw)
	if !ok || !plain || !strings.Contains(string(raw), "X-Spam-Status: No") {
		t.Fatalf("plain fixture: ok=%v plain=%v", ok, plain)
	}
	raw, plain, ok = DecodeRaw(base64wrap(fixtureRaw))
	if !ok || plain || !strings.Contains(string(raw), "plain body") {
		t.Fatalf("base64 fixture: ok=%v plain=%v", ok, plain)
	}
	if _, _, ok = DecodeRaw("not a message at all"); ok {
		t.Fatal("garbage must not decode")
	}
	if _, _, ok = DecodeRaw(""); ok {
		t.Fatal("empty must not decode")
	}
}

// base64wrap is the base64-encoded form Postmark could send.
func base64wrap(s string) string {
	enc := string(encodeBase64([]byte(s)))
	lines := make([]string, 0, len(enc)/76+1)
	for len(enc) > 76 {
		lines = append(lines, enc[:76])
		enc = enc[76:]
	}
	lines = append(lines, enc)
	return strings.Join(lines, "\r\n")
}

func TestBuildMIMERoundTrip(t *testing.T) {
	in := &Inbound{
		From:      "sender@origin.test",
		FromName:  "A Sender",
		FromFull:  Addr{Email: "sender@origin.test", Name: "A Sender"},
		ToFull:    []Addr{{Email: "a@example.test"}},
		CcFull:    []Addr{{Email: "c@example.test"}},
		Subject:   "Re: héllo, wörld",
		MessageID: "<mid@origin.test>",
		Date:      "Fri, 23 Oct 2026 14:20:00 +0000",
		TextBody:  "the body",
		HtmlBody:  "<b>the body</b>",
		Headers: []struct{ Name, Value string }{
			{"X-Spam-Status", "No"},
			{"Received-SPF", "none"},
			{"Date", "injected date must not double"}, // written by BuildMIME itself
			{"Content-Transfer-Encoding", "8bit"},     // set by the MIME writer
		},
		Attachments: []struct{ Name, Content, ContentType, ContentID string }{
			{"a.txt", encodeBase64([]byte("attach me")), "text/plain", ""},
		},
	}
	raw, err := BuildMIME(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`From: "A Sender" <sender@origin.test>`,
		"To: <a@example.test>", "=C3=A9llo", "X-Spam-Status: No",
		"Received-SPF: none", "Content-Type: multipart/mixed", "YXR0YWNoIG1l",
		"Date: Fri, 23 Oct 2026", "MIME-Version: 1.0", "Message-ID: <mid@origin.test>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "injected date") {
		t.Error("the webhook Date header copies through")
	}
	if strings.Contains(s, "\r\nA Sender:\r\n") { // no header injection from names
		t.Error("injected header line")
	}
}

func TestInboundRecipientAndSender(t *testing.T) {
	in := &Inbound{FromFull: Addr{Email: "from@x.test"}}
	if got := in.Recipient(); got != "" {
		t.Fatal(got)
	}
	in.ToFull = []Addr{{Email: "First@Example.test"}}
	if got := in.Recipient(); got != "first@example.test" {
		t.Fatal(got)
	}
	in.OriginalRecipient = "Orig@Example.test"
	if got := in.Recipient(); got != "orig@example.test" {
		t.Fatal(got)
	}
	if got := in.Sender(); got != "from@x.test" {
		t.Fatal(got)
	}
}

func TestUnmarshalEvent(t *testing.T) {
	e, err := UnmarshalEvent([]byte(`{"RecordType":"Bounce","ID":11,"Type":"HardBounce","From":"a@b.test","MessageID":"m","Description":"x","Content":"y"}`))
	if err != nil || e.RecordType != "Bounce" || e.ID != 11 || e.From != "a@b.test" {
		t.Fatalf("event: %+v %v", e, err)
	}
}
