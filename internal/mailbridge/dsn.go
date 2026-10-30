// RFC 3464 bounce reports: what a real MTA would have mailed the original sender, synthesized
// from Postmark's bounce webhook. The report goes back over LMTP so the recipient server keeps
// its usual bounce handling.
package mailbridge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Body and field caps: Postmark caps inbound attachments at 35 MB and RawEmail roughly doubles
// the payload; one event notification is small and the stored row is bounded. Constants, not
// settings — these numbers move by release, not by deployment.
const (
	MaxBody      = 100 << 20 // inbound webhook body cap
	MaxEventBody = 5 << 20   // one event notification
	MaxPayload   = 64 << 10  // what we store per event row
)

// statusOf maps Postmark's bounce type to an RFC 3464 status; anything unknown is a hard fail.
func statusOf(bounceType string) string {
	if strings.HasPrefix(bounceType, "Soft") {
		return "4.0.0"
	}
	return "5.0.0"
}

// mailerDaemonLoop reports a From address that answers its own bounces (loop guard: a DSN to
// MAILER-DAEMON would bounce again).
func mailerDaemonLoop(addr string) bool {
	a, err := mail.ParseAddress(strings.TrimSpace(addr))
	if err != nil {
		return false // unparseable: let the delivery refuse it, the log shows why
	}
	lp, _, _ := strings.Cut(strings.ToLower(a.Address), "@")
	return lp == "mailer-daemon" || lp == "postmaster"
}

// MailerDaemonLoop is the handler-facing name of the loop guard.
func MailerDaemonLoop(addr string) bool { return mailerDaemonLoop(addr) }

var dsnMaxContent = 512 << 10 // the bounce body shipped inside the DSN, capped

// BuildDSN renders the multipart/report for one bounce webhook. domain is where the bridge sent
// the original message (the Reporting-MTA); bounce is the webhook; orig is what Postmark said
// came in (a short human-facing quote of the bounce).
func BuildDSN(domain string, e Event) ([]byte, error) {
	if e.From == "" {
		return nil, fmt.Errorf("bounce %d has no From address", e.ID)
	}
	boundary := "=_sgdsn_" + randBoundary()
	human := fmt.Sprintf(
		"This report relates to a message your mail system could not deliver.\r\n\r\n"+
			"Postmark report: %s (type %d)\r\n%s\r\n%s\r\n\r\nThe failed message follows below, if Postmark included it.\r\n",
		strings.TrimSpace(e.Type), e.TypeCode, strings.TrimSpace(noCRLF(e.Description)), strings.TrimSpace(noCRLF(e.Details)))

	var st bytes.Buffer
	fmt.Fprintf(&st, "\r\nReporting-MTA: dns; %s\r\n", domain)
	if t, err := mail.ParseDate(e.BounceDate()); err == nil {
		fmt.Fprintf(&st, "Arrival-Date: %s\r\n", t.Format(time.RFC1123Z))
	}
	to := noCRLF(strings.TrimSpace(e.From))
	email := noCRLF(strings.TrimSpace(e.Email))
	if email == "" {
		email = to
	}
	fmt.Fprintf(&st, "\r\nFinal-Recipient: rfc822; %s\r\n", email)
	fmt.Fprintf(&st, "Action: failed\r\n")
	fmt.Fprintf(&st, "Status: %s\r\n", statusOf(e.Type))
	if e.Description != "" || e.Details != "" {
		fmt.Fprintf(&st, "Diagnostic-Code: X-Postmark; %s\r\n", strings.TrimSpace(noCRLF(strings.Join([]string{e.Description, e.Details}, " - "))))
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "From: MAILER-DAEMON@%s\r\n", domain)
	fmt.Fprintf(&b, "To: %s\r\n", (&mail.Address{Address: to}).String())
	fmt.Fprintf(&b, "Subject: Mail delivery failed: returning message to sender\r\n")
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"%s\"\r\n\r\n", boundary)

	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", boundary, human)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: message/delivery-status\r\n%s\r\n", boundary, st.String())
	if c := e.Content; c != "" { // IncludeBounceContentInHook; oversized content is cut, not lost silently — the event row holds the webhook payload
		fmt.Fprintf(&b, "--%s\r\nContent-Type: message/rfc822\r\n\r\n", boundary)
		content := []byte(noCRLF(c)) // Postmark gives it as one escaped string; keep it on one line per original line
		content = bytes.ReplaceAll(content, []byte("\\n"), []byte("\r\n"))
		if len(content) > dsnMaxContent {
			content = content[:dsnMaxContent]
		}
		b.Write(content)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func randBoundary() string {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "static" // no randomness: the boundary is still valid, just guessable
	}
	return hex.EncodeToString(r[:])
}

// BounceDate supports the two timestamps the bounce payload may carry.
func (e Event) BounceDate() string {
	if e.BouncedAt != "" {
		return e.BouncedAt
	}
	return ""
}
