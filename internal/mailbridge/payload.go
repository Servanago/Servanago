// Package mailbridge carries the Postmark side of the mail bridge: webhook payloads, the message
// bytes (Postmark's RawEmail or a deterministic rebuild), LMTP delivery and bounce DSNs. It holds
// no state of its own: SQLite records dedupe keys and events, the LMTP server stores the mail.
package mailbridge

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

// Addr is Postmark's To/From entry.
type Addr struct {
	Email       string
	Name        string
	MailboxHash string
}

// Inbound is one Postmark inbound webhook payload.
type Inbound struct {
	FromName, From, OriginalRecipient, Subject, MessageID, Date string
	MailboxHash, Tag, TextBody, HtmlBody, StrippedTextReply     string
	RawEmail                                                    string
	FromFull                                                    Addr
	ToFull, CcFull                                              []Addr
	Headers                                                     []struct{ Name, Value string }
	Attachments                                                 []struct {
		Name, Content, ContentType, ContentID string
	}
}

// Header returns the first matching webhook-parsed header, case-insensitive.
func (in *Inbound) Header(name string) string {
	for _, h := range in.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// Recipient is the envelope recipient: OriginalRecipient or the first To entry, lower-cased.
func (in *Inbound) Recipient() string {
	rcpt := strings.ToLower(strings.TrimSpace(in.OriginalRecipient))
	if rcpt == "" && len(in.ToFull) > 0 {
		rcpt = strings.ToLower(strings.TrimSpace(in.ToFull[0].Email))
	}
	return rcpt
}

// Sender is the envelope sender to use at the LMTP hop: the From address, possibly empty.
func (in *Inbound) Sender() string {
	if in.FromFull.Email != "" {
		return in.FromFull.Email
	}
	return in.From
}

func addrList(as []Addr) string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, (&mail.Address{Name: a.Name, Address: a.Email}).String())
	}
	return strings.Join(out, ", ")
}

func noCRLF(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// DecodeRaw accepts Postmark's RawEmail field: plain RFC 822 first (verified), else base64.
// It also logs which branch fired so the encoding stays observable.
func DecodeRaw(s string) (raw []byte, plainBranch bool, ok bool) {
	if isMessage([]byte(s)) {
		return []byte(s), true, true
	}
	if b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err == nil && isMessage(b) {
		return b, false, true
	}
	return nil, false, false
}

func isMessage(b []byte) bool {
	m, err := mail.ReadMessage(bytes.NewReader(b)) // Go's reader accepts LF-only messages too
	return err == nil && len(m.Header) > 0
}

// BuildMIME rebuilds a message byte-identically to nothing: when RawEmail is unusable the
// reconstructed RFC 822 has Postmark's parsed fields and the webhook headers, minus the ones
// MIME would set itself. The original DKIM cannot verify after this; counters record the
// fallback, per the gopmstall FR2 note.
func BuildMIME(in *Inbound) ([]byte, error) {
	var b bytes.Buffer
	h := func(k, v string) {
		if v = noCRLF(strings.TrimSpace(v)); v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	date := in.Date
	if t, err := mail.ParseDate(in.Date); err == nil {
		date = t.Format(time.RFC1123Z)
	}
	h("Date", date)
	h("From", (&mail.Address{Name: in.FromName, Address: in.Sender()}).String())
	h("To", addrList(in.ToFull))
	h("Cc", addrList(in.CcFull))
	h("Reply-To", in.Header("Reply-To"))
	h("Subject", mime.QEncoding.Encode("utf-8", in.Subject))
	h("Message-ID", in.MessageID)
	for _, x := range in.Headers {
		n := strings.ToLower(x.Name)
		switch {
		case mimeOwnHeader(n), strings.HasPrefix(n, "content-"):
			continue // written above, or set by the MIME writer
		default:
			h(x.Name, x.Value)
		}
	}
	h("MIME-Version", "1.0")

	const boundary = "=_sg_bridge_alt"
	writeText := func(w *bytes.Buffer) {
		if in.HtmlBody == "" {
			writeBody(w, "text/plain", in.TextBody)
			return
		}
		fmt.Fprintf(w, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary)
		for _, p := range [][2]string{{"text/plain", in.TextBody}, {"text/html", in.HtmlBody}} {
			fmt.Fprintf(w, "--%s\r\n", boundary)
			writeBody(w, p[0], p[1])
		}
		fmt.Fprintf(w, "--%s--\r\n", boundary)
	}
	if len(in.Attachments) == 0 {
		writeText(&b)
		return b.Bytes(), nil
	}
	const mixed = "=_sg_bridge_mixed"
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n--%s\r\n", mixed, mixed)
	writeText(&b)
	for _, at := range in.Attachments {
		ct := at.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		name := at.Name
		if name == "" {
			name = "attachment"
		}
		disp := "attachment"
		if at.ContentID != "" {
			disp = "inline"
		}
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Disposition: %s\r\nContent-Transfer-Encoding: base64\r\n", mixed,
			mime.FormatMediaType(ct, map[string]string{"name": name}), mime.FormatMediaType(disp, map[string]string{"filename": name}))
		if at.ContentID != "" {
			fmt.Fprintf(&b, "Content-ID: <%s>\r\n", strings.Trim(at.ContentID, "<>"))
		}
		b.WriteString("\r\n")
		raw, err := base64.StdEncoding.DecodeString(at.Content)
		if err != nil { // a bad attachment costs the rebuild branch, not the whole message
			raw = []byte(at.Content)
		}
		enc := base64.StdEncoding.EncodeToString(raw)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", mixed)
	return b.Bytes(), nil
}

func writeBody(w *bytes.Buffer, ctype, text string) {
	fmt.Fprintf(w, "Content-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", ctype)
	q := quotedprintable.NewWriter(w)
	_, _ = q.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")))
	_ = q.Close()
	w.WriteString("\r\n")
}

// mimeOwnHeader is a header BuildMIME writes itself; webhook copies are skipped.
func mimeOwnHeader(name string) bool {
	switch name {
	case "date", "from", "to", "cc", "reply-to", "subject", "message-id", "mime-version":
		return true
	}
	return false
}

// Event is the subset of a Postmark event notification the bridge acts on. The full JSON is
// stored separately (bounded), so the struct only needs what DSN decisions read.
type Event struct {
	RecordType  string   `json:"RecordType"`
	ID          int64    `json:"ID"`
	MessageID   string   `json:"MessageID"`
	Type        string   `json:"Type"` // Bounce: HardBounce, SoftBounce, ...
	TypeCode    int      `json:"TypeCode"`
	Description string   `json:"Description"`
	Details     string   `json:"Details"`
	Email       string   `json:"Email"`
	From        string   `json:"From"`
	Subject     string   `json:"Subject"`
	Content     string   `json:"Content"`
	BouncedAt   string   `json:"BouncedAt"`
	Recipients  []string `json:"Recipients"`
}

// UnmarshalEvent decodes a webhook JSON body, tolerant of unknown fields.
func UnmarshalEvent(body []byte) (Event, error) {
	var e Event
	if err := json.Unmarshal(body, &e); err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}
	return e, nil
}
