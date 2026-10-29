// Minimal LMTP client for one recipient per message — exactly the webhook shape (one
// OriginalRecipient, one bounce From). Result classes map to the HTTP answer Postmark sees
// per the settled rule. Hand-rolled: the maintained library either refuses to send credentials
// unencrypted or cannot run LHLO over STARTTLS; the reply grammar is small.
package mailbridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Result is how one delivery ended: OK for a 2xx, Temporary for a 4xx (or transport trouble),
// Failed for a 5xx.
type Result string

const (
	ResultOK        Result = "ok"        // accepted: the handler answers 200
	ResultTemporary Result = "temporary" // Postmark retries: the handler answers 503
	ResultFailed    Result = "failed"    // Postmark stops retrying: the handler answers 403
)

// Target is one LMTP endpoint: the global Settings target or a per-domain override. The
// password arrives unsealed (the caller opened it) and is never logged.
type Target struct {
	HostPort string
	TLS      bool // STARTTLS after LHLO
	User     string
	Pass     string
}

const lmtpTimeout = 2 * time.Minute // dial through the final dot; Postmark's timeout is generous

// Deliver sends one message over LMTP. host is the LHLO name (the panel host); from and rcpt
// are envelope addresses; msg is the RFC 822 bytes (CRLF-normalized and dot-stuffed here).
func Deliver(ctx context.Context, t Target, host, from, rcpt string, msg []byte) (Result, error) {
	if t.HostPort == "" {
		return ResultFailed, errors.New("no LMTP target configured (set one in Settings or per domain)")
	}
	if ctx.Err() != nil {
		return ResultTemporary, ctx.Err()
	}
	deadline := time.Now().Add(lmtpTimeout) // clamp to the caller's, then bound ours on top
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithDeadline(ctx, deadline)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", t.HostPort)
	if err != nil {
		return ResultTemporary, fmt.Errorf("dial %s: %w", t.HostPort, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	c := &lmtp{conn: conn, br: bufio.NewReader(conn)}

	defer func() { _, _ = fmt.Fprintf(c.conn, "QUIT\r\n") }()
	if code, _, err := c.reply(); err != nil || code/100 != 2 { // the greeting
		return byCode(code, err)
	}
	if code, _, err := c.cmd("LHLO " + cleanAddr(host)); err != nil || code/100 != 2 {
		return byCode(code, err)
	}
	if t.TLS {
		if code, _, err := c.cmd("STARTTLS"); err != nil || code != 220 {
			return byCode(code, err)
		}
		inner := tls.Client(c.conn, &tls.Config{ServerName: hostPart(t.HostPort)})
		if err := inner.HandshakeContext(ctx); err != nil {
			return ResultTemporary, fmt.Errorf("TLS handshake: %w", err)
		}
		c.conn = inner
		c.br = bufio.NewReader(inner)
	}
	if t.User != "" {
		ir := base64.StdEncoding.EncodeToString([]byte("\x00" + t.User + "\x00" + t.Pass))
		if code, _, err := c.cmd("AUTH PLAIN " + ir); err != nil || code != 235 {
			return byCode(code, err)
		}
	}
	if code, _, err := c.cmd("MAIL FROM:" + envAddr(from)); err != nil || code/100 != 2 {
		return byCode(code, err)
	}
	code, text, err := c.cmd("RCPT TO:" + envAddr(rcpt))
	switch {
	case err != nil:
		return ResultTemporary, err
	case code/100 == 4:
		return ResultTemporary, replyErr("RCPT", code, text)
	case code/100 != 2:
		return ResultFailed, replyErr("RCPT", code, text)
	}
	if code, _, err := c.cmd("DATA"); err != nil || code != 354 {
		return byCode(code, err)
	}
	if err := c.data(msg); err != nil {
		return ResultTemporary, err
	}
	return byCode(mustReply(c), nil)
}

// byCode classifies one non-0 reply code; a 0 means no reply ever arrived.
func byCode(code int, err error) (Result, error) {
	if err != nil {
		if code == 0 {
			return ResultTemporary, err // transport trouble: retryable
		}
	}
	switch code / 100 {
	case 4:
		return ResultTemporary, replyErr("reply", code, "")
	case 5:
		return ResultFailed, replyErr("reply", code, "")
	}
	if code/100 == 2 {
		return ResultOK, nil
	}
	return ResultTemporary, replyErr("reply", code, "")
}

func mustReply(c *lmtp) int {
	code, _, err := c.reply()
	if err != nil {
		return 0 // byCode turns 0 into a temporary
	}
	return code
}

func replyErr(label string, code int, text string) error {
	return fmt.Errorf("LMTP %s %d: %s", label, code, text)
}

// lmtp speaks one LMTP session with a single RCPT.
type lmtp struct {
	conn net.Conn
	br   *bufio.Reader // swapped for the TLS connection
}

// reply reads one response: continuation lines end with '-', the last with ' '.
func (c *lmtp) reply() (int, string, error) {
	var b strings.Builder
	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			return 0, "", fmt.Errorf("read LMTP reply: %w", err)
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
			return 0, "", fmt.Errorf("bad LMTP reply %q", line)
		}
		code, aerr := strconv.Atoi(line[:3])
		if aerr != nil {
			return 0, "", fmt.Errorf("bad LMTP code %q", line[:3])
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(line[4:])
		if line[3] == ' ' {
			return code, b.String(), nil
		}
	}
}

// cmd writes one command line and reads its reply.
func (c *lmtp) cmd(format string, args ...any) (int, string, error) {
	if _, err := fmt.Fprintf(c.conn, format+"\r\n", args...); err != nil {
		return 0, "", fmt.Errorf("write LMTP: %w", err)
	}
	return c.reply()
}

// data canonicalizes to CRLF, escapes leading dots and sends the terminating dot.
func (c *lmtp) data(msg []byte) error {
	if l := len(msg); l == 0 || msg[l-1] != '\n' {
		msg = append(msg, '\n')
	}
	var out strings.Builder
	for len(msg) > 0 {
		line, rest, _ := bytes.Cut(msg, []byte("\n"))
		msg = rest
		line = append(line, '\n')
		if bytes.HasPrefix(line, []byte(".")) {
			_ = out.WriteByte('.')
		}
		_, _ = out.Write(line)
	}
	if _, err := c.conn.Write([]byte(out.String() + ".\r\n")); err != nil {
		return fmt.Errorf("send DATA: %w", err)
	}
	return nil
}

// cleanAddr strips what would change SMTP state from an envelope address.
func cleanAddr(s string) string {
	r := strings.Map(func(r rune) rune {
		switch r {
		case '<', '>', '\r', '\n', 0:
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(r)
}

// envAddr renders one envelope address; empty keeps the bounce envelope.
func envAddr(s string) string {
	if a := cleanAddr(s); a != "" {
		return "<" + a + ">"
	}
	return "<>"
}

func hostPart(hostPort string) string { return strings.Split(hostPort, ":")[0] }

// DeliverReply maps a result to the HTTP status Postmark sees: 2xx accepted, 503 retried,
// 403 stops the retries.
func DeliverReply(r Result) int {
	switch r {
	case ResultOK:
		return 200
	case ResultFailed:
		return 403
	default:
		return 503
	}
}
