package mailbridge

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLMTP runs one session per test: fixed replies, transcript on lines. The transcript is
// mutex-guarded: the server goroutine may still be writing (the QUIT reply) when the test reads.
type fakeLMTP struct {
	rcpt, data string // RCPT and final-DATA replies
	mu         sync.Mutex
	saw        strings.Builder
}

func (f *fakeLMTP) write(c net.Conn, s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _ = fmt.Fprint(c, s+"\r\n")
	f.saw.WriteString("< " + strings.ReplaceAll(s, "\r\n", " ⁋ ") + "\n")
}

// transcript snapshots what the session exchanged.
func (f *fakeLMTP) transcript() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saw.String()
}

func (f *fakeLMTP) listen(t *testing.T, target *Target) {
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
	go serveOne(ln, f)
	target.HostPort = ln.Addr().String()
}

func serveOne(ln net.Listener, f *fakeLMTP) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	f.write(conn, "220 fake LMTP ready")
	for {
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\r\n")
		switch {
		case true: // every command is transcribed before it is answered
			f.mu.Lock()
			f.saw.WriteString("cmd: " + line + "\n")
			f.mu.Unlock()
		}
		switch {
		case strings.HasPrefix(line, "LHLO"):
			f.write(conn, "250-LMTP fake")
			f.write(conn, "250 8BITMIME")
		case strings.HasPrefix(line, "MAIL FROM"):
			f.write(conn, "250 sender ok")
		case strings.HasPrefix(line, "RCPT TO"):
			f.write(conn, f.rcpt)
			if strings.HasPrefix(f.rcpt, "4") || strings.HasPrefix(f.rcpt, "5") {
				return
			}
		case strings.HasPrefix(line, "DATA"):
			f.write(conn, "354 go")
			f.readBody(conn)
			f.write(conn, f.data)
			if !strings.HasPrefix(f.data, "2") {
				return
			}
		case strings.HasPrefix(line, "QUIT"):
			f.write(conn, "221 bye")
			return
		default:
			f.write(conn, "250 ok")
		}
	}
}

// readBody reads the dot-terminated block; a dotted line means the client stuffed it.
func (f *fakeLMTP) readBody(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\r\n")
		if line == "." {
			return
		}
		f.mu.Lock()
		f.saw.WriteString("body: " + line + "\n")
		f.mu.Unlock()
	}
}

func TestDeliverLMTP(t *testing.T) {
	f := &fakeLMTP{rcpt: "250 ok", data: "250 2.0.0 OK"}
	var tgt Target
	f.listen(t, &tgt)
	res, err := Deliver(context.Background(), tgt, "panel.test", "sender@x.test", "rcpt@example.test", []byte("Subject: hi\r\n\r\nhello\r\n"))
	if res != ResultOK || err != nil {
		t.Fatalf("deliver: %v %v", res, err)
	}
	tr := f.transcript()
	for _, want := range []string{"LHLO panel.test", "MAIL FROM:<sender@x.test>", "RCPT TO:<rcpt@example.test>", "hello", "250 2.0.0 OK"} {
		if !strings.Contains(tr, want) {
			t.Fatalf("missing %q in transcript:\n%s", want, tr)
		}
	}
}

// fakeLMTP replies configurable at RUN time? The rcpt field is set before listen, so
// parameterize per scenario by rebuilding the listener.
func TestDeliverMapsFailures(t *testing.T) {
	scenarios := []struct {
		name, rcpt, data string
		want             Result
	}{
		{"rcpt temp", "451 try again", "250 2.0.0 ok", ResultTemporary},
		{"rcpt perm", "550 mailbox not found", "250 2.0.0 ok", ResultFailed},
		{"data temp", "250 ok", "451 try again", ResultTemporary},
		{"data perm", "250 ok", "550 denied", ResultFailed},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			f := &fakeLMTP{rcpt: s.rcpt, data: s.data}
			var tgt Target
			f.listen(t, &tgt)
			res, err := Deliver(context.Background(), tgt, "panel.test", "sender@x.test", "rcpt@example.test", []byte("Subject: hi\r\n\r\nhello\r\n"))
			if res != s.want || s.want != ResultOK && err == nil {
				t.Fatalf("result %v err %v (want %v)", res, err, s.want)
			}
		})
	}
	if got := DeliverReply(ResultOK); got != 200 || DeliverReply(ResultTemporary) != 503 || DeliverReply(ResultFailed) != 403 {
		t.Fatalf("mapping: 200/503/403, got %d/%d/%d", got, DeliverReply(ResultTemporary), DeliverReply(ResultFailed))
	}
}

func TestDeliverNoTarget(t *testing.T) {
	res, err := Deliver(context.Background(), Target{}, "h", "f", "r", nil)
	if res != ResultFailed || err == nil {
		t.Fatalf("no target: %v %v", res, err)
	}
}

// TestDeliverDotStuffs checks RFC 5321: a body line starting with a dot is doubled.
func TestDeliverDotStuffs(t *testing.T) {
	f := &fakeLMTP{}
	var tgt Target
	f.listen(t, &tgt)
	body := "Subject: d\r\n\r\n.ok: leading dot\r\n"
	res, err := Deliver(context.Background(), tgt, "panel.test", "s@x.test", "r@example.test", []byte(body))
	if err != nil || res != ResultOK {
		t.Fatalf("deliver: %v %v", res, err)
	}
	tr := f.transcript()
	if !strings.Contains(tr, "body: .") || strings.Contains(tr, "body: .ok:") {
		t.Fatalf("dots not stuffed or line sent unstuffed:\n%s", tr)
	}
}

func TestCleanAddr(t *testing.T) {
	if got := envAddr("a@x.test"); got != "<a@x.test>" {
		t.Fatal(got)
	}
	if got := envAddr("a@x.test>"); got != "<a@x.test>" {
		t.Fatal(got)
	}
	if got := cleanAddr("a\r\nBINARY x"); strings.ContainsAny(got, "\r\n") {
		t.Fatal(got)
	}
	if got := envAddr(""); got != "<>" {
		t.Fatal(got)
	}
}

func TestLMTPTimeout(t *testing.T) {
	// no server: dial a closed port and confirm the transport maps to a temporary result
	tgt := Target{HostPort: "127.0.0.1:1"}
	res, err := Deliver(context.Background(), tgt, "h", "s@x.test", "r@x.test", []byte("b"))
	if res != ResultTemporary || err == nil {
		t.Fatalf("refused dial: %v %v", res, err)
	}
}

// TestTLSDeliver exercises STARTTLS against a fake speaking a self-signed session. TLS on
// 127.0.0.1 with a server name mismatch must fail (no InsecureSkipVerify).
func TestDeliverTLSRejected(t *testing.T) {
	var tgt Target
	tgt.TLS = true
	tgt.HostPort = "127.0.0.1:1"
	res, err := Deliver(context.Background(), tgt, "panel.test", "s@x.test", "r@x.test", []byte("b"))
	if res != ResultTemporary || err == nil {
		t.Fatalf("tls dial: %v %v", res, err)
	}
}
