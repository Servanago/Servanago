package smtpx

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// TestSendTalksSMTP drives a minimal loopback SMTP server through the full dialogue.
func TestSendTalksSMTP(t *testing.T) {
	var got strings.Builder
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan error, 1)
	go func() { done <- serve(l, &got) }()
	d := Dialer{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	if err := d.Send("access@example.com", "alice@example.com", "Access link", "click https://st.example.com/_gate/verify/xyz"); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"From: access@example.com", "To: alice@example.com", "Subject: Access link", "click https://st.example.com/_gate/verify/xyz"} {
		if !strings.Contains(got.String(), want) {
			t.Errorf("message missing %q:\n%s", want, got.String())
		}
	}
}

func serve(l net.Listener, out *strings.Builder) error {
	c, err := l.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	w := func(s string) { _, _ = c.Write([]byte(s)) }
	w("220 mock ESMTP\r\n")
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
		case strings.HasPrefix(line, "EHLO"):
			w("250-mock\r\n250 OK\r\n")
		case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
			out.WriteString(line + "\n")
			w("250 OK\r\n")
		case line == "DATA":
			w("354 go\r\n")
			var body strings.Builder
			for sc.Scan() {
				if sc.Text() == "." {
					break
				}
				body.WriteString(sc.Text())
			}
			out.WriteString(body.String() + "\n")
			w("250 OK\r\n")
		case line == "QUIT":
			w("221 bye\r\n")
			return nil
		default:
			w("250 OK\r\n")
		}
	}
	return sc.Err()
}
