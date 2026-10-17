// Package caddyharness proves embedded Caddy behaves as DESIGN.md assumes.
// Tests are serial: caddy.Load and caddylog.Sink are process globals.
package caddyharness

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/caddy-dns/cloudflare"
	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	"github.com/servanago/servanago/internal/caddylog"
)

const host = "app.example.com"

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// cfg renders a minimal static config: one host routed to upstream, internal issuer.
func cfg(t *testing.T, httpPort, httpsPort int, storage, upstream string) []byte {
	t.Helper()
	m := map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": map[string]any{"module": "file_system", "root": storage},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{
			"writer": map[string]any{"output": "servanago"}, "encoder": map[string]any{"format": "json"}, "level": "INFO"}}},
		"apps": map[string]any{
			"http": map[string]any{
				"http_port": httpPort, "https_port": httpsPort,
				"servers": map[string]any{"srv0": map[string]any{
					"listen": []string{fmt.Sprintf("127.0.0.1:%d", httpsPort)},
					"routes": []any{map[string]any{
						"match":    []any{map[string]any{"host": []string{host}}},
						"handle":   []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream}}}},
						"terminal": true,
					}},
				}},
			},
			"tls": map[string]any{"automation": map[string]any{"policies": []any{map[string]any{
				"subjects": []string{host}, "issuers": []any{map[string]any{"module": "internal"}}}}}},
			"pki": map[string]any{"certificate_authorities": map[string]any{"local": map[string]any{"install_trust": false}}},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func get(t *testing.T, httpsPort int) (int, string) {
	t.Helper()
	waitCert(t, httpsPort)
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
		},
	}}
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func upstream(t *testing.T, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, _, _ := w.(http.Hijacker).Hijack()
			defer conn.Close()
			fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

type env struct {
	httpPort, httpsPort int
	storage             string
}

func newEnv(t *testing.T) env {
	t.Helper()
	dir := t.TempDir() // registered first so it is removed after Caddy stops
	t.Cleanup(func() {
		_ = caddy.Stop()
		if t.Failed() {
			t.Log(strings.Join(caddylog.Sink.Lines(), ""))
		}
	})
	return env{freePort(t), freePort(t), dir}
}

// waitCert polls until the internal issuer has produced a cert (issuance is async after Load).
func waitCert(t *testing.T, httpsPort int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cert never issued: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLoadReloadAndRollback(t *testing.T) {
	e := newEnv(t)
	if err := caddy.Load(cfg(t, e.httpPort, e.httpsPort, e.storage, upstream(t, "one")), true); err != nil {
		t.Fatal(err)
	}
	if code, body := get(t, e.httpsPort); code != 200 || body != "one" {
		t.Fatalf("got %d %q", code, body)
	}

	if err := caddy.Load(cfg(t, e.httpPort, e.httpsPort, e.storage, upstream(t, "two")), true); err != nil {
		t.Fatal(err)
	}
	if _, body := get(t, e.httpsPort); body != "two" {
		t.Fatalf("new site not live: %q", body)
	}

	if err := caddy.Load([]byte(`{"apps":{"http":{"servers":{"s":{"routes":[{"handle":[{"handler":"nope"}]}]}}}}}`), true); err == nil {
		t.Fatal("invalid config accepted")
	}
	if _, body := get(t, e.httpsPort); body != "two" {
		t.Fatalf("old site lost after rejected load: %q", body)
	}
}

func TestLogWriterSurvivesReloads(t *testing.T) {
	e := newEnv(t)
	up := upstream(t, "x")
	last := caddylog.Sink.Total()
	for i := range 3 { // initial load + two reloads
		if err := caddy.Load(cfg(t, e.httpPort, e.httpsPort, e.storage, up), true); err != nil {
			t.Fatal(err)
		}
		if n := caddylog.Sink.Total(); n <= last {
			t.Fatalf("load %d: no new log lines (total %d)", i, n)
		} else {
			last = n
		}
	}
	waitCert(t, e.httpsPort) // let issuance finish before storage is removed
}

func TestAdminDisabled(t *testing.T) {
	e := newEnv(t)
	if err := caddy.Load(cfg(t, e.httpPort, e.httpsPort, e.storage, upstream(t, "x")), true); err != nil {
		t.Fatal(err)
	}
	waitCert(t, e.httpsPort)
	if c, err := net.Dial("tcp", "127.0.0.1:2019"); err == nil {
		c.Close()
		t.Fatal("admin API listening on :2019")
	}
}

func TestWebsocketUpgrade(t *testing.T) {
	e := newEnv(t)
	if err := caddy.Load(cfg(t, e.httpPort, e.httpsPort, e.storage, upstream(t, "x")), true); err != nil {
		t.Fatal(err)
	}
	waitCert(t, e.httpsPort)
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.httpsPort), &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", host)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("no 101: %q %v", line, err)
	}
}
