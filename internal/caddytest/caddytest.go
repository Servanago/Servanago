// Package caddytest holds helpers for integration tests that run the in-process Caddy.
// Tests using it must run serially (caddy.Load is a process global).
package caddytest

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/caddy-dns/cloudflare"
	"github.com/caretakarr/caretakarr/internal/caddylog"
)

// FreePort returns a currently unused loopback TCP port.
func FreePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Cleanup stops Caddy after the test, dumping captured log lines on failure.
// Call it before t.TempDir so storage is removed after Caddy stops.
func Cleanup(t testing.TB) {
	t.Cleanup(func() {
		_ = caddy.Stop()
		if t.Failed() {
			t.Log(strings.Join(caddylog.Sink.Lines(), ""))
		}
	})
}

// Upstream starts an HTTP server answering every request with body; returns host:port.
func Upstream(t testing.TB, body string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

// WaitCert polls until a TLS handshake for host succeeds (issuance is async after Load).
func WaitCert(t testing.TB, httpsPort int, host string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no cert for %s: %v", host, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Get requests https://host/ through the local HTTPS port, waiting for the cert first.
func Get(t testing.TB, httpsPort int, host string) (int, string) {
	t.Helper()
	WaitCert(t, httpsPort, host)
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

// GetAs is Get with HTTP basic credentials (skipped when user is empty).
func GetAs(t testing.TB, httpsPort int, host, user, pass string) (int, string) {
	t.Helper()
	WaitCert(t, httpsPort, host)
	c := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
		},
	}}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
