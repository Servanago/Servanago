package main

import (
	"net/http"
	"testing"
	"time"
)

func TestUIServerHasTimeouts(t *testing.T) {
	s := newUIServer("127.0.0.1:0", http.NotFoundHandler())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 {
		t.Fatalf("missing timeout: %+v", s)
	}
	// the dashboard may probe upstreams while rendering, so the write budget must exceed a probe round
	if s.WriteTimeout < 30*time.Second {
		t.Errorf("WriteTimeout %v too small", s.WriteTimeout)
	}
}

func TestLoopbackDial(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:8080": "127.0.0.1:8080", "0.0.0.0:9000": "127.0.0.1:9000", ":8080": "127.0.0.1:8080",
		"192.168.1.5:80": "192.168.1.5:80", "[::]:8080": "127.0.0.1:8080",
	} {
		if got, err := loopbackDial(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := loopbackDial("nope"); err == nil {
		t.Error("bad address accepted")
	}
}
