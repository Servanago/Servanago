package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticHandler(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("index.html", "home")
	write("css/site.css", "body{}")
	write(".env", "SECRET=1")
	write(".git/config", "[core]")
	write("docs/readme.txt", "no index here")
	write("blog/index.html", "blog home")
	h := staticHandler(root)
	tests := []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/", 200, "home"},
		{"GET", "/css/site.css", 200, "body{}"},
		{"HEAD", "/css/site.css", 200, ""},
		{"GET", "/blog/", 200, "blog home"},
		{"GET", "/docs/readme.txt", 200, "no index here"},
		{"GET", "/docs/", 404, ""}, // no directory listing
		{"GET", "/.env", 404, ""},
		{"GET", "/.git/config", 404, ""},
		{"GET", "/css/../.env", 404, ""},
		{"GET", "/%2eenv", 404, ""},
		{"GET", "/nope", 404, ""},
		{"POST", "/", 405, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tt.method, tt.path, nil)
			h.ServeHTTP(w, r)
			if w.Code != tt.code {
				t.Fatalf("status %d, want %d (%q)", w.Code, tt.code, w.Body.String())
			}
			if tt.body != "" && w.Body.String() != tt.body {
				t.Errorf("body %q, want %q", w.Body.String(), tt.body)
			}
			if tt.code == http.StatusNotFound && (w.Body.String() == "SECRET=1" || w.Body.String() == "[core]") {
				t.Errorf("a dotfile was served")
			}
		})
	}
}

// systemd hands the socket as fd 3 with LISTEN_PID naming this process; anything else is refused.
func TestSystemdSocketRefusedWithoutTheHandoff(t *testing.T) {
	t.Setenv("LISTEN_PID", "1")
	t.Setenv("LISTEN_FDS", "1")
	if _, err := systemdListener(); err == nil {
		t.Error("a LISTEN_PID for another process was accepted")
	}
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	if _, err := systemdListener(); err == nil {
		t.Error("no socket handoff was accepted")
	}
}
