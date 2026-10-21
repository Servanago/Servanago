package phpbuild

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPGetRetries(t *testing.T) {
	old := retryDelay
	retryDelay = []time.Duration{0, 0}
	t.Cleanup(func() { retryDelay = old })

	tests := []struct {
		name      string
		fail      int // answers 503 this many times first
		status    int // then this status
		wantTries int32
		wantErr   string
	}{
		{"recovers after two bad answers", 2, 200, 3, ""},
		{"gives up after three", 3, 200, 3, "503"},
		{"a 404 is final", 0, 404, 1, "404"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tries atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if int(tries.Add(1)) <= tt.fail {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte("body"))
			}))
			defer srv.Close()
			b, err := HTTPGet(context.Background(), srv.URL)
			if tries.Load() != tt.wantTries {
				t.Errorf("%d tries, want %d", tries.Load(), tt.wantTries)
			}
			switch {
			case tt.wantErr == "" && (err != nil || string(b) != "body"):
				t.Errorf("got %q, %v", b, err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("err %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHTTPGetRefusesRedirectToPlainHTTP(t *testing.T) {
	old := retryDelay
	retryDelay = []time.Duration{0, 0}
	t.Cleanup(func() { retryDelay = old })
	var tries atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tries.Add(1)
		http.Redirect(w, r, "http://mirror.example/file", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := HTTPGet(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("err %v", err)
	}
	if tries.Load() != 1 {
		t.Errorf("a refused redirect was retried %d times", tries.Load())
	}
}
