// Package caddylog is a Caddy log writer module feeding an in-memory ring.
package caddylog

import (
	"io"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

// Ring keeps the last N written lines. Write never blocks beyond a short mutex hold.
type Ring struct {
	mu    sync.Mutex
	max   int
	lines []string
	total int
}

func NewRing(max int) *Ring { return &Ring{max: max} }

func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == r.max {
		r.lines = r.lines[1:]
	}
	r.lines = append(r.lines, string(p))
	r.total++
	return len(p), nil
}

// Total is the count of lines ever written (monotonic, survives overflow).
func (r *Ring) Total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// Sink is set before caddy.Load and read by the web layer.
var Sink = NewRing(1000)

func init() { caddy.RegisterModule(Writer{}) }

type Writer struct{}

func (Writer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.logging.writers.caretakarr", New: func() caddy.Module { return new(Writer) }}
}
func (Writer) String() string    { return "caretakarr" }
func (Writer) WriterKey() string { return "caretakarr:ring" }

// OpenWriter returns the ring with a no-op Close: Caddy closes dropped writers on reload.
func (Writer) OpenWriter() (io.WriteCloser, error) { return nopCloser{Sink}, nil }

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

var _ caddy.WriterOpener = (*Writer)(nil)
