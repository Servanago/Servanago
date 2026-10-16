// Package caddylog is a Caddy log writer module feeding an in-memory ring.
package caddylog

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type Entry struct {
	Time   time.Time
	Level  string
	Logger string
	Msg    string
	Error  string
	Raw    string
}

var levelRank = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3, "dpanic": 3, "panic": 3, "fatal": 3}

// Ring keeps the last N entries. Write never blocks beyond a short mutex hold.
type Ring struct {
	mu      sync.Mutex
	max     int
	entries []Entry // oldest first
	total   int
}

func NewRing(max int) *Ring { return &Ring{max: max} }

// Write stores every line in p; it never fails, so a bad line cannot stall Caddy's logger.
func (r *Ring) Write(p []byte) (int, error) {
	var parsed []Entry
	for _, l := range bytes.Split(p, []byte("\n")) {
		if l = bytes.TrimSpace(l); len(l) > 0 {
			parsed = append(parsed, parseLine(l))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range parsed {
		if len(r.entries) == r.max {
			r.entries = r.entries[1:]
		}
		r.entries = append(r.entries, e)
		r.total++
	}
	return len(p), nil
}

func parseLine(l []byte) Entry {
	var j struct {
		Level  string
		Ts     float64
		Logger string
		Msg    string
		Error  string
	}
	if err := json.Unmarshal(l, &j); err != nil || j.Msg == "" && j.Level == "" {
		return Entry{Time: time.Now(), Level: "info", Msg: string(l), Raw: string(l)}
	}
	sec, frac := math.Modf(j.Ts)
	return Entry{Time: time.Unix(int64(sec), int64(math.Round(frac*1e9))), Level: j.Level, Logger: j.Logger, Msg: j.Msg, Error: j.Error, Raw: string(l)}
}

// Total counts every line ever written (monotonic, survives overflow).
func (r *Ring) Total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Entries returns entries at or above minLevel, newest first. Unknown or empty minLevel means all.
func (r *Ring) Entries(minLevel string) []Entry {
	min := levelRank[strings.ToLower(minLevel)] // unknown -> 0
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Entry, 0, len(r.entries))
	for i := len(r.entries) - 1; i >= 0; i-- {
		if levelRank[r.entries[i].Level] >= min {
			out = append(out, r.entries[i])
		}
	}
	return out
}

// Lines returns the raw stored lines, oldest first (test diagnostics).
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.entries))
	for i, e := range r.entries {
		out[i] = e.Raw + "\n"
	}
	return out
}

// LastError returns the newest error-level message mentioning host, or its parent wildcard ("*.parent").
func (r *Ring) LastError(host string) string {
	needles := []string{host}
	if _, parent, ok := strings.Cut(host, "."); ok {
		needles = append(needles, "*."+parent)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.entries) - 1; i >= 0; i-- {
		e := r.entries[i]
		if levelRank[e.Level] < levelRank["error"] {
			continue
		}
		for _, n := range needles {
			if strings.Contains(e.Raw, n) {
				if e.Error != "" {
					return e.Error
				}
				return e.Msg
			}
		}
	}
	return ""
}

// Sink is set before caddy.Load and read by the web layer.
var Sink = NewRing(1000)

func init() { caddy.RegisterModule(Writer{}) }

type Writer struct{}

func (Writer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.logging.writers.servanago", New: func() caddy.Module { return new(Writer) }}
}
func (Writer) String() string    { return "servanago" }
func (Writer) WriterKey() string { return "servanago:ring" }

// OpenWriter tees to the ring and stderr (so `docker logs` keeps working) with a no-op Close:
// Caddy closes dropped writers on reload and must not close either.
func (Writer) OpenWriter() (io.WriteCloser, error) {
	return nopCloser{io.MultiWriter(Sink, os.Stderr)}, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

var _ caddy.WriterOpener = (*Writer)(nil)
