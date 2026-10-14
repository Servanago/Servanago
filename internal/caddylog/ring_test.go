package caddylog

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func line(level, logger, msg string) string {
	return fmt.Sprintf(`{"level":%q,"ts":1791978000.5,"logger":%q,"msg":%q}`+"\n", level, logger, msg)
}

func TestParseJSONLine(t *testing.T) {
	r := NewRing(10)
	_, _ = r.Write([]byte(`{"level":"error","ts":1791978000.5,"logger":"tls.obtain","msg":"will retry","error":"dns challenge failed"}` + "\n"))
	es := r.Entries("")
	if len(es) != 1 {
		t.Fatalf("%d entries", len(es))
	}
	e := es[0]
	if e.Level != "error" || e.Logger != "tls.obtain" || e.Msg != "will retry" || e.Error != "dns challenge failed" {
		t.Fatalf("%+v", e)
	}
	if want := time.Unix(1791978000, 500_000_000); !e.Time.Equal(want) {
		t.Errorf("time %v want %v", e.Time, want)
	}
}

func TestMalformedLineIsKeptVerbatim(t *testing.T) {
	r := NewRing(10)
	n, err := r.Write([]byte("panic: something not json\n"))
	if err != nil || n != len("panic: something not json\n") {
		t.Fatalf("Write must report the full length and never fail: %d %v", n, err)
	}
	es := r.Entries("")
	if len(es) != 1 || es[0].Msg != "panic: something not json" || es[0].Level != "info" {
		t.Fatalf("%+v", es)
	}
}

func TestMultipleLinesInOneWrite(t *testing.T) {
	r := NewRing(10)
	_, _ = r.Write([]byte(line("info", "a", "one") + line("warn", "b", "two")))
	if es := r.Entries(""); len(es) != 2 {
		t.Fatalf("%d entries", len(es))
	}
}

func TestOverflowDropsOldest(t *testing.T) {
	r := NewRing(3)
	for i := range 5 {
		_, _ = r.Write([]byte(line("info", "x", fmt.Sprintf("m%d", i))))
	}
	es := r.Entries("")
	if len(es) != 3 || es[0].Msg != "m4" || es[2].Msg != "m2" { // newest first
		t.Fatalf("%+v", es)
	}
	if r.Total() != 5 {
		t.Errorf("total %d", r.Total())
	}
}

func TestLevelFilter(t *testing.T) {
	r := NewRing(10)
	for _, l := range []string{"debug", "info", "warn", "error"} {
		_, _ = r.Write([]byte(line(l, "x", l)))
	}
	for min, want := range map[string]int{"": 4, "debug": 4, "info": 3, "warn": 2, "error": 1, "bogus": 4} {
		if got := len(r.Entries(min)); got != want {
			t.Errorf("min %q: %d entries, want %d", min, got, want)
		}
	}
}

func TestConcurrentWrites(t *testing.T) {
	r := NewRing(100)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				_, _ = r.Write([]byte(line("info", "x", fmt.Sprintf("g%d-%d", g, i))))
				_ = r.Entries("")
			}
		}()
	}
	wg.Wait()
	if r.Total() != 1600 || len(r.Entries("")) != 100 {
		t.Fatalf("total %d len %d", r.Total(), len(r.Entries("")))
	}
}

func TestLastErrorMatchesHostAndWildcard(t *testing.T) {
	r := NewRing(10)
	_, _ = r.Write([]byte(line("info", "x", "unrelated app.example.com ok")))
	_, _ = r.Write([]byte(`{"level":"error","ts":1,"logger":"tls.obtain","msg":"will retry","error":"[*.example.com] Obtain: dns failed"}` + "\n"))
	_, _ = r.Write([]byte(`{"level":"error","ts":2,"logger":"tls.obtain","msg":"other","error":"[other.org] boom"}` + "\n"))
	if got := r.LastError("app.example.com"); !strings.Contains(got, "dns failed") {
		t.Errorf("wildcard error not matched: %q", got)
	}
	if got := r.LastError("nothing.net"); got != "" {
		t.Errorf("unexpected match: %q", got)
	}
	if got := r.LastError("other.org"); !strings.Contains(got, "boom") {
		t.Errorf("exact host not matched: %q", got)
	}
}
