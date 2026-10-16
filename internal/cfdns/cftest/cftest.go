// Package cftest is a stateful in-memory fake of the Cloudflare DNS endpoints ServanaGo uses.
package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type Record struct {
	ID, Name, Content string
	Proxied           bool
	Comment           string
}

type Fake struct {
	URL string

	mu      sync.Mutex
	records map[string]Record
	next    int
	writes  int
	failMsg string
	zones   map[string]string // zone name -> id
}

func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{records: map[string]Record{}, zones: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// Seed adds a pre-existing record and returns its id.
func (f *Fake) Seed(name, content string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	id := fmt.Sprintf("rec%d", f.next)
	f.records[id] = Record{ID: id, Name: name, Content: content}
	return id
}

func (f *Fake) Records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Record, 0, len(f.records))
	for _, r := range f.records {
		out = append(out, r)
	}
	return out
}

// Writes counts create, update and delete calls received.
func (f *Fake) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// FailWith makes every DNS request answer 500 with this message; "" restores normal service.
func (f *Fake) FailWith(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failMsg = msg
}

func reply(w http.ResponseWriter, status int, ok bool, result any, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errs := []map[string]any{}
	if errMsg != "" {
		errs = append(errs, map[string]any{"code": 1000, "message": errMsg})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": ok, "errors": errs, "messages": []any{}, "result": result,
		"result_info": map[string]any{"page": 1, "per_page": 100, "count": 1, "total_count": 1}})
}

func (r Record) json() map[string]any {
	return map[string]any{"id": r.ID, "name": r.Name, "content": r.Content, "type": "A", "proxied": r.Proxied, "comment": r.Comment, "ttl": 1}
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")                // zones/{z}/dns_records[/{id}]
	if len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet { // zone lookup by name
		res := []any{}
		if id, ok := f.zones[strings.ToLower(r.URL.Query().Get("name"))]; ok {
			res = append(res, map[string]any{"id": id, "name": r.URL.Query().Get("name")})
		}
		reply(w, 200, true, res, "")
		return
	}
	if len(parts) < 3 || parts[0] != "zones" || parts[2] != "dns_records" {
		http.NotFound(w, r)
		return
	}
	if f.failMsg != "" {
		reply(w, http.StatusInternalServerError, false, nil, f.failMsg)
		return
	}
	var id string
	if len(parts) == 4 {
		id = parts[3]
	}
	switch {
	case r.Method == http.MethodGet && id == "":
		name := r.URL.Query().Get("name.exact")
		if name == "" {
			name = r.URL.Query().Get("name")
		}
		res := []any{}
		for _, rec := range f.records {
			if strings.EqualFold(rec.Name, name) {
				res = append(res, rec.json())
			}
		}
		reply(w, 200, true, res, "")
	case r.Method == http.MethodPost && id == "":
		var b struct {
			Name, Content, Comment string
			Proxied                bool
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.writes++
		f.next++
		rec := Record{ID: fmt.Sprintf("rec%d", f.next), Name: b.Name, Content: b.Content, Proxied: b.Proxied, Comment: b.Comment}
		f.records[rec.ID] = rec
		reply(w, 200, true, rec.json(), "")
	case (r.Method == http.MethodPut || r.Method == http.MethodPatch) && id != "":
		rec, ok := f.records[id]
		if !ok {
			reply(w, 404, false, nil, "record not found")
			return
		}
		var b struct {
			Name, Content string
			Proxied       bool
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.writes++
		rec.Name, rec.Content, rec.Proxied = b.Name, b.Content, b.Proxied
		f.records[id] = rec
		reply(w, 200, true, rec.json(), "")
	case r.Method == http.MethodDelete && id != "":
		if _, ok := f.records[id]; !ok {
			reply(w, 404, false, nil, "record not found")
			return
		}
		f.writes++
		delete(f.records, id)
		reply(w, 200, true, map[string]any{"id": id}, "")
	default:
		http.NotFound(w, r)
	}
}

// Clear removes every record (simulates deletion outside ServanaGo).
func (f *Fake) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = map[string]Record{}
}

// Handler exposes the fake for mounting inside a larger test server.
func (f *Fake) Handler() http.Handler { return http.HandlerFunc(f.serve) }

// AddZone makes GET /zones?name=name find a zone.
func (f *Fake) AddZone(name, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones[strings.ToLower(name)] = id
}
