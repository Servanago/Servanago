// Package cftest is a stateful in-memory fake of the Cloudflare DNS endpoints ServanaGo uses.
package cftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type Record struct {
	ID, Name, Content string
	Type              string // "A" or "AAAA"
	Proxied           bool
	Comment           string
	TTL               int // 0 behaves as 1 (Auto), like the real API
	Priority          int // MX/SRV priority
	Data              map[string]any
}

// typeOf is the record type implied by an address: IPv6 text has colons.
func typeOf(content string) string {
	if strings.Contains(content, ":") {
		return "AAAA"
	}
	return "A"
}

type Fake struct {
	URL string

	mu      sync.Mutex
	records map[string]Record
	next    int
	writes  int
	failMsg string
	zones   map[string]string // zone name -> id
	// PageSize caps every listing's per_page; 0 keeps the client's request. Tests set 1 to walk pages.
	PageSize int
}

func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{records: map[string]Record{}, zones: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.URL = srv.URL
	return f
}

// Seed adds a pre-existing record and returns its id. An IPv6 address makes it an AAAA record.
func (f *Fake) Seed(name, content string) string {
	return f.Add(Record{Name: name, Content: content})
}

// Add adds one record verbatim and returns its id; Type defaults to the family the content implies.
func (f *Fake) Add(r Record) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if r.Type == "" {
		r.Type = typeOf(r.Content)
	}
	if r.TTL == 0 {
		r.TTL = 1
	}
	r.ID = fmt.Sprintf("rec%d", f.next)
	f.records[r.ID] = r
	return r.ID
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

// pageReply encodes a paginated listing's result_info faithfully; the SDK's auto-paginator
// walks pages by replaying the query, so only result content decides where pages end.
func pageReply(w http.ResponseWriter, page []any, info map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": page, "result_info": info})
}

func (r Record) json() map[string]any {
	t := r.Type
	if t == "" {
		t = "A"
	}
	m := map[string]any{"id": r.ID, "name": r.Name, "content": r.Content, "type": t, "proxied": r.Proxied, "comment": r.Comment, "ttl": max(r.TTL, 1)}
	if r.Priority != 0 {
		m["priority"] = r.Priority
	}
	if r.Data != nil {
		m["data"] = r.Data
	}
	return m
}

// pageRange computes [from,to] for one page of n items, mirroring the real API's page/per_page
// params, plus the per_page and page it actually used (for result_info).
func (f *Fake) pageRange(r *http.Request, n int) (from, to, per, page int) {
	per = 100
	if v, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && v > 0 {
		per = v
	}
	if f.PageSize > 0 && per > f.PageSize {
		per = f.PageSize
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
		page = v
	} else {
		page = 1
	}
	from, to = (page-1)*per, min(page*per, n)
	if from > n {
		from = n
	}
	return from, to, per, page
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/") // zones/{z}/dns_records[/{id}]
	if len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet {
		if name := strings.ToLower(r.URL.Query().Get("name")); name != "" { // zone lookup by name
			res := []any{}
			if id, ok := f.zones[name]; ok {
				res = append(res, map[string]any{"id": id, "name": name})
			}
			reply(w, 200, true, res, "")
			return
		}
		names := make([]string, 0, len(f.zones)) // sorted by name, so paging is deterministic
		for n := range f.zones {
			names = append(names, n)
		}
		sort.Strings(names)
		from, to, per, pg := f.pageRange(r, len(names))
		page := []any{}
		for _, n := range names[from:to] {
			page = append(page, map[string]any{"id": f.zones[n], "name": n, "status": "active"})
		}
		pageReply(w, page, map[string]any{"page": pg, "per_page": per, "count": len(page), "total_pages": max(1, (len(names)+per-1)/per), "total_count": len(names)})
		return
	}
	if len(parts) == 2 && parts[0] == "zones" && r.Method == http.MethodGet { // zone lookup by id
		for n, id := range f.zones {
			if id == parts[1] {
				reply(w, 200, true, map[string]any{"id": id, "name": n, "status": "active"}, "")
				return
			}
		}
		reply(w, 404, false, nil, "no such zone")
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
		want := r.URL.Query().Get("type")        // "" = every type, like the real API
		all := make([]Record, 0, len(f.records)) // sorted by type, name, id so paging is deterministic
		for _, rec := range f.records {
			all = append(all, rec)
		}
		sort.Slice(all, func(i, j int) bool {
			a, b := all[i], all[j]
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return a.ID < b.ID
		})
		res := []any{}
		for _, rec := range all {
			if (name == "" || strings.EqualFold(rec.Name, name)) && (want == "" || strings.EqualFold(want, rec.Type)) {
				res = append(res, rec.json())
			}
		}
		if _, has := r.URL.Query()["per_page"]; has { // the SDK walks pages; the name-filtered FindRecord does not
			from, to, per, pg := f.pageRange(r, len(res))
			count := len(res)
			pageReply(w, res[from:to], map[string]any{"page": pg, "per_page": per, "count": to - from, "total_count": count})
			return
		}
		reply(w, 200, true, res, "")
	case r.Method == http.MethodPost && id == "":
		var b struct {
			Name, Content, Comment, Type string
			Proxied                      bool
			TTL, Priority                float64
			Data                         map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.writes++
		f.next++
		rec := Record{ID: fmt.Sprintf("rec%d", f.next), Name: b.Name, Content: b.Content, Type: b.Type, Proxied: b.Proxied, Comment: b.Comment,
			TTL: max(int(b.TTL), 0), Priority: int(b.Priority), Data: b.Data}
		f.records[rec.ID] = rec
		reply(w, 200, true, rec.json(), "")
	case (r.Method == http.MethodPut || r.Method == http.MethodPatch) && id != "":
		rec, ok := f.records[id]
		if !ok {
			reply(w, 404, false, nil, "record not found")
			return
		}
		var b struct {
			Name, Content, Comment, Type string
			Proxied                      bool
			TTL, Priority                float64
			Data                         map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.writes++
		rec.Name, rec.Content, rec.Proxied, rec.Comment = b.Name, b.Content, b.Proxied, b.Comment
		if b.Type != "" {
			rec.Type = b.Type
		}
		if int(b.TTL) > 0 {
			rec.TTL = int(b.TTL)
		}
		rec.Priority, rec.Data = int(b.Priority), b.Data // a full rewrite: 0/nil are real values
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
