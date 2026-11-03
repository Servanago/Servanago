package web

import (
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/caddywaf"
	"github.com/servanago/servanago/internal/store"
)

// wafrulesPage serves the read-only rules browser of the site's WAF tab: the CRS files
// with their rule counts, and a per-file detail page with every id, message and tag —
// straight from the ruleset compiled into the binary (caddywaf.LoadCRS).
func (s *Server) wafrulesPage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rt, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rules, err := caddywaf.LoadCRS()
	if err != nil {
		slog.Error("waf rules parse", "error", err)
		s.render(w, "wafrules", http.StatusInternalServerError, page{Title: "WAF rules", Nav: "dashboard",
			Data: wafrulesData{Site: rt, Error: true}})
		return
	}

	// group by file
	files := []wafrulesFile{}
	byName := map[string]*wafrulesFile{}
	excl := map[string]bool{} // rows the site excluded, to grey them in the browser
	for _, x := range rt.Exclusions {
		excl[x.RuleID] = true
	}
	for _, r := range rules {
		f, ok := byName[r.File]
		if !ok {
			files = append(files, wafrulesFile{Name: r.File})
			f = &files[len(files)-1]
			byName[r.File] = f
		}
		f.Count++
		if _, ok := excl[r.ID]; ok {
			f.Excluded++
		}
	}
	slices.SortFunc(files, func(a, b wafrulesFile) int { return strings.Compare(a.Name, b.Name) })

	file := r.URL.Query().Get("file")
	var detail *wafrulesFile
	all := make([]caddywaf.CRSRule, 0)
	if file != "" && byName[file] != nil {
		for _, r := range rules {
			if r.File == file {
				all = append(all, r)
			}
		}
		idx := slices.IndexFunc(files, func(f wafrulesFile) bool { return f.Name == file })
		detail = &files[idx]
	}
	s.render(w, "wafrules", http.StatusOK, page{Title: rt.Hostnames[0] + " WAF rules", Nav: "dashboard", Data: wafrulesData{
		Site: rt, Active: "waf", Title: siteTabTitle["waf"], Files: files, Detail: detail, Rules: all, Excluded: excl,
	}})
}

type wafrulesFile struct {
	Name     string
	Count    int
	Excluded int
}

type wafrulesData struct {
	Site     store.Site
	Active   string
	Title    string
	Files    []wafrulesFile
	Detail   *wafrulesFile
	Rules    []caddywaf.CRSRule
	Excluded map[string]bool
	Error    bool // the embedded ruleset failed to parse (a broken build, surfaced in the log)
}
