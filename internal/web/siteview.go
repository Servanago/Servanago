package web

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/probe"
	"github.com/servanago/servanago/internal/store"
)

// siteview.go: the per-site control view. One server-rendered page per tab at /sites/<id>/<tab>;
// the full editor (Settings) stays at /sites/<id>. Tabs show what the site has and reuse the same
// store rows and endpoints the lists use; their forms send back= so an action lands on the tab
// that called it (backOf in auth.go).

// siteTabs are the tab paths under /sites/<id>/; the rail lists Settings first (that path redirects here).
var siteTabs = []string{"dns", "ssl", "scan", "backups", "mail", "snippets", "runtime", "gate", "routes", "countries"}

var siteTabTitle = map[string]string{
	"dns": "DNS", "ssl": "SSL", "scan": "Virus scanning", "backups": "Backups", "mail": "Mail",
	"snippets": "Snippets", "runtime": "Runtime", "gate": "Gate", "routes": "Routes", "countries": "Countries",
}

// siteTabPage serves one tab of the site view.
func (s *Server) siteTabPage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tab := r.PathValue("tab")
	if tab == "settings" {
		http.Redirect(w, r, "/sites/"+fmt.Sprint(id), http.StatusSeeOther)
		return
	}
	if !slices.Contains(siteTabs, tab) {
		http.NotFound(w, r)
		return
	}
	rt, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.siteViewPage(w, r, rt, tab)
}

// certFacts is one hostname's certificate as the SSL tab reports it.
type certFacts struct {
	Host string
	probe.CertStatus
}

// routeRow is one parsed extra-route line (path=dial) on the Routes tab.
type routeRow struct{ Path, Dial string }

type siteViewData struct {
	Site   store.Site
	Active string
	Title  string
	DNSOn  bool // Cloudflare is configured
	MailOK bool // gate mail can work: session key and Cloudflare
	GeoOn  bool
	ScanOn bool
	// Row carries the probe and DNS state the lists compute (nil when the store failed).
	Row         *siteRow
	Certs       []certFacts // one per hostname, probed only while the site is served
	Scans       []scanRunRow
	Unit        *unitPanel
	Grants      []store.Grant
	Snips       []snippetOpt
	Backup      scopeView
	BackHas     bool // a backup scope view really was built (GetSiteBackup and GetBackupSettings succeed)
	BackRuns    []runView
	SetSched    string // the backups page's default schedule, quoted on the tab
	CountryText string
	Routes      []routeRow
}

func (s *Server) siteViewPage(w http.ResponseWriter, r *http.Request, rt store.Site, tab string) {
	d := siteViewData{Site: rt, Active: tab, Title: siteTabTitle[tab],
		DNSOn: s.dnsOn(), MailOK: s.gateUsable(),
		CountryText: strings.Join(strings.Fields(rt.Countries), ", ")}
	if st, err := s.deps.Store.GetSettings(r.Context()); err == nil {
		d.GeoOn, d.ScanOn = st.GeoDB != "", st.ScanSocket != ""
	}
	if set, err := s.deps.Store.GetBackupSettings(r.Context()); err == nil {
		d.SetSched = set.Sched
		if sb, err := s.deps.Store.GetSiteBackup(r.Context(), rt.ID); err == nil {
			last, lastOK, _ := s.deps.Store.LastRuns(r.Context())
			d.Backup = s.scopeOf(s.auth.now(), set, last, lastOK, rt.Slug, rt.Hostnames[0], rt.ID, sb, false, rt.Kind != "" && rt.Kind != "proxy")
			d.BackHas = true
		}
		if rs, err := s.deps.Store.ListRuns(r.Context(), rt.Slug, 10); err == nil {
			for _, x := range rs {
				rv := runView{When: when(x.Finished), Scope: x.Scope, Trigger: x.Trigger, Status: x.Status, Archive: x.Archive, Error: x.Error, Actor: x.Actor}
				if x.Bytes > 0 {
					rv.Size = humanBytes(x.Bytes)
				}
				d.BackRuns = append(d.BackRuns, rv)
			}
		}
	}
	if rows, err := s.buildRows(r, []store.Site{rt}); err == nil && len(rows) == 1 {
		d.Row = &rows[0]
	}
	// The row probe covers the primary hostname; the tab asks every host while the site is served.
	if d.Row != nil && d.Row.Probed && s.deps.Probe != nil {
		cs := make([]certFacts, len(rt.Hostnames))
		probe.Parallel(len(cs), func(i int) {
			cs[i] = certFacts{Host: rt.Hostnames[i], CertStatus: s.deps.Probe.Cert(r.Context(), rt.Hostnames[i])}
		})
		d.Certs = cs
	}
	if d.ScanOn {
		if runs, err := s.deps.Store.ListScanRuns(r.Context(), rt.ID, 10); err == nil && len(runs) > 0 {
			ids := make([]int64, 0, len(runs))
			for _, run := range runs {
				ids = append(ids, run.ID)
			}
			hits, _ := s.deps.Store.ListRunsHits(r.Context(), ids)
			d.Scans = make([]scanRunRow, len(runs))
			for i, run := range runs {
				d.Scans[i] = scanRunRow{ScanRun: run, SiteName: rt.Hostnames[0], Hits: hits[run.ID]}
			}
		}
	}
	d.Unit = s.unitPanelFor(r, rt)
	if gs, err := s.deps.Store.Grants(r.Context(), rt.ID); err == nil {
		d.Grants = gs
	}
	if all, err := s.deps.Store.ListSnippets(r.Context()); err == nil {
		for _, x := range all {
			d.Snips = append(d.Snips, snippetOpt{x.Name, slices.Contains(rt.Snippets, x.Name)})
		}
	}
	for _, line := range strings.Split(rt.ExtraRoutes, "\n") {
		if path, dial, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			d.Routes = append(d.Routes, routeRow{Path: path, Dial: dial})
		}
	}
	s.render(w, "siteview", http.StatusOK, page{Title: d.Title + " · " + rt.Hostnames[0], Nav: "dashboard", Data: d})
}
