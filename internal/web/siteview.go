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

// inplace answers an in-place save the way updateSite does: 200 with a short status line that
// htmx swaps into the form's message target.
func inplace(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, msg)
}

// mutateSite opens the apply transaction, lets fn change the stored site, and reports the result:
// every scoped save shares it.
func (s *Server) mutateSite(w http.ResponseWriter, r *http.Request, action string, fn func(*store.Site) error) bool {
	rt, ok := s.gateSite(w, r) // parses the form and loads the site; has answered when !ok
	if !ok {
		return false
	}
	if err := s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		cur, err := tx.GetSite(r.Context(), rt.ID)
		if err != nil {
			return userError{http.StatusNotFound, "site not found"}
		}
		if err := fn(&cur); err != nil {
			return userError{http.StatusUnprocessableEntity, err.Error()}
		}
		return tx.UpdateSite(r.Context(), cur)
	}); err != nil {
		failErr(w, err)
		return false
	}
	s.audit(r, action, rt.Hostnames[0])
	return true
}

// saveSiteGate writes the Gate tab's mode and mail block in place; grants keep their own rows.
func (s *Server) saveSiteGate(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.gate", func(rt *store.Site) error {
		mode := strings.TrimSpace(r.PostFormValue("gate_mode"))
		switch mode {
		case "", "acl", "open":
		default:
			return fmt.Errorf("access mode %q is unknown: use none, acl or open", mode)
		}
		rt.GateMode = mode
		if err := s.applyGateMail(rt, r.PostForm); err != nil {
			return err
		}
		if _, err := s.parseGate(r.Context(), *rt, r.PostForm); err != nil { // refuses a gate the app cannot honor
			return err
		}
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied. The gate covers every hostname; the first link takes a minute.")
}

// saveSiteAccess writes the IP allowlist and basic auth of the Gate tab in place.
func (s *Server) saveSiteAccess(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.access", func(rt *store.Site) error {
		if _, ok := r.PostForm["allowlist"]; ok {
			a, err := parseAllowlist(r.PostFormValue("allowlist"))
			if err != nil {
				return err
			}
			rt.Allowlist = a
		}
		if _, ok := r.PostForm["basic_user"]; ok {
			return applyBasicAuth(rt, strings.TrimSpace(r.PostFormValue("basic_user")), r.PostFormValue("basic_password"))
		}
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied.")
}

// saveSiteMail writes the mail provider block of the Mail tab in place. A blank credential keeps
// the stored one; the gate-mode checks only run for a site that actually gates.
func (s *Server) saveSiteMail(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.mail", func(rt *store.Site) error {
		if err := s.applyGateMail(rt, r.PostForm); err != nil {
			return err
		}
		if rt.GateMode != "" {
			if _, err := s.parseGate(r.Context(), *rt, r.PostForm); err != nil {
				return err
			}
		}
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied. A test mail goes out without saving.")
}
