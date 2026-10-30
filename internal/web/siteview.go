package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
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

// saveSiteSnippets replaces the site's attached snippets in place; the store refuses unknown names.
func (s *Server) saveSiteSnippets(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.snippets", func(rt *store.Site) error {
		rt.Snippets = nil
		for _, n := range r.PostForm["snippets"] {
			if n != "" {
				rt.Snippets = append(rt.Snippets, n)
			}
		}
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied.")
}

// saveSiteRoutes writes the extra routes box and (a proxy site's) tuning in place.
func (s *Server) saveSiteRoutes(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.routes", func(rt *store.Site) error {
		text, err := extraRoutesText(r.PostFormValue("extra_routes"))
		if err != nil {
			return err
		}
		rt.ExtraRoutes = text
		if _, ok := r.PostForm["tls_skip_verify"]; ok {
			rt.TLSSkipVerify = r.PostFormValue("tls_skip_verify") != ""
		}
		if _, ok := r.PostForm["stream"]; ok {
			rt.Stream = r.PostFormValue("stream") != ""
		}
		if _, ok := r.PostForm["max_body"]; ok {
			rt.MaxBody = 0
			if v := strings.TrimSpace(r.PostFormValue("max_body")); v != "" {
				n, err := config.ParseSize(v)
				if err != nil {
					return fmt.Errorf("upload limit: %w", err)
				}
				rt.MaxBody = n
			}
		}
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied.")
}

// saveSiteGeo writes the country rule in place.
func (s *Server) saveSiteGeo(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.geo", func(rt *store.Site) error {
		mode := r.PostFormValue("country_mode")
		if mode == "deny" || mode == "allow" {
			codes, err := config.ValidateCountryList(r.PostFormValue("countries"))
			if err != nil {
				return fmt.Errorf("country list: %w", err)
			}
			rt.Countries = strings.Join(codes, " ")
		} else if mode != "" {
			return fmt.Errorf("country mode %q must be deny, allow or empty (off)", mode)
		}
		rt.CountryMode = mode
		return nil
	}) {
		return
	}
	inplace(w, "Saved and applied. The rule applies to requests as soon as Caddy has reloaded.")
}

// siteRuntimeAction starts, stops or restarts the site's supervised unit through the helper,
// then answers the runtime tab's unit panel again (the page's fragment, no reload).
func (s *Server) siteRuntimeAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	do := r.PathValue("do")
	switch do {
	case "start", "stop", "restart":
	default:
		http.NotFound(w, r)
		return
	}
	rt, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !rt.IsRuntime() {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is a %s site: no supervised unit to %s.", rt.Hostnames[0], rt.Kind, do))
		return
	}
	hc := s.helperClient()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 60*time.Second)
	defer cancel()
	spec := helper.Spec{Slug: rt.Slug}
	do1 := helper.ActionUnitStop
	do2 := ""
	switch do {
	case "start":
		do1 = helper.ActionUnitStart
	case "restart":
		do2 = helper.ActionUnitStart
	}
	if _, err := hc.Call(ctx, do1, spec); err != nil {
		fail(w, http.StatusBadGateway, "systemd would not "+strings.TrimPrefix(do1, "unit-")+": "+err.Error())
		return
	}
	if do2 != "" {
		if _, err := hc.Call(ctx, do2, spec); err != nil {
			fail(w, http.StatusBadGateway, "systemd would not start: "+err.Error())
			return
		}
	}
	words := map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}
	s.audit(r, "site.unit_"+words[do], rt.Hostnames[0])
	panel := struct {
		Site store.Site
		Unit *unitPanel
	}{rt, s.unitPanelFor(r, rt)}
	s.renderPart(w, "siteview", "unitpanel", panel)
}

// renderPart renders one define of a registered page to the wire for an in-place update.
func (s *Server) renderPart(w http.ResponseWriter, pageName, def string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := s.pages[pageName].ExecuteTemplate(&buf, def, data); err != nil {
		slog.Error("render fragment", "define", def, "error", err)
		http.Error(w, "This update failed to render; the error is in the ServanaGo log.", http.StatusInternalServerError)
		return
	}
	_, _ = buf.WriteTo(w)
}

// saveSiteDNSIP writes the DNS record IP overrides in place.
func (s *Server) saveSiteDNSIP(w http.ResponseWriter, r *http.Request) {
	idParsed, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if !s.mutateSite(w, r, "site.dns_ip", func(rt *store.Site) error {
		if _, ok := r.PostForm["record_ip"]; ok {
			ip := strings.TrimSpace(r.PostFormValue("record_ip"))
			if ip != "" {
				if _, err := config.ValidateIP(ip); err != nil {
					return fmt.Errorf("record IP: %w", err)
				}
			}
			rt.RecordIP = ip
		}
		if _, ok := r.PostForm["record_ip6"]; ok {
			ip6 := strings.TrimSpace(r.PostFormValue("record_ip6"))
			if ip6 != "" {
				if _, err := config.ValidateIP6(ip6); err != nil {
					return fmt.Errorf("record IPv6: %w", err)
				}
			}
			rt.RecordIP6 = ip6
		}
		return nil
	}) {
		return
	}
	s.reconcile(r, idParsed) // the record's content changes with the override; the row updates detached
	inplace(w, "Saved and applied. The record updates in Cloudflare on the next sync.")
}
