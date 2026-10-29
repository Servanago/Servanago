// Virus scanning: the settings section, the /scan pages, the per-site badge and Scan now, the
// sweep scheduler and the hit actions. internal/scan talks to clamd; this file is the driver and
// the bookkeeping (one run row per site per scan, hits quarantined + notified).
package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/scan"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// scanData is the /scan page.
type scanData struct {
	On       bool
	Socket   string
	PingErr  string
	Filter   string
	Rows     []scanRunRow
	Hour     string
	NtfySet  bool
	TokenSet bool
}

type scanRunRow struct {
	store.ScanRun
	SiteName string
	Hits     []store.ScanHit
}

// Running is the row's own state, spelled out for the templates.
func (r scanRunRow) Running() bool { return r.State == "running" }

func (s *Server) scanOn() bool {
	st, err := s.deps.Store.GetSettings(context.Background())
	return err == nil && st.ScanSocket != ""
}

// scanSocket reads the configured socket path ("" = scanning off).
func (s *Server) scanSocket(ctx context.Context) (string, error) {
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return "", err
	}
	return st.ScanSocket, nil
}

// scanRootOf is the directory a site serves: the folder, or its public folder when one is set.
// k kinds without a folder (proxy, node) return "".
func servedRootOf(r store.Site) string {
	if r.StaticRoot == "" {
		return ""
	}
	if r.PublicDir == "" {
		return r.StaticRoot
	}
	return filepath.Join(r.StaticRoot, r.PublicDir)
}

// scanable is true when a scan has content to walk.
func scanable(r store.Site) bool { return servedRootOf(r) != "" }

// quarantineDir is where a site's infected files wait for a decision.
func (s *Server) quarantineDir(slug string) string {
	return filepath.Join(s.deps.Cfg.DataDir, "quarantine", slug)
}

func (s *Server) scanPage(w http.ResponseWriter, r *http.Request) {
	d := scanData{}
	if st, err := s.deps.Store.GetSettings(r.Context()); err == nil {
		d.On, d.Socket, d.Hour = st.ScanSocket != "", st.ScanSocket, strconv.Itoa(st.ScanHour)
		d.NtfySet, d.TokenSet = st.ScanNtfy != nil, st.ScanNtfyToken != nil
	}
	if d.On {
		pctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		if err := scan.New(d.Socket).Ping(pctx); err != nil {
			d.PingErr = err.Error()
		}
		cancel()
	}
	sites, err := s.deps.Store.ListSites(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := map[int64]string{}
	for _, x := range sites {
		names[x.ID] = x.Hostnames[0]
	}
	runs, err := s.deps.Store.ListScanRuns(r.Context(), 0, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if f := strings.TrimSpace(r.FormValue("name")); f != "" { // the /scan page's site-name filter
		d.Filter = strings.ToLower(f)
	}
	ids := make([]int64, 0, len(runs))
	for i, run := range runs {
		name := names[run.SiteID]
		if d.Filter != "" && !strings.Contains(strings.ToLower(name)+strconv.FormatInt(run.SiteID, 10), d.Filter) {
			runs[i].SiteID = -1 // keep the slice indexes stable; below only the kept rows append
			continue
		}
		ids = append(ids, run.ID)
	}
	hits, _ := s.deps.Store.ListRunsHits(r.Context(), ids)
	d.Rows = make([]scanRunRow, 0, len(runs))
	for _, run := range runs {
		if run.SiteID == -1 {
			continue
		}
		d.Rows = append(d.Rows, scanRunRow{ScanRun: run, SiteName: names[run.SiteID], Hits: hits[run.ID]})
	}
	s.render(w, "scan", http.StatusOK, page{Title: "Virus scanning", Data: d})
}

// scanRunPage shows one run's hits with their actions.
type scanRunData struct {
	Run  scanRunRow
	Root string
}

func (s *Server) scanRunPage(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad run id")
		return
	}
	run, err := s.deps.Store.GetScanRun(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "no such scan run")
		return
	}
	d := scanRunData{Run: scanRunRow{ScanRun: run}}
	if x, err := s.deps.Store.GetSite(r.Context(), run.SiteID); err == nil {
		d.Run.SiteName = x.Hostnames[0]
	}
	if d.Run.Hits, err = s.deps.Store.ListScanHits(r.Context(), run.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "scanrun", http.StatusOK, page{Title: "Scan run", Data: d})
}

// startScanSite runs a manual scan in the background and answers at once.
func (s *Server) startScanSite(w http.ResponseWriter, r *http.Request) {
	if !s.scanOn() {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	x, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "no such site")
		return
	}
	if !scanable(x) {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is a %s site without a served folder: nothing to scan (proxy and node sites are skipped)", x.Hostnames[0], x.Kind))
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Minute)
	go func() {
		defer cancel()
		s.runScan(ctx, x, "manual")
	}()
	s.audit(r, "scan.started", x.Hostnames[0])
	w.Header().Set("HX-Redirect", "/scan")
	w.WriteHeader(http.StatusNoContent)
}

// runScan scans one site end to end: run row, walk, quarantine on find, notify, finish row.
func (s *Server) runScan(ctx context.Context, x store.Site, trigger string) {
	socket, err := s.scanSocket(ctx)
	if err != nil || socket == "" {
		return // scanning is off: a sweep simply does not happen
	}
	runID, err := s.deps.Store.InsertScanRun(ctx, x.ID, trigger, time.Now().Unix())
	if err != nil {
		slog.Error("scan run row", "site", x.ID, "error", err)
		return
	}
	root := servedRootOf(x)
	c := scan.New(socket)
	var hits []store.ScanHit
	res, err := c.ScanTree(ctx, root, func(path, virus string) error {
		action := "quarantined"
		to, qerr := scan.Quarantine(path, s.quarantineDir(x.Slug))
		if qerr != nil {
			slog.Warn("quarantine move failed", "path", path, "error", qerr)
			action, to = "error", ""
		}
		id, err := s.deps.Store.AddScanHit(ctx, store.ScanHit{RunID: runID, SiteID: x.ID, Path: path, Virus: virus, Action: action, QuarantinedTo: to})
		if err != nil {
			return err
		}
		hits = append(hits, store.ScanHit{ID: id, RunID: runID, SiteID: x.ID, Path: path, Virus: virus, Action: action, QuarantinedTo: to})
		return nil
	})
	errs := strings.Join(res.Errs, "; ")
	errText := errs
	if err != nil {
		errText = err.Error() + "; " + errs
	}
	state := "ok"
	if err != nil || len(res.Errs) > 0 {
		state = "error"
	}
	if err := s.deps.Store.FinishScanRun(ctx, runID, state, res.Files, res.Skipped, errText); err != nil {
		slog.Error("scan finish row", "run", runID, "error", err)
	}
	s.notifyHits(ctx, x, trigger, runID, hits)
	if err == nil {
		s.auditSystem(ctx, "scan."+trigger, fmt.Sprintf("%s: %d files, %d hits", x.Hostnames[0], res.Files, len(hits)))
	} else {
		s.auditSystem(ctx, "scan."+trigger, fmt.Sprintf("%s failed: %s", x.Hostnames[0], trimErr(errText, 160)))
	}
}

func trimErr(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

// notifyHits posts ntfy (urgent) and one mail for a run with hits; it never fails the run.
func (s *Server) notifyHits(ctx context.Context, x store.Site, trigger string, runID int64, hits []store.ScanHit) {
	if len(hits) == 0 {
		return
	}
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil {
		return
	}
	var lines []string
	for _, h := range hits {
		lines = append(lines, fmt.Sprintf("%s — %s (%s)", h.Path, h.Virus, h.Action))
	}
	message := x.Hostnames[0] + ": " + strings.Join(lines, "\n")
	if st.ScanNtfy != nil {
		token := ""
		if st.ScanNtfyToken != nil {
			if b, err := secretbox.Open(s.deps.Cfg.SecretKey, st.ScanNtfyToken); err == nil {
				token = string(b)
			}
		}
		if url, err := secretbox.Open(s.deps.Cfg.SecretKey, st.ScanNtfy); err == nil {
			if err := scan.Notify(ctx, string(url), token, "ServanaGo: virus found in "+x.Hostnames[0], message); err != nil {
				slog.Warn("scan ntfy", "error", err)
			}
		}
	}
	if st.MailReady() {
		body := "Virus scanning found " + strconv.Itoa(len(hits)) + " infected file(s) in " + x.Hostnames[0] + " (" + trigger + ", run " + strconv.FormatInt(runID, 10) + "):\n\n" +
			message + "\n\nOpen the Scan page to restore or ignore them; quarantined files are under " + s.quarantineDir(x.Slug) + ".\n"
		if err := s.sendMail(st.MailFrom, st.MailFrom, "ServanaGo: virus found in "+x.Hostnames[0], body); err != nil {
			slog.Warn("scan mail", "error", err)
		}
	}
}

// RunScans closes the runs a restart interrupted, then sweeps daily at the set hour until ctx ends.
func (s *Server) RunScans(ctx context.Context) {
	if err := s.deps.Store.FailRunningScans(ctx, "interrupted by restart"); err != nil {
		slog.Error("close interrupted scans", "error", err)
	}
	for {
		if err := s.sweepDue(ctx); err != nil {
			slog.Warn("scan sweep", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// sweepDue runs one sweep when the local hour reached scan_hour and today has none yet.
func (s *Server) sweepDue(ctx context.Context) error {
	st, err := s.deps.Store.GetSettings(ctx)
	if err != nil || st.ScanSocket == "" {
		return nil // scanning off: never sweep
	}
	if now := time.Now(); now.Hour() < st.ScanHour {
		return nil // earlier than the set hour
	}
	last, err := s.deps.Store.LastSweepAt(ctx)
	if err != nil {
		return err
	}
	if y, m, d := time.Unix(last, 0).Local().Date(); y == time.Now().Year() && m == time.Now().Month() && d == time.Now().Day() {
		return nil // already swept today
	}
	slog.Info("scan sweep starting", "hour", st.ScanHour)
	var failed int
	for _, x := range s.sitesBy(ctx, func(x store.Site) bool { return x.Enabled && scanable(x) }) {
		s.runScan(ctx, x, "sweep")
		if run, ok, qerr := s.deps.Store.LatestScanForSite(ctx, x.ID); qerr == nil && ok && run.State == "error" {
			failed++
		}
	}
	if err := s.deps.Store.PruneScanRuns(ctx, 50); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d site(s) failed during the sweep", failed)
	}
	return nil
}

// sitesBy is the enabled/scanable site list with a simple predicate.
func (s *Server) sitesBy(ctx context.Context, keep func(store.Site) bool) []store.Site {
	rs, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		return nil
	}
	var out []store.Site
	for _, x := range rs {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

// saveScan stores the scanning section of the Settings page: socket, hour and the ntfy secrets.
func (s *Server) saveScan(w http.ResponseWriter, r *http.Request) {
	socket := strings.TrimSpace(r.PostFormValue("scan_socket"))
	if socket != "" && !filepath.IsAbs(socket) {
		fail(w, http.StatusUnprocessableEntity, "The clamd socket path must be absolute, such as /run/clamav/clamd.ctl.")
		return
	}
	hour := 3
	if h := strings.TrimSpace(r.PostFormValue("scan_hour")); h != "" {
		var err error
		if hour, err = strconv.Atoi(h); err != nil || hour < 0 || hour > 23 {
			fail(w, http.StatusUnprocessableEntity, "The sweep hour must be 0-23 (UTC or local as the machine counts it).")
			return
		}
	}
	cur, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var ntfyURL, ntfyToken []byte
	clear := r.PostFormValue("clear_ntfy") != ""
	ntfy := strings.TrimSpace(r.PostFormValue("scan_ntfy"))
	if clear { // drop the topic and its token both
	} else if ntfy == "" {
		ntfyURL, ntfyToken = cur.ScanNtfy, cur.ScanNtfyToken
	} else if s.deps.Cfg.SecretKey == "" {
		fail(w, http.StatusUnprocessableEntity, "Storing the ntfy address needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file.")
		return
	} else {
		if !strings.HasPrefix(ntfy, "https://") || len(ntfy) > 500 || strings.ContainsAny(ntfy, " \r\n\t") {
			fail(w, http.StatusUnprocessableEntity, "The ntfy address must be an https:// topic URL.")
			return
		}
		if ntfyURL, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(ntfy)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tok := r.PostFormValue("scan_ntfy_token"); tok != "" {
			if ntfyToken, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(tok)); err != nil {
				fail(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			ntfyToken = cur.ScanNtfyToken
		}
	}
	st := store.Settings{
		SMTPHost:      cur.SMTPHost,
		SMTPPort:      cur.SMTPPort,
		SMTPUser:      cur.SMTPUser,
		SMTPPass:      cur.SMTPPass,
		MailFrom:      cur.MailFrom,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		ScanSocket:    socket,
		ScanHour:      hour,
		ScanNtfy:      ntfyURL,
		ScanNtfyToken: ntfyToken,
		// the geo panel owns its own columns: carry them over untouched
		GeoDB: cur.GeoDB, WebUIMode: cur.WebUIMode, WebUICountries: cur.WebUICountries,
	}
	if err := s.deps.Store.SaveSettings(r.Context(), st); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if st.ScanSocket != "" {
		pctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := scan.New(st.ScanSocket).Ping(pctx); err != nil {
			s.flash("Saved, but clamd did not answer on " + st.ScanSocket + ": " + err.Error() + " — installing clamd is `apt install clamav-daemon`, then check the socket path.")
		}
		cancel()
	}
	s.audit(r, "settings.scan", "socket="+st.ScanSocket)
	hxRedirect(w, "/settings")
}

// scanHitAction handles one of the three hit buttons: quarantine, restore, ignore.
func (s *Server) scanHitAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("hid"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad hit id")
		return
	}
	h, err := s.deps.Store.GetScanHit(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "no such scan hit")
		return
	}
	action := r.PathValue("do")
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
	defer cancel()
	switch action {
	case "quarantine":
		if h.Action == "quarantined" || h.Action == "ignored" {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is already quarantined", h.Path))
			return
		}
		to, err := scan.Quarantine(h.Path, s.siteSlugDir(ctx, h.SiteID))
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, "The file could not be moved out of the site: "+err.Error())
			return
		}
		err = s.deps.Store.SetScanHitAction(ctx, id, "quarantined", to)
		s.finishHit(ctx, r, h, w, "scan.hit_quarantined", to, err)
	case "restore":
		if h.QuarantinedTo == "" || h.Action == "live" {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is not quarantined", h.Path))
			return
		}
		if err := scan.Restore(h.QuarantinedTo, h.Path); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		err = s.deps.Store.SetScanHitAction(ctx, id, "restored", "")
		s.finishHit(ctx, r, h, w, "scan.hit_restored", "", err)
	case "ignore":
		if h.Action != "quarantined" {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is not quarantined", h.Path))
			return
		}
		err = s.deps.Store.SetScanHitAction(ctx, id, "ignored", h.QuarantinedTo)
		s.finishHit(ctx, r, h, w, "scan.hit_ignored", h.QuarantinedTo, err)
	default:
		fail(w, http.StatusBadRequest, "unknown hit action "+action)
	}
}

// siteSlugDir resolves a site's slug for its quarantine dir after the site row is gone too.
func (s *Server) siteSlugDir(ctx context.Context, siteID int64) string {
	slug := ""
	if x, err := s.deps.Store.GetSite(ctx, siteID); err == nil {
		slug = x.Slug
	} else {
		slug = strconv.FormatInt(siteID, 10) // the site is gone; the dir still groups its files
	}
	return s.quarantineDir(slug)
}

func (s *Server) finishHit(ctx context.Context, r *http.Request, h store.ScanHit, w http.ResponseWriter, action, to string, err error) {
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, action, h.Virus+" "+h.Path)
	w.Header().Set("HX-Redirect", "/scan/runs/"+strconv.FormatInt(h.RunID, 10))
	w.WriteHeader(http.StatusNoContent)
}

// saveGeo stores the country-filter section: the mmdb path and the panel's own rule. The file is
// geoipupdate's business; ServanaGo only reads it.
func (s *Server) saveGeo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	db := strings.TrimSpace(r.PostFormValue("geo_db"))
	if db != "" && !filepath.IsAbs(db) {
		fail(w, http.StatusUnprocessableEntity, "The MaxMind database path must be absolute, such as /var/lib/GeoIP/GeoLite2-Country.mmdb.")
		return
	}
	if db != "" {
		if _, err := os.Stat(db); os.IsNotExist(err) {
			s.flash("Saved, but no MaxMind database exists at " + db + " yet — installing geoipupdate fills it (apt install geoipupdate; the license key goes into /etc/GeoIP.conf).")
		}
	}
	cur, err := s.deps.Store.GetSettings(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	mode := r.PostFormValue("webui_mode")
	countries := ""
	if mode != "" {
		if mode != "deny" && mode != "allow" {
			fail(w, http.StatusUnprocessableEntity, "The panel's country mode must be deny, allow or empty (off).")
			return
		}
		codes, err := config.ValidateCountryList(r.PostFormValue("webui_countries"))
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		countries = strings.Join(codes, " ")
	}
	if err := s.deps.Store.SaveSettings(r.Context(), store.Settings{
		SMTPHost: cur.SMTPHost, SMTPPort: cur.SMTPPort, SMTPUser: cur.SMTPUser, SMTPPass: cur.SMTPPass, MailFrom: cur.MailFrom,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		ScanSocket: cur.ScanSocket, ScanHour: cur.ScanHour, ScanNtfy: cur.ScanNtfy, ScanNtfyToken: cur.ScanNtfyToken,
		GeoDB: db, WebUIMode: mode, WebUICountries: countries,
	}); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.geo.Use(db)
	s.geoRule.Store(geoRule{db: db, mode: mode, countries: countries})
	s.audit(r, "settings.geoip", "db="+db+" mode="+mode)
	hxRedirect(w, "/settings")
}
