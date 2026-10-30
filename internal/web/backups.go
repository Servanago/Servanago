// The Backups page: global settings, per-site opt-in with dump profiles and volumes, archives to download or restore,
// and the ingest of the backup job's result files. The job itself (root, `servanago backup-job`) is started through the
// helper; nothing here reads or writes site files.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/backup"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

const (
	minPassphrase = 20
	downloadTTL   = time.Minute
)

type archiveView struct {
	Name    string
	When    string
	Size    string
	Trigger string
	Damaged string
}

type profileView struct {
	Name, Engine, Target string
	HasSecret            bool
}

type scopeView struct {
	Scope      string // panel or the site slug
	Title      string
	SiteID     int64
	Panel      bool
	CanFiles   bool // the site has a folder to back up and restore
	On         bool
	Sched      string // the site's override ("" = inherit)
	Keep       int
	KeepWeekly int
	EffSched   string
	Due        bool
	LastText   string
	LastOK     bool
	LastErr    string
	LastOKText string
	Archives   []archiveView
	Profiles   []profileView
	Volumes    []string
	VolUsers   map[string]string // volume -> the containers that mount it, as text
}

// volumeUsers says, per volume, which containers mount it (the helper's cached docker-list).
func (s *Server) volumeUsers(ctx context.Context, vols []string) map[string]string {
	out := map[string]string{}
	d, err := s.dockerData(ctx)
	for _, v := range vols {
		if err != nil || !d.Present {
			out[v] = "container list unavailable"
			continue
		}
		var names []string
		for _, c := range d.Containers {
			if slices.Contains(c.Volumes, v) {
				names = append(names, c.Name+" ("+c.State+")")
			}
		}
		out[v] = "no containers use it"
		if len(names) > 0 {
			out[v] = "stops and restarts: " + strings.Join(names, ", ")
		}
	}
	return out
}

type backupsData struct {
	Set      store.BackupSettings
	PassSet  bool
	NtfySet  bool
	HasKey   bool
	NeedCode bool
	Running  bool
	JobState string
	Scopes   []scopeView
	Runs     []runView
	Warn     string
}

type runView struct {
	When, Scope, Trigger, Status, Archive, Size, Error, Actor string
}

// scopeOf builds one scope's view: the panel the Backups page renders and the facts the site's
// Backups tab shows. canFiles comes from the site's kind, which the caller knows.
func (s *Server) scopeOf(now time.Time, set store.BackupSettings, last map[string]store.BackupRun, lastOK map[string]int64,
	scope, title string, siteID int64, sb store.SiteBackup, isPanel, canFiles bool) scopeView {
	v := scopeView{Scope: scope, Title: title, SiteID: siteID, Panel: isPanel, On: sb.On || isPanel && set.Panel, Sched: sb.Sched, Keep: sb.Keep, KeepWeekly: sb.KeepWeekly, EffSched: set.Sched, CanFiles: canFiles}
	if sb.Sched != "" {
		v.EffSched = sb.Sched
	}
	if l, ok := last[scope]; ok {
		v.LastText = when(l.Finished) + " " + l.Status
		v.LastOK = l.Status == "ok"
		v.LastErr = l.Error
	} else {
		v.LastText = "never"
	}
	v.LastOKText = when(lastOK[scope])
	if sc, err := backup.ParseSched(v.EffSched); err == nil {
		v.Due = sc.Due(backup.Last(set.Dir, scope), now)
	}
	ins, _ := backup.List(set.Dir, scope)
	for _, in := range ins {
		v.Archives = append(v.Archives, archiveView{Name: in.Name, When: in.Manifest.Started.Local().Format("2006-01-02 15:04"), Size: humanBytes(in.Bytes), Trigger: in.Manifest.Trigger, Damaged: in.Damaged})
	}
	return v
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func when(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04")
}

func (s *Server) backupsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := s.deps.Store
	set, err := st.GetBackupSettings(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	sites, err := st.ListSites(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	last, lastOK, err := st.LastRuns(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := s.auth.now()
	d := backupsData{Set: set, PassSet: set.Pass != nil, NtfySet: set.Ntfy != nil, HasKey: s.deps.Cfg.SecretKey != "", NeedCode: s.needCode(r), Warn: s.backupWarnText()}
	if resp, err := s.helperClient().Call(ctx, helper.ActionBackupStatus, helper.Spec{}); err == nil && resp.Status != nil {
		d.JobState = resp.Status.ActiveState
		d.Running = resp.Status.ActiveState == "active" || resp.Status.ActiveState == "activating"
	}
	mk := func(scope, title string, siteID int64, sb store.SiteBackup, isPanel, canFiles bool) scopeView {
		return s.scopeOf(now, set, last, lastOK, scope, title, siteID, sb, isPanel, canFiles)
	}
	d.Scopes = append(d.Scopes, mk("panel", "Panel (database, certificates, secret key)", 0, store.SiteBackup{}, true, false))
	for _, site := range sites {
		sb, err := st.GetSiteBackup(ctx, site.ID)
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		v := mk(site.Slug, site.Hostnames[0], site.ID, sb, false, site.Kind != "" && site.Kind != "proxy")
		ps, _ := st.ListProfiles(ctx, site.ID)
		for _, p := range ps {
			t := p.Container + " / " + p.DB
			if p.Engine == "sqlite" {
				t = p.Path
			}
			v.Profiles = append(v.Profiles, profileView{Name: p.Name, Engine: p.Engine, Target: t, HasSecret: p.Secret != nil})
		}
		v.Volumes, _ = st.ListVolumes(ctx, site.ID)
		if len(v.Volumes) > 0 {
			v.VolUsers = s.volumeUsers(ctx, v.Volumes)
		}
		d.Scopes = append(d.Scopes, v)
	}
	if rs, err := st.ListRuns(ctx, "", 30); err == nil {
		for _, x := range rs {
			rv := runView{When: when(x.Finished), Scope: x.Scope, Trigger: x.Trigger, Status: x.Status, Archive: x.Archive, Error: x.Error, Actor: x.Actor}
			if x.Bytes > 0 {
				rv.Size = humanBytes(x.Bytes)
			}
			d.Runs = append(d.Runs, rv)
		}
	}
	s.render(w, "backups", http.StatusOK, page{Title: "Backups", Data: d})
}

// saveBackupSettings stores the global settings, seals the passphrase and ntfy URL, and installs or removes the timer.
func (s *Server) saveBackupSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	cur, err := s.deps.Store.GetBackupSettings(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	next := cur
	next.Enabled, next.Panel = r.PostFormValue("enabled") != "", r.PostFormValue("panel") != ""
	next.Dir = strings.TrimSpace(r.PostFormValue("dir"))
	next.Sched = strings.TrimSpace(r.PostFormValue("sched"))
	if err := helper.ValidateSiteRoot(next.Dir); err != nil {
		fail(w, http.StatusUnprocessableEntity, "Backup folder: "+err.Error())
		return
	}
	if _, err := backup.ParseSched(next.Sched); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	var perr error
	if next.Keep, perr = strconv.Atoi(strings.TrimSpace(r.PostFormValue("keep"))); perr != nil || next.Keep < 1 || next.Keep > 365 {
		fail(w, http.StatusUnprocessableEntity, "Keep the newest must be a number from 1 to 365.")
		return
	}
	if next.KeepWeekly, perr = strconv.Atoi(strings.TrimSpace(r.PostFormValue("keep_weekly"))); perr != nil || next.KeepWeekly < 0 || next.KeepWeekly > 52 {
		fail(w, http.StatusUnprocessableEntity, "Keep weekly must be a number from 0 to 52.")
		return
	}
	pass, ntfy := r.PostFormValue("passphrase"), strings.TrimSpace(r.PostFormValue("ntfy"))
	if (pass != "" || ntfy != "") && s.deps.Cfg.SecretKey == "" {
		fail(w, http.StatusUnprocessableEntity, "Storing the passphrase or the ntfy address needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file.")
		return
	}
	if pass != "" {
		if len([]rune(pass)) < minPassphrase {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("The passphrase needs at least %d characters: it is all that protects the archives, which hold your secret key.", minPassphrase))
			return
		}
		if next.Pass, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(pass)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	switch {
	case r.PostFormValue("clear_ntfy") != "":
		next.Ntfy = nil
	case ntfy != "":
		if !strings.HasPrefix(ntfy, "https://") || len(ntfy) > 500 || strings.ContainsAny(ntfy, " \r\n\t") {
			fail(w, http.StatusUnprocessableEntity, "The ntfy address must be an https:// topic URL.")
			return
		}
		if next.Ntfy, err = secretbox.Seal(s.deps.Cfg.SecretKey, []byte(ntfy)); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if next.Enabled && next.Pass == nil {
		fail(w, http.StatusUnprocessableEntity, "Set a passphrase before turning backups on.")
		return
	}
	if (pass != "" || next.Enabled != cur.Enabled) && !s.confirm(w, r) { // the passphrase and the switch are what an attacker would change
		return
	}
	if err := s.deps.Store.SaveBackupSettings(ctx, next); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	if next.Enabled || cur.Enabled { // reinstalling is idempotent and keeps units current after an upgrade
		if _, err := s.helperClient().Call(ctx, helper.ActionBackupEnable, helper.Spec{Enabled: next.Enabled}); err != nil {
			s.audit(r, "backup.settings", "saved, but the timer change failed")
			fail(w, http.StatusBadGateway, "Saved, but the schedule could not be installed: "+err.Error())
			return
		}
	}
	s.audit(r, "backup.settings", fmt.Sprintf("enabled=%v", next.Enabled))
	if pass != "" {
		s.audit(r, "backup.passphrase", "")
	}
	s.refreshBackupWarn(ctx)
	hxRedirect(w, backOf(r, "/backups"))
}

// runBackup starts the job for one scope or all of them, now.
func (s *Server) runBackup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	spec := helper.Spec{Scope: r.PostFormValue("scope"), Actor: helperActor(r)}
	switch spec.Scope {
	case "all", "panel":
	case "site":
		site, ok := s.siteByForm(w, r)
		if !ok {
			return
		}
		spec.Slug = site.Slug
	default:
		fail(w, http.StatusBadRequest, "Unknown backup scope.")
		return
	}
	if _, err := s.helperClient().Call(r.Context(), helper.ActionBackupStart, spec); err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "backup.run", spec.Scope+" "+spec.Slug)
	s.flash("Backup started. Results appear here within a minute of it finishing.")
	hxRedirect(w, backOf(r, "/backups"))
}

func (s *Server) siteByForm(w http.ResponseWriter, r *http.Request) (store.Site, bool) {
	id, err := strconv.ParseInt(r.PostFormValue("site"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "Unknown site.")
		return store.Site{}, false
	}
	site, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "Unknown site.")
		return store.Site{}, false
	}
	return site, true
}

func (s *Server) pathSite(w http.ResponseWriter, r *http.Request) (store.Site, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "Unknown site.")
		return store.Site{}, false
	}
	site, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "Unknown site.")
		return store.Site{}, false
	}
	return site, true
}

// saveSiteBackup stores one site's opt-in and overrides.
func (s *Server) saveSiteBackup(w http.ResponseWriter, r *http.Request) {
	site, ok := s.pathSite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	sb := store.SiteBackup{On: r.PostFormValue("on") != "", Sched: strings.TrimSpace(r.PostFormValue("sched"))}
	if sb.Sched != "" {
		if _, err := backup.ParseSched(sb.Sched); err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	for name, dst := range map[string]*int{"keep": &sb.Keep, "keep_weekly": &sb.KeepWeekly} {
		if v := strings.TrimSpace(r.PostFormValue(name)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 365 {
				fail(w, http.StatusUnprocessableEntity, "Retention must be a number from 0 (inherit) to 365.")
				return
			}
			*dst = n
		}
	}
	if err := s.deps.Store.SaveSiteBackup(r.Context(), site.ID, sb); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "backup.site", fmt.Sprintf("%s on=%v", site.Slug, sb.On))
	hxRedirect(w, backOf(r, "/backups"))
}

func (s *Server) addBackupProfile(w http.ResponseWriter, r *http.Request) {
	site, ok := s.pathSite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	f := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	pw := r.PostFormValue("secret")
	p := backup.Profile{Name: f("name"), Engine: f("engine"), Container: f("container"), DB: f("db"), User: f("user"), Path: f("path"), Secret: pw}
	if p.Engine == "sqlite" {
		p.Container, p.DB, p.User, pw = "", "", "", ""
	} else {
		p.Path = ""
	}
	if err := p.Validate(); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	row := store.BackupProfile{SiteID: site.ID, Name: p.Name, Engine: p.Engine, Container: p.Container, DB: p.DB, User: p.User, Path: p.Path}
	if pw != "" {
		if s.deps.Cfg.SecretKey == "" {
			fail(w, http.StatusUnprocessableEntity, "Storing a database password needs SERVANAGO_SECRET_KEY in the environment file.")
			return
		}
		sealed, err := secretbox.Seal(s.deps.Cfg.SecretKey, []byte(pw))
		if err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		row.Secret = sealed
	}
	if err := s.deps.Store.AddProfile(r.Context(), row); err != nil {
		fail(w, http.StatusConflict, "That name is already used by another dump of this site.")
		return
	}
	s.audit(r, "backup.profile.add", site.Slug+" "+p.Name)
	hxRedirect(w, backOf(r, "/backups"))
}

func (s *Server) deleteBackupProfile(w http.ResponseWriter, r *http.Request) {
	site, ok := s.pathSite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PostFormValue("name")
	if err := s.deps.Store.DeleteProfile(r.Context(), site.ID, name); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "backup.profile.delete", site.Slug+" "+tidy(name, 32))
	hxRedirect(w, backOf(r, "/backups"))
}

func (s *Server) addBackupVolume(w http.ResponseWriter, r *http.Request) {
	site, ok := s.pathSite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	v := strings.TrimSpace(r.PostFormValue("volume"))
	if !backup.ValidVolume(v) {
		fail(w, http.StatusUnprocessableEntity, "That is not a valid volume name (letters, digits, _ . -).")
		return
	}
	if err := s.deps.Store.AddVolume(r.Context(), site.ID, v); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "backup.volume.add", site.Slug+" "+v)
	hxRedirect(w, backOf(r, "/backups"))
}

func (s *Server) deleteBackupVolume(w http.ResponseWriter, r *http.Request) {
	site, ok := s.pathSite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.deps.Store.DeleteVolume(r.Context(), site.ID, r.PostFormValue("volume")); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "backup.volume.delete", site.Slug)
	hxRedirect(w, backOf(r, "/backups"))
}

// scopeArchive validates an archive name against its scope and the files on disk and returns its path.
func (s *Server) scopeArchive(ctx context.Context, scope, name string) (string, error) {
	if _, err := s.scopeInfo(ctx, scope, name); err != nil {
		return "", err
	}
	set, _ := s.deps.Store.GetBackupSettings(ctx)
	return filepath.Join(set.Dir, scope, name), nil
}

// scopeInfo finds an undamaged archive of the scope in the backup folder.
func (s *Server) scopeInfo(ctx context.Context, scope, name string) (backup.Info, error) {
	set, err := s.deps.Store.GetBackupSettings(ctx)
	if err != nil {
		return backup.Info{}, err
	}
	if !backup.ValidName(name) || !strings.HasPrefix(name, scope+"-") {
		return backup.Info{}, fmt.Errorf("that is not an archive of %s", scope)
	}
	ins, err := backup.List(set.Dir, scope)
	if err != nil {
		return backup.Info{}, err
	}
	for _, in := range ins {
		if in.Name == name && in.Damaged == "" {
			return in, nil
		}
	}
	return backup.Info{}, fmt.Errorf("%s is not in the archive list (or is damaged)", name)
}

type downloadGrant struct {
	path, name, user string
	exp              time.Time
}

// startDownload re-authenticates and answers with a one-minute, single-use link. A plain POST cannot download a file
// through htmx, and the cookie alone must not be enough to take an archive.
func (s *Server) startDownload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	scope, name := r.PostFormValue("scope"), r.PostFormValue("name")
	if scope != "panel" && helper.ValidateSlug(scope) != nil {
		fail(w, http.StatusBadRequest, "Unknown scope.")
		return
	}
	path, err := s.scopeArchive(r.Context(), scope, name)
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	if !s.confirm(w, r) {
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	g := downloadGrant{path: path, name: name, exp: s.auth.now().Add(downloadTTL)}
	if u, ok := currentUser(r); ok {
		g.user = u.Username
	}
	s.downloads.Store(tok, g)
	s.audit(r, "backup.download", scope+" "+name)
	hxRedirect(w, "/backups/file/"+tok)
}

func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	v, ok := s.downloads.LoadAndDelete(r.PathValue("token"))
	if !ok {
		http.Error(w, "This download link was used or has expired.", http.StatusGone)
		return
	}
	g := v.(downloadGrant)
	if u, signed := currentUser(r); (signed && u.Username != g.user) || s.auth.now().After(g.exp) {
		http.Error(w, "This download link was used or has expired.", http.StatusGone)
		return
	}
	f, err := os.Open(g.path)
	if err != nil {
		http.Error(w, "The archive is no longer there.", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The UI server's write timeout is 60 s; an archive can take longer than that to send.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+g.name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, g.name, fi.ModTime(), f)
}

// restoreBackup asks the helper to restore one site from one of its archives. The job takes a pre-restore backup first.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	site, ok := s.siteByForm(w, r)
	if !ok {
		return
	}
	spec, serr := s.checkRestore(r.Context(), site, r.PostFormValue("name"), r.PostFormValue("files") != "", r.PostFormValue("dumps") != "", r.PostForm["volumes"])
	if serr != nil {
		fail(w, serr.code, serr.msg)
		return
	}
	if r.PostFormValue("sure") != site.Slug {
		fail(w, http.StatusUnprocessableEntity, "Type the site's short name ("+site.Slug+") to confirm: a restore overwrites files, databases and volumes.")
		return
	}
	if !s.confirm(w, r) {
		return
	}
	if serr := s.sendRestore(r, site, spec); serr != nil {
		fail(w, serr.code, serr.msg)
		return
	}
	hxRedirect(w, backOf(r, "/backups"))
}

// helperActor is the signed-in user's name as the helper accepts it (no spaces: the MCP actor is "mcp token").
func helperActor(r *http.Request) string {
	u, _ := currentUser(r)
	return strings.ReplaceAll(u.Username, " ", "-")
}

type statusErr struct {
	code int
	msg  string
}

// checkRestore validates a restore request without side effects and returns the helper spec for it. Shared by the page
// and the MCP tool, which differ only in how they confirm.
func (s *Server) checkRestore(ctx context.Context, site store.Site, name string, files, dumps bool, volumes []string) (helper.Spec, *statusErr) {
	in, err := s.scopeInfo(ctx, site.Slug, name)
	if err != nil {
		return helper.Spec{}, &statusErr{http.StatusNotFound, err.Error()}
	}
	spec := helper.Spec{Slug: site.Slug, Archive: name, RestoreFiles: files, RestoreDumps: dumps, RestoreVolumes: volumes}
	if !files && !dumps && len(volumes) == 0 {
		return spec, &statusErr{http.StatusUnprocessableEntity, "Tick files, database dumps, volumes or any of them."}
	}
	on, _ := s.deps.Store.ListVolumes(ctx, site.ID)
	for _, v := range volumes {
		if !slices.Contains(on, v) || !slices.Contains(in.Manifest.Volumes, v) {
			return spec, &statusErr{http.StatusUnprocessableEntity, "Volume " + v + " is not switched on for this site and in that archive."}
		}
	}
	return spec, nil
}

// sendRestore asks the helper to start the restore, then audits and flashes. The job takes a pre-restore backup first.
func (s *Server) sendRestore(r *http.Request, site store.Site, spec helper.Spec) *statusErr {
	spec.Actor = helperActor(r)
	if _, err := s.helperClient().Call(r.Context(), helper.ActionBackupRestore, spec); err != nil {
		return &statusErr{http.StatusBadGateway, err.Error()}
	}
	s.audit(r, "backup.restore", strings.TrimSpace(site.Slug+" "+spec.Archive+" "+strings.Join(spec.RestoreVolumes, ",")))
	s.flash("Restore started for " + site.Slug + ". The current state is backed up first; the result appears under Recent runs.")
	return nil
}

// ---- ingest ----

// RunBackupIngest reads the job's result files into the run history once a minute.
func (s *Server) RunBackupIngest(ctx context.Context) {
	for {
		s.ingestBackups(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func (s *Server) ingestBackups(ctx context.Context) {
	if s.deps.Store == nil {
		return
	}
	set, err := s.deps.Store.GetBackupSettings(ctx)
	if err != nil {
		slog.Error("backup ingest settings", "error", err)
		return
	}
	ents, err := os.ReadDir(filepath.Join(set.Dir, ".runs"))
	if err == nil {
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(set.Dir, ".runs", e.Name()))
			var res backup.Result
			if err != nil || json.Unmarshal(b, &res) != nil || res.RunID == "" {
				continue
			}
			fresh, err := s.deps.Store.AddRun(ctx, store.BackupRun{RunID: res.RunID, Scope: res.Scope, Trigger: res.Trigger, Actor: res.Actor, Status: res.Status,
				Archive: res.Archive, Bytes: res.Bytes, Error: res.Error, Started: res.Started, Finished: res.Finished})
			if err != nil {
				slog.Error("backup ingest", "error", err)
				continue
			}
			if fresh {
				s.auditBackupResult(ctx, res)
				s.ingestScanOf(ctx, res)
			}
		}
	}
	s.refreshBackupWarn(ctx)
}

// ingestScanOf turns a backup scope's scan pass into Scan page rows: one run row (trigger
// backup) and its quarantined hits. Scopes without a scan pass add nothing.
func (s *Server) ingestScanOf(ctx context.Context, res backup.Result) {
	if res.Scanned == 0 && len(res.Infected) == 0 {
		return
	}
	var siteID int64
	if sites, err := s.deps.Store.ListSites(ctx); err == nil {
		for _, x := range sites {
			if x.Slug == res.Scope {
				siteID = x.ID
			}
		}
	}
	if siteID == 0 {
		slog.Warn("backup scan rows", "scope", res.Scope, "error", "no site with this slug; the hits stay in the result and the manifest")
		return
	}
	runID, err := s.deps.Store.InsertScanRun(ctx, siteID, "backup", res.Started)
	if err != nil {
		slog.Error("backup scan rows", "scope", res.Scope, "error", err)
		return
	}
	for _, h := range res.Infected {
		if _, err := s.deps.Store.AddScanHit(ctx, store.ScanHit{RunID: runID, SiteID: siteID, Path: h.Path, Virus: h.Virus,
			Action: map[bool]string{true: "quarantined", false: "live"}[h.To != ""], QuarantinedTo: h.To, UpdatedAt: res.Finished}); err != nil {
			slog.Error("backup scan hit row", "path", h.Path, "error", err)
		}
	}
	state := "ok"
	if res.Status != "ok" {
		state = "error"
	}
	if err := s.deps.Store.FinishScanRun(ctx, runID, state, res.Scanned, 0, res.Error); err != nil {
		slog.Error("backup scan run finish", "error", err)
	}
	if err := s.deps.Store.PruneScanRuns(ctx, 50); err != nil {
		slog.Error("scan prune", "error", err)
	}
}

func (s *Server) auditBackupResult(ctx context.Context, r backup.Result) {
	action := "backup." + r.Status
	if r.Trigger == "restore" {
		action = "restore." + map[string]string{"ok": "done", "failed": "failed"}[r.Status]
	}
	actor := r.Actor
	if actor == "" {
		actor = "system"
	}
	target := r.Scope
	if r.Error != "" {
		target += ": " + r.Error
	}
	e := store.AuditEntry{At: time.Unix(r.Finished, 0).UTC().Format(time.RFC3339), Actor: tidy(actor, 64), Action: action, Target: tidy(target, 200)}
	if err := s.deps.Store.AddAudit(ctx, e); err != nil {
		slog.Error("write backup audit row", "error", err)
	}
}

// staleScopes names the scopes whose newest success is older than twice their schedule interval, and the scopes whose
// latest run failed. A scope that has never run is not stale: its first run is due within a quarter hour.
func staleScopes(now time.Time, set store.BackupSettings, scopes map[string]string, last map[string]store.BackupRun, lastOK map[string]int64) []string {
	var out []string
	for scope, sched := range scopes {
		l, ran := last[scope]
		if !ran {
			continue
		}
		if sched == "" {
			sched = set.Sched
		}
		if l.Status == "failed" {
			out = append(out, scope+" failed: "+tidy(l.Error, 120))
			continue
		}
		if sc, err := backup.ParseSched(sched); err == nil {
			if ok := lastOK[scope]; ok == 0 || now.Sub(time.Unix(ok, 0)) > 2*sc.Interval() {
				out = append(out, scope+" has no recent successful backup")
			}
		}
	}
	return out
}

func (s *Server) refreshBackupWarn(ctx context.Context) {
	set, err := s.deps.Store.GetBackupSettings(ctx)
	if err != nil || !set.Enabled {
		s.backupWarn.Store("")
		return
	}
	last, lastOK, err := s.deps.Store.LastRuns(ctx)
	if err != nil {
		return
	}
	scopes := map[string]string{}
	if set.Panel {
		scopes["panel"] = ""
	}
	if sites, err := s.deps.Store.ListSites(ctx); err == nil {
		for _, site := range sites {
			if sb, err := s.deps.Store.GetSiteBackup(ctx, site.ID); err == nil && sb.On {
				scopes[site.Slug] = sb.Sched
			}
		}
	}
	s.backupWarn.Store(strings.Join(staleScopes(s.auth.now(), set, scopes, last, lastOK), "; "))
}

func (s *Server) backupWarnText() string {
	v, _ := s.backupWarn.Load().(string)
	return v
}
