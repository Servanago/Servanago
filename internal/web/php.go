package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/phpbuild"
	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/store"
)

// php.go: the PHP page. Builds ServanaGo compiled itself (runtimes.PHPRoot), a build started from the page, a switch of the
// sites on a branch to its newest build, and each login user's default CLI PHP. Privileged work goes through the helper;
// everything here is desired state in SQLite plus requests to the helper.

var (
	phpBranchRE  = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}$`)
	phpVersionRE = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}$`)
	phpLabelRE   = regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,3}-[0-9]{1,3})?$`)

	passwdFile       = "/etc/passwd"
	composerFilePath = "/opt/servanago/composer/composer.phar"
)

type buildView struct {
	Label       string
	Branch      string
	Libs        []string
	Sites       []string // hostnames running this exact build
	Newest      bool     // the newest build of its branch: the one a branch pin follows
	InUse       string   // why it cannot be pruned; "" = it can
	Unsupported bool     // its branch no longer gets security fixes
}

type jobView struct {
	Phase   string
	Version string
	Message string
	Logs    []string
	Active  bool
	Err     string // the helper could not be asked
}

type phpPageData struct {
	Builds     []buildView
	Branches   []string // branches with a build: Switch and the user-default picker offer these
	Labels     []string // everything a user default can name: branches, then exact builds
	Job        jobView
	Updates    []phpUpdate
	Releases   []phpRelease // latest release per supported branch, for the build form
	CheckedAt  string
	Defaults   []store.PHPUserDefault
	Users      []string
	ComposerOK bool
	NeedCode   bool
}

// confirm asks for the signed-in admin's password (and code) before a sensitive change. In open mode (no
// administrators exist, the whole UI is open) there is nobody to ask.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) bool {
	return !s.auth.enabled() || s.reauth(w, r)
}

// loginUsers lists the accounts a default PHP can be set for: regular users with a login shell.
func loginUsers() []string {
	f, err := os.Open(passwdFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) != 7 {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil || uid < 1000 || uid >= 65534 {
			continue
		}
		if sh := p[6]; sh == "" || strings.HasSuffix(sh, "/nologin") || strings.HasSuffix(sh, "/false") {
			continue
		}
		out = append(out, p[0])
	}
	sort.Strings(out)
	return out
}

func (s *Server) phpJob(ctx context.Context) jobView {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := s.helperClient().Call(cctx, helper.ActionPHPStatus, helper.Spec{Lines: 40})
	if err != nil || resp.Build == nil {
		return jobView{Phase: phpbuild.PhaseIdle, Err: fmt.Sprintf("The ServanaGo helper could not report the build state (%v). Check `systemctl status servanago-helper`.", err)}
	}
	b := resp.Build
	return jobView{Phase: b.Phase, Version: b.Version, Message: b.Message, Logs: resp.Logs,
		Active: b.Phase == phpbuild.PhaseFetching || b.Phase == phpbuild.PhaseBuilding}
}

// buildViews describes every exact build on the host: who runs it, what it was linked against, whether it can go.
func buildViews(rep runtimes.Report, sites []store.Site, defaults []store.PHPUserDefault, latest map[string]phpRelease) []buildView {
	var out []buildView
	newest := map[string]string{}
	count := map[string]int{}
	for _, p := range rep.PHP {
		if p.Source && runtimes.BuildRE.MatchString(p.Version) {
			count[runtimes.Branch(p.Version)]++
			if _, ok := newest[runtimes.Branch(p.Version)]; !ok { // rep.PHP is newest first
				newest[runtimes.Branch(p.Version)] = p.Version
			}
		}
	}
	for _, p := range rep.PHP {
		if !p.Source || !runtimes.BuildRE.MatchString(p.Version) {
			continue
		}
		b := buildView{Label: p.Version, Branch: runtimes.Branch(p.Version), Libs: runtimes.BuildLibs(p.Version), Newest: newest[runtimes.Branch(p.Version)] == p.Version}
		if latest != nil {
			_, supported := latest[b.Branch]
			b.Unsupported = !supported
		}
		followers := 0
		for _, st := range sites {
			if st.Kind != "php" {
				continue
			}
			res, _, ok := runtimes.Resolve(st.FPMVersion, rep.PHP)
			if ok && res.Path == p.Path {
				b.Sites = append(b.Sites, st.Hostnames[0])
			}
			switch {
			case st.FPMVersion == p.Version:
				b.InUse = "pinned by " + st.Hostnames[0]
			case st.FPMVersion == b.Branch:
				followers++
			}
		}
		for _, d := range defaults {
			if d.Version == p.Version && b.InUse == "" {
				b.InUse = "the default PHP of " + d.Username
			} else if d.Version == b.Branch {
				followers++
			}
		}
		if b.InUse == "" && b.Newest && count[b.Branch] == 1 && followers > 0 {
			b.InUse = "the only build of PHP " + b.Branch + ", which sites or users follow"
		}
		out = append(out, b)
	}
	return out
}

func (s *Server) phpPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rep := s.detect(ctx)
	sites, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	defaults, err := s.deps.Store.PHPUserDefaults(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	check, at := s.loadCheck(ctx)
	d := phpPageData{
		Builds: buildViews(rep, sites, defaults, check.Latest), Job: s.phpJob(ctx), Defaults: defaults, Users: loginUsers(),
		Updates: pendingUpdates(check.Latest, rep.PHP), NeedCode: s.needCode(r),
	}
	if at > 0 {
		d.CheckedAt = time.Unix(at, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	seen := map[string]bool{}
	for _, p := range rep.PHP {
		if p.Source && runtimes.BuildRE.MatchString(p.Version) {
			if br := runtimes.Branch(p.Version); !seen[br] {
				seen[br] = true
				d.Branches = append(d.Branches, br)
			}
		}
	}
	d.Labels = append(d.Labels, d.Branches...)
	for _, b := range d.Builds {
		d.Labels = append(d.Labels, b.Label)
	}
	for _, rel := range check.Latest {
		d.Releases = append(d.Releases, rel)
	}
	sort.Slice(d.Releases, func(i, j int) bool { return runtimes.Newer(d.Releases[i].Version, d.Releases[j].Version) })
	_, err = os.Stat(composerFilePath)
	d.ComposerOK = err == nil
	s.render(w, "php", http.StatusOK, page{Title: "PHP", Data: d})
}

// needCode reports whether the signed-in admin has an authenticator, so the forms ask for a code too.
func (s *Server) needCode(r *http.Request) bool {
	u, ok := currentUser(r)
	if !ok {
		return false
	}
	t, has, err := s.deps.Store.GetTOTP(r.Context(), u.ID)
	return err == nil && has && t.Enabled
}

// phpJobPanel is the live build panel the page polls while a build runs.
func (s *Server) phpJobPanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	job := s.phpJob(r.Context())
	if !job.Active { // the build ended: reload once so the page shows Install, the new build, and no more polling
		w.Header().Set("HX-Refresh", "true")
	}
	if err := s.pages["php"].ExecuteTemplate(w, "phpjob", job); err != nil {
		slog.Error("render php job", "error", err)
	}
}

// say answers a mutating request with a short message for the page's alert area.
func say(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, html.EscapeString(msg))
}

// phpBuild starts a build of one PHP version. EOL branches are refused: the choice comes from php.net's list of supported
// branches, refreshed first when it is stale.
func (s *Server) phpBuild(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	ver := strings.TrimSpace(r.PostFormValue("version"))
	if !phpVersionRE.MatchString(ver) {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("PHP version %q must look like 8.4.27.", ver))
		return
	}
	ctx := r.Context()
	check, at := s.loadCheck(ctx)
	if time.Since(time.Unix(at, 0)) > time.Hour {
		if err := s.runPHPCheck(ctx); err != nil {
			fail(w, http.StatusBadGateway, "Could not read php.net's list of supported versions, so the build was not started: "+err.Error())
			return
		}
		check, _ = s.loadCheck(ctx)
	}
	if _, supported := check.Latest[runtimes.Branch(ver)]; !supported {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("PHP %s no longer gets security fixes, so it cannot be built.", runtimes.Branch(ver)))
		return
	}
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := s.helperClient().Call(bctx, helper.ActionPHPBuild, helper.Spec{PHPVersion: ver}); err != nil {
		fail(w, http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), "helper: "))
		return
	}
	s.audit(r, "php.build.start", ver)
	go s.watchBuild(ver, r.PostFormValue("switch") != "", s.auditorFor(r))
	hxRedirect(w, "/php")
}

// auditorFor keeps who started a build, for the audit rows the background watcher writes after the request is gone.
func (s *Server) auditorFor(r *http.Request) func(action, target string) {
	actor := "open mode"
	if u, ok := currentUser(r); ok {
		actor = u.Username
	}
	ip := clientIP(r)
	return func(action, target string) {
		e := store.AuditEntry{At: time.Now().UTC().Format(time.RFC3339), Actor: tidy(actor, 64), Action: action, Target: tidy(target, 200), IP: ip}
		if err := s.deps.Store.AddAudit(context.Background(), e); err != nil {
			slog.Error("write audit row", "action", action, "error", err)
		}
	}
}

// watchBuild follows a running build; when it has built, it asks the helper to install it and, if asked, switches the
// sites that follow the branch. One watcher at a time; if the web process restarts mid-build, the finished build waits
// on the page for the Install button.
func (s *Server) watchBuild(ver string, switchAfter bool, audit func(action, target string)) {
	if !s.phpWatch.CompareAndSwap(false, true) {
		return
	}
	defer s.phpWatch.Store(false)
	deadline := time.Now().Add(12 * time.Hour)
	for time.Now().Before(deadline) {
		time.Sleep(s.phpPoll)
		job := s.phpJob(context.Background())
		switch {
		case job.Err != "":
			continue
		case job.Phase == phpbuild.PhaseFailed:
			audit("php.build.failed", ver+": "+job.Message)
			return
		case job.Phase == phpbuild.PhaseIdle:
			return
		case job.Phase == phpbuild.PhaseBuilt && job.Version == ver:
			label, err := s.installBuild(context.Background(), ver)
			if err != nil {
				audit("php.build.failed", ver+": "+err.Error())
				s.flash(fmt.Sprintf("PHP %s was built but could not be installed: %v", ver, err))
				return
			}
			audit("php.install", label)
			s.flash("PHP " + label + " is installed.")
			if switchAfter {
				s.reportSwitch(context.Background(), runtimes.Branch(ver), audit)
			}
			return
		}
	}
}

func (s *Server) installBuild(ctx context.Context, ver string) (string, error) {
	ictx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := s.helperClient().Call(ictx, helper.ActionPHPInstall, helper.Spec{PHPVersion: ver}); err != nil {
		return "", errors.New(strings.TrimPrefix(err.Error(), "helper: "))
	}
	for _, p := range s.detect(ictx).PHP {
		if p.Source && runtimes.BuildRE.MatchString(p.Version) && strings.HasPrefix(p.Version, ver+"-") {
			return p.Version, nil
		}
	}
	return ver, nil
}

// phpInstall installs a finished build the watcher missed (the web process restarted while it ran).
func (s *Server) phpInstall(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	job := s.phpJob(r.Context())
	if job.Phase != phpbuild.PhaseBuilt {
		fail(w, http.StatusConflict, "There is no finished build waiting to be installed.")
		return
	}
	label, err := s.installBuild(context.WithoutCancel(r.Context()), job.Version)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "php.install", label)
	s.flash("PHP " + label + " is installed.")
	hxRedirect(w, "/php")
}

// phpPrune removes a build, unless something runs it or follows its branch with no other build to go to.
func (s *Server) phpPrune(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	label := r.PathValue("label")
	if !runtimes.BuildRE.MatchString(label) {
		fail(w, http.StatusBadRequest, "That is not a build name.")
		return
	}
	ctx := r.Context()
	sites, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	defaults, err := s.deps.Store.PHPUserDefaults(ctx)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, b := range buildViews(s.detect(ctx), sites, defaults, nil) {
		if b.Label == label {
			found = true
			if b.InUse != "" {
				fail(w, http.StatusConflict, fmt.Sprintf("%s cannot be removed: %s.", label, b.InUse))
				return
			}
		}
	}
	if !found {
		fail(w, http.StatusNotFound, label+" is not installed.")
		return
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if _, err := s.helperClient().Call(pctx, helper.ActionPHPPrune, helper.Spec{Build: label}); err != nil {
		fail(w, http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), "helper: "))
		return
	}
	s.audit(r, "php.prune", label)
	hxRedirect(w, "/php")
}

// phpSwitch moves the sites that follow a branch onto its newest build.
func (s *Server) phpSwitch(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	branch := strings.TrimSpace(r.PostFormValue("branch"))
	if !phpBranchRE.MatchString(branch) {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%q is not a PHP branch such as 8.4.", branch))
		return
	}
	msg := s.reportSwitch(context.WithoutCancel(r.Context()), branch, s.auditorFor(r))
	say(w, msg)
}

// reportSwitch switches and describes the result in one sentence.
func (s *Server) reportSwitch(ctx context.Context, branch string, audit func(action, target string)) string {
	switched, reverted, problem := s.switchBranch(ctx, branch, audit)
	switch {
	case problem != "":
		s.flash(problem)
		return problem
	case reverted != "":
		return fmt.Sprintf("Switched %d site(s); %s", switched, reverted)
	case switched == 0:
		return "No site follows PHP " + branch + "."
	}
	return fmt.Sprintf("Switched %d site(s) to the newest PHP %s.", switched, branch)
}

// switchBranch re-applies every php site that follows branch, one at a time, onto the branch's newest build. A site that does
// not come up healthy goes back to the previous build of the branch and the loop stops, so a bad build never takes
// every site down. problem is set when nothing could be done; reverted describes a site that was put back.
func (s *Server) switchBranch(ctx context.Context, branch string, audit func(action, target string)) (switched int, reverted, problem string) {
	rep := s.detect(ctx)
	newest, ok := branchBuild(rep, branch, 0)
	if !ok {
		return 0, "", "There is no PHP " + branch + " build to switch to."
	}
	prev, hasPrev := branchBuild(rep, branch, 1)
	sites, err := s.deps.Store.ListSites(ctx)
	if err != nil {
		return 0, "", err.Error()
	}
	for _, site := range sites {
		if site.Kind != "php" || site.FPMVersion != branch {
			continue
		}
		err := s.applyRuntime(ctx, site, &newest)
		if err == nil {
			err = s.phpHealthy(ctx, site)
		}
		if err == nil {
			switched++
			audit("php.switch", site.Hostnames[0]+" -> "+newest.Version)
			continue
		}
		msg := fmt.Sprintf("%s did not come up on %s (%v)", site.Hostnames[0], newest.Version, err)
		if !hasPrev {
			audit("php.switch.failed", site.Hostnames[0]+": "+err.Error())
			return switched, "", msg + "; there is no earlier PHP " + branch + " build to go back to."
		}
		if rerr := s.applyRuntime(ctx, site, &prev); rerr != nil {
			audit("php.switch.failed", site.Hostnames[0]+": "+err.Error()+"; revert: "+rerr.Error())
			return switched, "", msg + fmt.Sprintf("; going back to %s failed too (%v). Fix it by hand.", prev.Version, rerr)
		}
		audit("php.switch.reverted", site.Hostnames[0]+": "+err.Error())
		return switched, msg + fmt.Sprintf("; it was put back on %s and the remaining sites were left alone.", prev.Version), ""
	}
	return switched, "", ""
}

// branchBuild is the nth newest exact build of a branch.
func branchBuild(rep runtimes.Report, branch string, n int) (runtimes.PHPVersion, bool) {
	i := 0
	for _, p := range rep.PHP {
		if p.Source && runtimes.BuildRE.MatchString(p.Version) && runtimes.Branch(p.Version) == branch {
			if i == n {
				return p, true
			}
			i++
		}
	}
	return runtimes.PHPVersion{}, false
}

// phpHealthy judges a switched site: its unit stays up after a settle delay, and its health path (if any) answers below 400.
func (s *Server) phpHealthy(ctx context.Context, site store.Site) error {
	if !site.Enabled { // a disabled site has a stopped unit by design
		return nil
	}
	time.Sleep(s.phpSettle)
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := s.helperClient().Call(sctx, helper.ActionUnitStatus, helper.Spec{Slug: site.Slug})
	if err != nil {
		return fmt.Errorf("cannot read the unit's state: %w", err)
	}
	if resp.Status == nil {
		return errors.New("the helper returned no unit state")
	}
	if resp.Status.ActiveState != "active" {
		return fmt.Errorf("php-fpm is %s (%s)", resp.Status.ActiveState, resp.Status.SubState)
	}
	if site.PHPHealthPath == "" {
		return nil
	}
	code, err := s.healthGet(sctx, site.Hostnames[0], site.PHPHealthPath)
	if err != nil {
		return fmt.Errorf("%s: %w", site.PHPHealthPath, err)
	}
	if code >= 400 {
		return fmt.Errorf("%s answered %d", site.PHPHealthPath, code)
	}
	return nil
}

// phpDefault sets or clears a login user's default CLI PHP. SQLite first (desired state), then the helper writes the files;
// a helper failure is reported and the next start writes them again.
func (s *Server) phpDefault(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	user, label := strings.TrimSpace(r.PostFormValue("user")), strings.TrimSpace(r.PostFormValue("version"))
	known := false
	for _, u := range loginUsers() {
		known = known || u == user
	}
	if !known {
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%q is not a login user on this machine.", user))
		return
	}
	ctx := r.Context()
	if label != "" {
		if !phpLabelRE.MatchString(label) {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%q is not a PHP branch such as 8.4 or a build such as 8.4.27-1.", label))
			return
		}
		if v, fallback, ok := runtimes.Resolve(label, s.detect(ctx).PHP); !ok || fallback || !v.Source {
			fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("%s is not a ServanaGo PHP build on this machine.", label))
			return
		}
		if err := s.deps.Store.SetPHPUserDefault(ctx, user, label); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if err := s.deps.Store.DeletePHPUserDefault(ctx, user); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := s.helperClient().Call(hctx, helper.ActionPHPUserDefault, helper.Spec{User: user, PHPVersion: label}); err != nil {
		slog.Error("php user default", "user", user, "error", err)
		fail(w, http.StatusBadGateway, "Saved, but the helper could not write the files: "+strings.TrimPrefix(err.Error(), "helper: ")+". They are written again when ServanaGo restarts.")
		return
	}
	if label == "" {
		s.audit(r, "php.default.cleared", user)
	} else {
		s.audit(r, "php.default.set", user+" = "+label)
	}
	hxRedirect(w, "/php")
}

// ReconcilePHP writes every stored user default again (shims included): SQLite is the desired state, the host files follow.
func (s *Server) ReconcilePHP(ctx context.Context) {
	defaults, err := s.deps.Store.PHPUserDefaults(ctx)
	if err != nil {
		slog.Error("read php defaults", "error", err)
		return
	}
	for _, d := range defaults {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := s.helperClient().Call(cctx, helper.ActionPHPUserDefault, helper.Spec{User: d.Username, PHPVersion: d.Version}); err != nil {
			slog.Warn("php default not applied", "user", d.Username, "error", err)
		}
		cancel()
	}
}

func (s *Server) phpCheckNow(w http.ResponseWriter, r *http.Request) {
	if err := s.runPHPCheck(r.Context()); err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	hxRedirect(w, "/php")
}

func (s *Server) phpComposer(w http.ResponseWriter, r *http.Request) {
	if !s.confirm(w, r) {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Minute)
	defer cancel()
	if _, err := s.helperClient().Call(cctx, helper.ActionComposer, helper.Spec{}); err != nil {
		fail(w, http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), "helper: "))
		return
	}
	s.audit(r, "php.composer", "")
	hxRedirect(w, "/php")
}
