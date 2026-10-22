package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/helper"
	"github.com/servanago/servanago/internal/runtimes"
	"github.com/servanago/servanago/internal/store"
)

const maxNotes = 10000 // characters; the schema CHECK says the same

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$`)

// parseHostnames reads the Hostnames box: one name per line (commas and spaces also separate), lower-cased,
// duplicates dropped, first one primary. Each must be a valid public-style name (no IP literals, no .local).
func parseHostnames(text string) ([]string, error) {
	var out []string
	for _, h := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		h = strings.ToLower(h)
		if err := config.ValidateDomain(h); err != nil {
			return nil, fmt.Errorf("hostname: %w", err)
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("hostname: enter at least one, such as app.example.com")
	}
	return out, nil
}

// userKinds are the kinds that can run as a named user.
var userKinds = map[string]bool{"static": true, "node": true, "php": true, "frankenphp": true, "cgi": true}

// userChoice is how the site's user was picked. It is not stored: only the user's name is.
type userChoice struct {
	Mode string // "" (the generated user), "existing", "create", or "fixed": an edit keeps the user the site has
	User string
	Home string // create only: the home to make
}

// parseUserChoice reads the user part of the form. An absent user_mode keeps the generated sg-<slug> user (and a
// static site in Caddy), so old callers and MCP do not create users. A site keeps its user for life (fixed).
func parseUserChoice(v url.Values, kind, host, fixed string) (userChoice, error) {
	if fixed != "" {
		if !userKinds[kind] {
			return userChoice{}, fmt.Errorf("this site runs as the user %s; a %s site cannot, delete it and add the other kind", fixed, kind)
		}
		return userChoice{Mode: "fixed", User: fixed}, nil
	}
	mode := v.Get("user_mode")
	switch mode {
	case "", "generated":
		return userChoice{}, nil
	case "existing", "create":
	default:
		return userChoice{}, fmt.Errorf("user_mode %q must be generated, existing or create", mode)
	}
	if !userKinds[kind] {
		return userChoice{}, nil
	}
	name := strings.TrimSpace(v.Get("site_user"))
	if name == "" {
		if mode == "existing" {
			return userChoice{}, errors.New("user: type the name of the existing user")
		}
		var err error
		if name, err = helper.DeriveUser(host); err != nil {
			return userChoice{}, fmt.Errorf("user name from %s: %w; type a user name instead", host, err)
		}
	}
	if err := helper.ValidateUser(name); err != nil {
		return userChoice{}, err
	}
	uc := userChoice{Mode: mode, User: name}
	if mode == "create" {
		if uc.Home = strings.TrimSpace(v.Get("user_home")); uc.Home == "" {
			uc.Home = "/home/" + name
		}
		if err := helper.ValidateNewHome(uc.Home); err != nil {
			return uc, err
		}
	}
	return uc, nil
}

// rootFor validates the site folder. A user's folder is checked by its spelling here (the web process often cannot
// read a home, and a new home does not exist yet) and again by the helper, which resolves it. Any other folder must
// exist and pass config.ValidateStaticRoot (stored symlink-resolved).
func rootFor(kind string, v url.Values, cfg config.Config, uc userChoice) (string, error) {
	if uc.User == "" {
		if kind == "static" {
			root, err := config.ValidateStaticRoot(strings.TrimSpace(v.Get("static_root")), cfg.DataDir, cfg.StaticRoots)
			if err != nil {
				return "", fmt.Errorf("static folder: %w", err)
			}
			return root, nil
		}
		return rootOrErr(v, cfg)
	}
	root := strings.TrimSpace(v.Get("static_root"))
	if root == "" && uc.Mode == "create" {
		root = uc.Home + "/public_html"
	}
	if err := helper.ValidateRoot(root); err != nil {
		return "", fmt.Errorf("folder: %w", err)
	}
	if len(cfg.StaticRoots) > 0 && !slices.ContainsFunc(cfg.StaticRoots, func(a string) bool { return root == a || strings.HasPrefix(root, a+"/") }) {
		return "", fmt.Errorf("folder %q: outside the allowed roots (SERVANAGO_STATIC_ROOTS)", root)
	}
	return root, nil
}

// parseSite validates the fields shared by create and edit. A proxy site needs an upstream; a static,
// node or php site needs a folder that passes config.ValidateStaticRoot (stored symlink-resolved).
func parseSite(v url.Values, cfg config.Config) (store.Site, error) {
	r, _, err := parseSiteFor(v, cfg, "")
	return r, err
}

// parseSiteFor is parseSite for a site that already has fixed as its user ("" = a new site or one with the generated user).
func parseSiteFor(v url.Values, cfg config.Config, fixed string) (store.Site, userChoice, error) {
	var r store.Site
	var uc userChoice
	var err error
	if r.Kind = v.Get("kind"); r.Kind == "" {
		r.Kind = "proxy"
	}
	switch r.Kind {
	case "proxy", "static", "node", "php", "frankenphp", "fastcgi", "cgi":
	default:
		return r, uc, fmt.Errorf("kind %q must be proxy, static, node, php, frankenphp, fastcgi or cgi", r.Kind)
	}
	if r.Hostnames, err = parseHostnames(v.Get("hostnames")); err != nil {
		return r, uc, err
	}
	if uc, err = parseUserChoice(v, r.Kind, r.Hostnames[0], fixed); err != nil {
		return r, uc, err
	}
	r.SiteUser = uc.User
	r, err = parseKind(r, v, cfg, uc)
	return r, uc, err
}

// parseKind fills in the kind-specific fields and the shared ones.
func parseKind(r store.Site, v url.Values, cfg config.Config, uc userChoice) (store.Site, error) {
	var err error
	switch r.Kind {
	case "static":
		if r.StaticRoot, err = rootFor("static", v, cfg, uc); err != nil {
			return r, err
		}
		r.Scheme = "http" // unused outside proxy; the column is NOT NULL
	case "node":
		if r.StaticRoot, err = rootFor("node", v, cfg, uc); err != nil {
			return r, err
		}
		r.Scheme, r.UpstreamHost = "http", "127.0.0.1"
		if r.UpstreamPort, err = parseAppPort(v); err != nil {
			return r, err
		}
		if r.StartCommand, err = parseCommand(v.Get("start_command"), true); err != nil {
			return r, err
		}
		if err := helper.ValidateStart(r.StartCommand); err != nil { // written into a unit file: no line breaks
			return r, err
		}
		if r.InstallCommand, err = parseCommand(v.Get("install_command"), false); err != nil {
			return r, err
		}
		if r.BuildCommand, err = parseCommand(v.Get("build_command"), false); err != nil {
			return r, err
		}
	case "frankenphp":
		if r.StaticRoot, err = rootFor("frankenphp", v, cfg, uc); err != nil {
			return r, err
		}
		r.Scheme, r.UpstreamHost = "http", "127.0.0.1"
		if r.UpstreamPort, err = parseAppPort(v); err != nil {
			return r, err
		}
	case "fastcgi":
		if r.StaticRoot, err = rootOrErr(v, cfg); err != nil {
			return r, err
		}
		r.Scheme = "http"
		if r.UpstreamHost, r.UpstreamPort, err = parseFCGIAddr(v.Get("fcgi_addr")); err != nil {
			return r, err
		}
	case "cgi":
		if r.StaticRoot, err = rootFor("cgi", v, cfg, uc); err != nil {
			return r, err
		}
		r.Scheme = "http"
	case "php":
		r.FPMVersion = strings.TrimSpace(v.Get("fpm_version"))
		if r.FPMVersion == "" {
			return r, errors.New("kind php: pick a php-fpm version from the detected list")
		}
		if r.StaticRoot, err = rootFor("php", v, cfg, uc); err != nil {
			return r, err
		}
		r.Scheme = "http"
		exts, err := runtimes.ParseExtensions(v["php_ext"])
		if err != nil {
			return r, err
		}
		r.PHPExtensions = strings.Join(exts, " ")
		if r.PHPHealthPath, err = parseHealthPath(v.Get("php_health_path")); err != nil {
			return r, err
		}
	default: // proxy
		if r.Scheme = v.Get("scheme"); r.Scheme != "http" && r.Scheme != "https" {
			return r, fmt.Errorf("scheme %q must be http or https", r.Scheme)
		}
		r.UpstreamHost = strings.TrimSpace(v.Get("upstream_host"))
		if _, ipErr := netip.ParseAddr(r.UpstreamHost); ipErr != nil && !hostnameRE.MatchString(r.UpstreamHost) {
			return r, fmt.Errorf("upstream host %q must be an IP address or a hostname", r.UpstreamHost)
		}
		if r.UpstreamPort, err = strconv.Atoi(strings.TrimSpace(v.Get("upstream_port"))); err != nil || r.UpstreamPort < 1 || r.UpstreamPort > 65535 {
			return r, fmt.Errorf("port %q must be 1-65535", v.Get("upstream_port"))
		}
		r.TLSSkipVerify = v.Get("tls_skip_verify") != ""
	}
	if r.RecordIP = strings.TrimSpace(v.Get("record_ip")); r.RecordIP != "" {
		if _, err := config.ValidateIP(r.RecordIP); err != nil {
			return r, fmt.Errorf("record IP: %w", err)
		}
	}
	if r.RecordIP6 = strings.TrimSpace(v.Get("record_ip6")); r.RecordIP6 != "" {
		if _, err := config.ValidateIP6(r.RecordIP6); err != nil {
			return r, fmt.Errorf("record IPv6: %w", err)
		}
	}
	if r.ExtraRoutes, err = extraRoutesText(v.Get("extra_routes")); err != nil {
		return r, err
	}
	r.Snippets = v["snippets"] // the store rejects a name that does not exist
	r.Notes = strings.ReplaceAll(strings.TrimSpace(v.Get("notes")), "\r\n", "\n")
	if utf8.RuneCountInString(r.Notes) > maxNotes {
		return r, fmt.Errorf("notes: at most 10,000 characters")
	}
	if pub := strings.TrimSpace(v.Get("public_dir")); pub != "" {
		switch r.Kind {
		case "php", "frankenphp", "fastcgi", "static":
		default:
			return r, fmt.Errorf("public folder: a %s site has none", r.Kind)
		}
		if err := helper.ValidatePublic(pub); err != nil {
			return r, err
		}
		if uc.User == "" { // a user's folder may be unreadable here; the helper checks it then
			if fi, err := os.Stat(filepath.Join(r.StaticRoot, pub)); err != nil || !fi.IsDir() {
				return r, fmt.Errorf("public folder %q: not a folder inside %s", pub, r.StaticRoot)
			}
		}
		r.PublicDir = pub
	}
	r.Enabled = v.Get("enabled") != ""
	return r, nil
}

// parseHealthPath reads the optional path requested after a PHP switch: an absolute URL path, not a URL.
func parseHealthPath(text string) (string, error) {
	p := strings.TrimSpace(text)
	if p == "" {
		return "", nil
	}
	if len(p) > 200 || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, " \t\r\n#\\") || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", fmt.Errorf("health path %q must be an absolute path such as /healthz (up to 200 characters, no spaces)", p)
	}
	if u, err := url.Parse(p); err != nil || u.Scheme != "" || u.Host != "" {
		return "", fmt.Errorf("health path %q must be a path, not a URL", p)
	}
	return p, nil
}

// extraRoutesText parses the extra routes box and returns its canonical form: one route per line,
// path=dial, so the renderer's re-parse of the stored text can never fail.
func extraRoutesText(text string) (string, error) {
	rs, err := config.ParseExtraRoutes(text)
	if err != nil {
		return "", fmt.Errorf("extra routes: %w", err)
	}
	lines := make([]string, len(rs))
	for i, x := range rs {
		lines[i] = x.Text()
	}
	return strings.Join(lines, "\n"), nil
}

// parseFCGIAddr reads the FastCGI upstream: an absolute socket path (port 0) or host:port.
func parseFCGIAddr(text string) (host string, port int, err error) {
	a := strings.TrimSpace(text)
	if strings.HasPrefix(a, "/") {
		if err := helper.ValidateRoot(a); err != nil { // same clean-path rules; the path is data in Caddy's JSON
			return "", 0, fmt.Errorf("FastCGI socket: %w", err)
		}
		return a, 0, nil
	}
	h, p, serr := net.SplitHostPort(a)
	if serr != nil {
		return "", 0, fmt.Errorf("FastCGI address %q must be an absolute socket path or host:port", a)
	}
	if _, ipErr := netip.ParseAddr(h); ipErr != nil && !hostnameRE.MatchString(h) {
		return "", 0, fmt.Errorf("FastCGI host %q must be an IP address or a hostname", h)
	}
	if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("FastCGI port %q must be 1-65535", p)
	}
	return h, port, nil
}

// parseAppPort reads the loopback port a node or frankenphp app listens on.
func parseAppPort(v url.Values) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(v.Get("port")))
	if err != nil || p < 1024 || p > 65535 {
		return 0, fmt.Errorf("port %q must be 1024-65535", v.Get("port"))
	}
	return p, nil
}

// rootOrErr validates the folder for node/php sites, same rules as a static site.
func rootOrErr(v url.Values, cfg config.Config) (string, error) {
	root, err := config.ValidateStaticRoot(strings.TrimSpace(v.Get("static_root")), cfg.DataDir, cfg.StaticRoots)
	if err != nil {
		return "", fmt.Errorf("app folder: %w", err)
	}
	// The same rules the helper applies when it writes the folder into a unit file.
	if err := helper.ValidateRoot(root); err != nil {
		return "", fmt.Errorf("app folder: %w", err)
	}
	return root, nil
}

// parseCommand bounds a command the admin supplies: 1-2000 characters (optional accepts ""),
// no NUL bytes. It runs as the site's unprivileged user, never root.
func parseCommand(text string, required bool) (string, error) {
	c := strings.TrimSpace(text)
	if c != "" && (strings.ContainsRune(c, 0) || len(c) > 2000) {
		return "", errors.New("command: at most 2000 characters, no NUL bytes")
	}
	if c == "" && required {
		return "", errors.New("command: required")
	}
	return c, nil
}

// readSiteForm parses the posted form into a site plus its gate grants: parseSite, then the access controls,
// then the gate (which needs the controls' gate mode). Static sites carry none of the proxy-only tuning.
func (s *Server) readSiteForm(r *http.Request, base store.Site) (store.Site, []store.Grant, error) {
	in, uc, err := parseSiteFor(r.PostForm, s.deps.Cfg, base.SiteUser)
	if err != nil {
		return in, nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	if uc.User != "" {
		if err := s.checkUser(r.Context(), in, uc); err != nil {
			return in, nil, err
		}
	}
	// A php site's version must be one the host actually has: the picker lists detected binaries.
	if in.Kind == "php" {
		if _, _, ok := runtimes.Resolve(in.FPMVersion, s.detect(r.Context()).PHP); !ok {
			return in, nil, userError{http.StatusUnprocessableEntity, "php-fpm " + in.FPMVersion + " is not installed on this host; pick a detected version"}
		}
	}
	if in.Kind == "frankenphp" && !s.detect(r.Context()).Franken.Installed {
		return in, nil, userError{http.StatusUnprocessableEntity, "frankenphp is not installed on this host; install it, then save again"}
	}
	if in.Kind == "cgi" && !s.detect(r.Context()).FCGIWrap.Installed {
		return in, nil, userError{http.StatusUnprocessableEntity, "fcgiwrap is not installed on this host; install it, then save again"}
	}
	// Overlay only the fields this form owns onto the stored site (base is the zero Site on create).
	base.Kind, base.Hostnames, base.Scheme = in.Kind, in.Hostnames, in.Scheme
	base.UpstreamHost, base.UpstreamPort, base.StaticRoot = in.UpstreamHost, in.UpstreamPort, in.StaticRoot
	base.StartCommand = in.StartCommand
	base.InstallCommand, base.BuildCommand = in.InstallCommand, in.BuildCommand
	base.TLSSkipVerify, base.Enabled, base.RecordIP, base.RecordIP6 = in.TLSSkipVerify, in.Enabled, in.RecordIP, in.RecordIP6
	base.FPMVersion, base.PHPExtensions, base.PHPHealthPath = in.FPMVersion, in.PHPExtensions, in.PHPHealthPath
	base.ExtraRoutes, base.Snippets = in.ExtraRoutes, in.Snippets
	base.SiteUser, base.PublicDir, base.Notes = in.SiteUser, in.PublicDir, in.Notes
	if err := applyControls(&base, r.PostForm); err != nil {
		return base, nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	if base.Kind == "static" || base.Kind == "php" || base.Kind == "fastcgi" || base.Kind == "cgi" {
		base.Stream, base.MaxBody = false, 0
	}
	grants, err := s.parseGate(r.Context(), base, r.PostForm)
	return base, grants, err
}

// checkUser asks the helper about the site's user before anything is saved: a new user must not exist, an existing
// one must (and may run a site), and the folder must lie inside its home. An edit of a site that already has its
// user is not blocked when the helper cannot be reached; the apply step reports that.
func (s *Server) checkUser(ctx context.Context, in store.Site, uc userChoice) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := s.helperClient().Call(cctx, helper.ActionUserCheck, helper.Spec{User: uc.User})
	if err != nil {
		if uc.Mode == "fixed" {
			return nil
		}
		return userError{http.StatusUnprocessableEntity, fmt.Sprintf("Cannot check the user %s: %s. A site with its own user needs the ServanaGo helper running.", uc.User, strings.TrimPrefix(err.Error(), "helper: "))}
	}
	var u helper.UserData
	if resp.User != nil {
		u = *resp.User
	}
	if uc.Mode == "create" {
		if u.Exists {
			return userError{http.StatusUnprocessableEntity, fmt.Sprintf("The user %s already exists. Choose \"Use an existing user\", or type another name.", uc.User)}
		}
		if !strings.HasPrefix(in.StaticRoot, uc.Home+"/") {
			return userError{http.StatusUnprocessableEntity, fmt.Sprintf("The folder must be inside the new home %s.", uc.Home)}
		}
		return nil
	}
	if !u.Exists {
		return userError{http.StatusUnprocessableEntity, fmt.Sprintf("The user %s does not exist.", uc.User)}
	}
	if !strings.HasPrefix(in.StaticRoot, u.Home+"/") {
		return userError{http.StatusUnprocessableEntity, fmt.Sprintf("The folder must be inside the home of %s (%s).", uc.User, u.Home)}
	}
	return nil
}

// checkHostnames refuses the UI host, any name another site already answers on, and a loopback port another
// node app already listens on, inside the apply transaction.
func (s *Server) checkHostnames(r *http.Request, tx *store.Store, rt store.Site) error {
	all, err := tx.ListSites(r.Context())
	if err != nil {
		return err
	}
	if rt.Kind == "node" || rt.Kind == "frankenphp" { // one loopback port space for both
		for _, x := range all {
			if x.ID != rt.ID && (x.Kind == "node" || x.Kind == "frankenphp") && x.UpstreamPort == rt.UpstreamPort {
				return userError{http.StatusConflict, fmt.Sprintf("Port %d is already used by the app for %s; choose another port.", rt.UpstreamPort, x.Hostnames[0])}
			}
		}
	}
	if rt.SiteUser != "" { // one site per user
		for _, x := range all {
			if x.ID != rt.ID && x.SiteUser == rt.SiteUser {
				return userError{http.StatusConflict, fmt.Sprintf("The user %s already runs the site %s. Type another user name.", rt.SiteUser, x.Hostnames[0])}
			}
		}
	}
	for _, h := range rt.Hostnames {
		if h == s.deps.Cfg.Host {
			return fmt.Errorf("%s is the ServanaGo UI host; choose another hostname", h)
		}
		for _, x := range all {
			if x.ID != rt.ID && slices.Contains(x.Hostnames, h) {
				return userError{http.StatusConflict, fmt.Sprintf("Hostname %q is already used by another site.", h)}
			}
		}
	}
	return nil
}

// newDomainFor is the domain to add for host: Cloudflare is on, no managed domain encloses it, and a zone
// does. nil otherwise, including when Cloudflare has no zone for it (the host is then served without a domain).
func (s *Server) newDomainFor(ctx context.Context, host string) (*store.Domain, error) {
	if !s.dnsOn() {
		return nil, nil
	}
	ds, err := s.deps.Store.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := store.ResolveDomain(ds, host); ok {
		return nil, nil
	}
	if _, err := config.ValidateIP(s.deps.Cfg.HostIP); err != nil {
		return nil, userError{http.StatusUnprocessableEntity, "SERVANAGO_HOST_IP: " + err.Error()}
	}
	zoneID, zone, err := s.deps.CF.ZoneFor(ctx, host, "")
	if errors.Is(err, cfdns.ErrNoZone) {
		return nil, nil
	}
	if err != nil {
		return nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	return &store.Domain{Name: zone, ZoneID: zoneID, DefaultIP: s.deps.Cfg.HostIP, DefaultIP6: s.deps.Cfg.HostIP6, CertMode: "wildcard"}, nil
}

// addDomainIfNew creates d unless a domain of that name appeared since newDomainFor looked.
func addDomainIfNew(ctx context.Context, tx *store.Store, d *store.Domain) error {
	if d == nil {
		return nil
	}
	ds, err := tx.ListDomains(ctx)
	if err != nil {
		return err
	}
	for _, x := range ds {
		if x.Name == d.Name {
			return nil
		}
	}
	_, err = tx.CreateDomain(ctx, *d)
	return err
}

func (s *Server) createSite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rt, grants, err := s.readSiteForm(r, store.Site{})
	if err != nil {
		failErr(w, err)
		return
	}
	nd, err := s.newDomainFor(r.Context(), rt.Hostnames[0])
	if err != nil {
		failErr(w, err)
		return
	}
	var created store.Site
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if err := addDomainIfNew(r.Context(), tx, nd); err != nil {
			return err
		}
		if err := s.checkHostnames(r, tx, rt); err != nil {
			return err
		}
		var err error
		if created, err = tx.CreateSite(r.Context(), rt); err != nil {
			return err
		}
		return tx.ReplaceGrants(r.Context(), created.ID, grants)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "site.created", created.Hostnames[0])
	if err := s.runtimeApply(r, created); err != nil {
		slog.Error("runtime site apply", "slug", created.Slug, "error", err)
		s.flash(fmt.Sprintf("Site saved, but the runtime setup failed: %v", err))
	}
	s.reconcile(r, created.ID)
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusNoContent)
}

// updateSite saves the edit form and stays on the page: the one handler that answers 200 with a message
// instead of 204 + HX-Redirect, so a long form can be saved repeatedly.
func (s *Server) updateSite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "site not found")
		return
	}
	in, grants, err := s.readSiteForm(r, cur)
	if err != nil {
		failErr(w, err)
		return
	}
	nd, err := s.newDomainFor(r.Context(), in.Hostnames[0])
	if err != nil {
		failErr(w, err)
		return
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		if _, err := tx.GetSite(r.Context(), id); err != nil {
			return userError{http.StatusNotFound, "site not found"}
		}
		if err := addDomainIfNew(r.Context(), tx, nd); err != nil {
			return err
		}
		if err := s.checkHostnames(r, tx, in); err != nil {
			return err
		}
		if err := tx.UpdateSite(r.Context(), in); err != nil {
			return err
		}
		return tx.ReplaceGrants(r.Context(), id, grants)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "site.updated", in.Hostnames[0])
	if err := s.runtimeApply(r, in); err != nil {
		slog.Error("runtime site apply", "slug", in.Slug, "error", err)
		s.flash(fmt.Sprintf("Saved, but the runtime setup failed: %v", err))
	}
	s.reconcile(r, id) // adds records for new hostnames and removes the owned ones of hostnames that went
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, "Saved and applied.")
}

type siteEditForm struct {
	Site        store.Site
	Edit        bool
	HostLines   string // the Hostnames box: one per line, primary first
	DNSOn       bool   // Cloudflare is configured; otherwise the DNS record fields are hidden
	GateACL     string // textarea content for an existing ACL
	MailOK      bool   // email delivery and the session key work; otherwise the gate section is shown disabled
	ServerIP    string // where new A records point; shown in the live preview
	Row         *siteRow
	RootNote    string         // any foldered site: why the folder cannot be read, or ""
	PHPVersions []runtimes.Opt // detected php-fpm versions for the pick list
	PHPExt      []extOpt       // the extension checklist (ServanaGo's own PHP builds)
	Node        runtimes.NodeReport
	Franken     runtimes.FrankenReport
	FCGIWrap    runtimes.FCGIWrapReport
	Unit        *unitPanel   // node and php sites: state and journal tail; nil otherwise
	UserOffer   bool         // a new site and the helper answers: offer to run it as a user
	Snippets    []snippetOpt // every snippet and whether this site has it attached
}

type snippetOpt struct {
	Name string
	On   bool
}

// helperUp reports whether the privileged helper answers; a site's own user needs it.
func (s *Server) helperUp(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err := s.helperClient().Call(cctx, helper.ActionPing, helper.Spec{})
	return err == nil
}

// IsStatic picks which half of the form is shown. (Kinds node/php have their own data-for blocks.)
func (f siteEditForm) IsStatic() bool { return f.Site.Kind == "static" }

// phpVersionOpts labels each detected version and which one is currently selected.
func phpVersionOpts(versions []runtimes.PHPVersion, selected string) []runtimes.Opt {
	var out []runtimes.Opt
	for _, v := range versions {
		out = append(out, runtimes.Opt{Version: v.Version, Selected: v.Version == selected})
	}
	return out
}

// extOpt is one checklist row: an extension and whether the site loads it (the core set when the site chose none).
type extOpt struct {
	Name, Group string
	On          bool
}

func extOpts(selected string) []extOpt {
	on := map[string]bool{}
	for _, n := range strings.Fields(selected) {
		on[n] = true
	}
	if len(on) == 0 {
		for _, n := range runtimes.CoreExtensions {
			on[n] = true
		}
	}
	var out []extOpt
	for _, e := range runtimes.PHPExtensions {
		out = append(out, extOpt{Name: e.Name, Group: e.Group, On: on[e.Name]})
	}
	return out
}

func (s *Server) siteEditPage(w http.ResponseWriter, r *http.Request, rt store.Site, edit bool) {
	title := "Add site"
	rep := s.detect(r.Context())
	form := siteEditForm{Site: rt, Edit: edit, HostLines: strings.Join(rt.Hostnames, "\n"), DNSOn: s.dnsOn(),
		MailOK: s.gateUsable(r.Context()), ServerIP: s.deps.Cfg.HostIP, PHPVersions: phpVersionOpts(rep.PHP, rt.FPMVersion), PHPExt: extOpts(rt.PHPExtensions), Node: rep.Node, Franken: rep.Franken, FCGIWrap: rep.FCGIWrap}
	if form.Site.Kind == "" {
		form.Site.Kind = "proxy"
	}
	form.UserOffer = !edit && s.helperUp(r.Context())
	if all, err := s.deps.Store.ListSnippets(r.Context()); err == nil {
		for _, x := range all {
			form.Snippets = append(form.Snippets, snippetOpt{x.Name, slices.Contains(rt.Snippets, x.Name)})
		}
	}
	if edit {
		title = "Edit " + rt.Hostnames[0]
		if gs, err := s.deps.Store.Grants(r.Context(), rt.ID); err == nil {
			form.GateACL = gateACLText(gs)
		}
		if rows, err := s.buildRows(r, []store.Site{rt}); err == nil && len(rows) == 1 {
			form.Row = &rows[0]
		}
		if rt.Kind != "proxy" && !(rt.Kind == "static" && rt.SiteUser != "") { // a user's static site is read by its own unit, not by Caddy
			if err := config.StaticRootReadable(rt.WebRoot()); err != nil {
				form.RootNote = err.Error()
			}
		}
		form.Unit = s.unitPanelFor(r, rt)
	}
	s.render(w, "siteedit", http.StatusOK, page{Title: title, Data: form})
}

// newSitePage supports prefill via ?hostname=&host=&port=.
func (s *Server) newSitePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	port, _ := strconv.Atoi(q.Get("port"))
	rt := store.Site{Kind: "proxy", Scheme: "http", Enabled: true, UpstreamHost: q.Get("host"), UpstreamPort: port}
	if h := strings.ToLower(strings.TrimSpace(q.Get("hostname"))); h != "" {
		rt.Hostnames = []string{h}
	}
	s.siteEditPage(w, r, rt, false)
}

func (s *Server) editSitePage(w http.ResponseWriter, r *http.Request) {
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
	s.siteEditPage(w, r, rt, true)
}
