package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/guard"
	"github.com/servanago/servanago/internal/store"
)

func intIn(v url.Values, name string, def, lo, hi int) (int, error) {
	s := strings.TrimSpace(v.Get(name))
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be a number from %d to %d", name, lo, hi)
	}
	return n, nil
}

// ensureGuard gives a site built without the protection set (a create) its defaults.
func ensureGuard(r *store.Site) *store.SiteGuard {
	if r.Guard == nil {
		g := store.DefaultGuard()
		r.Guard = &g
	}
	return r.Guard
}

// applyProtection reads the Protection tab's fields (and an MCP overlay's) into the site. A form without the
// `protect` marker leaves the stored settings alone, like the WAF and country fields.
func (s *Server) applyProtection(r *store.Site, v url.Values) error {
	if _, ok := v["protect"]; !ok {
		return nil
	}
	g := ensureGuard(r)
	var err error
	g.BanOn = v.Get("ban_on") != ""
	switch g.UAMode = v.Get("ua_mode"); g.UAMode {
	case "", "on", "auto":
	default:
		return fmt.Errorf("under-attack mode %q must be off, on or auto", g.UAMode)
	}
	if g.CHKind = v.Get("ch_kind"); g.CHKind == "" {
		g.CHKind = "pow"
	}
	if g.CHKind != "pow" && g.CHKind != "turnstile" {
		return fmt.Errorf("challenge %q must be pow or turnstile", g.CHKind)
	}
	if g.CHKind == "turnstile" && g.UAMode != "" && (s.deps.Cfg.TurnstileSecret == "" || s.deps.Cfg.TurnstileSiteKey == "") {
		return errors.New("the Turnstile challenge needs TURNSTILE_SECRET and TURNSTILE_SITE_KEY in the environment file; use the proof-of-work challenge or set them")
	}
	if g.CHDifficulty = v.Get("ch_difficulty"); g.CHDifficulty == "" {
		g.CHDifficulty = "medium"
	}
	if !slices.Contains([]string{"low", "medium", "high"}, g.CHDifficulty) {
		return fmt.Errorf("difficulty %q must be low, medium or high", g.CHDifficulty)
	}
	if g.CHTTLMin, err = intIn(v, "ch_ttl_min", 60, 1, 10080); err != nil {
		return err
	}
	if g.UAAutoRPS, err = intIn(v, "ua_auto_rps", 0, 0, 100000); err != nil {
		return err
	}
	if g.UAMode == "auto" && g.UAAutoRPS == 0 {
		return errors.New("auto under-attack mode needs a requests-per-second trigger above 0")
	}
	if g.UACooldownMin, err = intIn(v, "ua_cooldown_min", 10, 1, 1440); err != nil {
		return err
	}
	g.QOn = v.Get("q_on") != ""
	if g.QCapacity, err = intIn(v, "q_capacity", 100, 1, 100000); err != nil {
		return err
	}
	if g.QActiveTTLs, err = intIn(v, "q_active_ttl_s", 300, 30, 86400); err != nil {
		return err
	}
	if g.QMaxQueue, err = intIn(v, "q_max_queue", 5000, 1, 100000); err != nil {
		return err
	}
	if g.Backends, err = parseBackends(v.Get("backends"), r.Kind); err != nil {
		return err
	}
	if r.X402, err = parseX402(v.Get("x402_routes")); err != nil {
		return err
	}
	r.AlertDests = r.AlertDests[:0:0]
	for _, id := range v["alert_dest"] {
		if n, err := strconv.ParseInt(id, 10, 64); err == nil && !slices.Contains(r.AlertDests, n) {
			r.AlertDests = append(r.AlertDests, n)
		}
	}
	return nil
}

// parseBackends reads the extra upstreams of a proxy site: host:port per line, at most 16.
func parseBackends(text, kind string) (string, error) {
	var out []string
	for _, l := range strings.Fields(text) {
		host, port, err := net.SplitHostPort(l)
		if err != nil {
			return "", fmt.Errorf("backend %q must be host:port", l)
		}
		if _, ipErr := netip.ParseAddr(host); ipErr != nil && !hostnameRE.MatchString(host) {
			return "", fmt.Errorf("backend %q: %q is not an IP address or a hostname", l, host)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("backend %q: port must be 1-65535", l)
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	if kind != "proxy" && kind != "" { // meaningless for the other kinds: dropped, so a kind change never trips on them
		return "", nil
	}
	if len(out) > 16 {
		return "", errors.New("at most 16 extra backends")
	}
	return strings.Join(out, "\n"), nil
}

// parseX402 reads the paywall rows: "path price mode grant ttl" per line (mode all|bots, grant request|token, ttl seconds for a token).
func parseX402(text string) ([]store.X402Route, error) {
	var out []store.X402Route
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 4 || len(f) > 5 {
			return nil, fmt.Errorf("paywall line %q: write path, price, all or bots, request or token, and a token lifetime in seconds", strings.TrimSpace(line))
		}
		x := store.X402Route{Path: f[0], Price: f[1], Mode: f[2], GrantKind: f[3], TokenTTLs: 600}
		if err := validRoutePath(x.Path); err != nil {
			return nil, err
		}
		if seen[x.Path] {
			return nil, fmt.Errorf("paywall path %s appears twice", x.Path)
		}
		seen[x.Path] = true
		if _, err := guard.PriceToUnits(x.Price); err != nil {
			return nil, fmt.Errorf("paywall %s: %w", x.Path, err)
		}
		if x.Mode != "all" && x.Mode != "bots" {
			return nil, fmt.Errorf("paywall %s: mode %q must be all or bots", x.Path, x.Mode)
		}
		if x.GrantKind != "request" && x.GrantKind != "token" {
			return nil, fmt.Errorf("paywall %s: grant %q must be request or token", x.Path, x.GrantKind)
		}
		if len(f) == 5 {
			n, err := strconv.Atoi(f[4])
			if err != nil || n < 30 || n > 86400 {
				return nil, fmt.Errorf("paywall %s: token lifetime must be 30-86400 seconds", x.Path)
			}
			x.TokenTTLs = n
		}
		out = append(out, x)
		if len(out) > 20 {
			return nil, errors.New("at most 20 paywall routes per site")
		}
	}
	return out, nil
}

func validRoutePath(p string) error {
	if !strings.HasPrefix(p, "/") || len(p) > 200 || strings.ContainsAny(p, "?#*\\\"' \t\r\n") || strings.Contains(p, "//") || strings.Contains(p, "..") || strings.Contains(p, "/.") {
		return fmt.Errorf("path %q must be a clean prefix such as /api/", p)
	}
	return nil
}

// x402Text is the paywall rows as the textarea shows them.
func x402Text(rs []store.X402Route) string {
	var b strings.Builder
	for _, x := range rs {
		fmt.Fprintf(&b, "%s %s %s %s %d\n", x.Path, x.Price, x.Mode, x.GrantKind, x.TokenTTLs)
	}
	return strings.TrimRight(b.String(), "\n")
}

// applyPage reads a page site's content: a status page or a redirect. Absent page_status keeps the stored page.
func applyPage(r *store.Site, v url.Values) error {
	if r.Kind != "page" {
		return nil
	}
	if r.Page.Status == 0 {
		r.Page = store.DefaultPage()
	}
	if _, ok := v["page_status"]; !ok {
		return nil
	}
	st, err := intIn(v, "page_status", 503, 200, 599)
	if err != nil {
		return err
	}
	p := store.SitePage{Status: st, Title: strings.TrimSpace(v.Get("page_title")), Message: strings.TrimSpace(v.Get("page_message")),
		HTML: strings.ReplaceAll(v.Get("page_html"), "\r\n", "\n"), Target: strings.TrimSpace(v.Get("page_target")), KeepPath: v.Get("page_keep_path") != ""}
	if utf8.RuneCountInString(p.Title) > 200 || utf8.RuneCountInString(p.Message) > 2000 {
		return errors.New("page title is at most 200 characters and the message at most 2000")
	}
	if utf8.RuneCountInString(p.HTML) > 65536 {
		return errors.New("a custom page is at most 64 KB")
	}
	switch st {
	case 301, 302, 303, 307, 308:
		if p.Target, err = redirectTarget(p.Target, r.Hostnames); err != nil {
			return err
		}
	default:
		if p.Target != "" {
			return errors.New("a target belongs to a redirect status (301, 302, 303, 307 or 308)")
		}
	}
	r.Page = p
	return nil
}

// redirectTarget accepts an http(s) URL with a public hostname that is not one of the site's own names.
func redirectTarget(t string, own []string) (string, error) {
	if t == "" || len(t) > 500 || strings.ContainsFunc(t, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return "", errors.New("a redirect needs a target URL without spaces or control characters")
	}
	u, err := url.Parse(t)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" {
		return "", errors.New("the redirect target must be an http:// or https:// URL without a user name")
	}
	host := strings.ToLower(u.Hostname())
	if err := config.ValidateDomain(host); err != nil {
		return "", fmt.Errorf("redirect target: %w", err)
	}
	if slices.Contains(own, host) {
		return "", errors.New("the redirect target is this site's own address: that would loop")
	}
	return t, nil
}

// saveSiteProtection is the Protection tab's save.
func (s *Server) saveSiteProtection(w http.ResponseWriter, r *http.Request) {
	if !s.mutateSite(w, r, "site.protection", func(rt *store.Site) error {
		r.PostForm.Set("protect", "1")
		return s.applyProtection(rt, r.PostForm)
	}) {
		return
	}
	inplace(w, "Saved and applied. The layers are live immediately; Caddy did not restart.")
}

// setProtectionForm writes the site's protection set and page into a form, so an MCP update_site that never mentions them
// keeps them (formOf is the base every MCP update overlays).
func setProtectionForm(v url.Values, cur store.Site) {
	g := store.DefaultGuard()
	if cur.Guard != nil {
		g = *cur.Guard
	}
	v.Set("protect", "1")
	if g.BanOn {
		v.Set("ban_on", "on")
	}
	v.Set("ua_mode", g.UAMode)
	v.Set("ch_kind", g.CHKind)
	v.Set("ch_difficulty", g.CHDifficulty)
	v.Set("ch_ttl_min", strconv.Itoa(g.CHTTLMin))
	v.Set("ua_auto_rps", strconv.Itoa(g.UAAutoRPS))
	v.Set("ua_cooldown_min", strconv.Itoa(g.UACooldownMin))
	if g.QOn {
		v.Set("q_on", "on")
	}
	v.Set("q_capacity", strconv.Itoa(g.QCapacity))
	v.Set("q_active_ttl_s", strconv.Itoa(g.QActiveTTLs))
	v.Set("q_max_queue", strconv.Itoa(g.QMaxQueue))
	v.Set("backends", g.Backends)
	v.Set("x402_routes", x402Text(cur.X402))
	for _, id := range cur.AlertDests {
		v.Add("alert_dest", strconv.FormatInt(id, 10))
	}
	if cur.Kind == "page" {
		p := cur.Page
		v.Set("page_status", strconv.Itoa(p.Status))
		v.Set("page_title", p.Title)
		v.Set("page_message", p.Message)
		v.Set("page_html", p.HTML)
		v.Set("page_target", p.Target)
		if p.KeepPath {
			v.Set("page_keep_path", "on")
		}
	}
}
