package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/servanago/servanago/internal/cfdns"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

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

// parseSite validates the fields shared by create and edit. A proxy site needs an upstream; a static site
// needs a folder that passes config.ValidateStaticRoot (stored symlink-resolved).
func parseSite(v url.Values, cfg config.Config) (store.Site, error) {
	var r store.Site
	var err error
	if r.Kind = v.Get("kind"); r.Kind == "" {
		r.Kind = "proxy"
	}
	if r.Kind != "proxy" && r.Kind != "static" {
		return r, fmt.Errorf("kind %q must be proxy or static", r.Kind)
	}
	if r.Hostnames, err = parseHostnames(v.Get("hostnames")); err != nil {
		return r, err
	}
	if r.Kind == "static" {
		if r.StaticRoot, err = config.ValidateStaticRoot(strings.TrimSpace(v.Get("static_root")), cfg.DataDir, cfg.StaticRoots); err != nil {
			return r, fmt.Errorf("static folder: %w", err)
		}
		r.Scheme = "http" // unused for static; the column is NOT NULL
	} else {
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
	r.Enabled = v.Get("enabled") != ""
	return r, nil
}

// readSiteForm parses the posted form into a site plus its gate grants: parseSite, then the access controls,
// then the gate (which needs the controls' gate mode). Static sites carry none of the proxy-only tuning.
func (s *Server) readSiteForm(r *http.Request, base store.Site) (store.Site, []store.Grant, error) {
	in, err := parseSite(r.PostForm, s.deps.Cfg)
	if err != nil {
		return in, nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	// Overlay only the fields this form owns onto the stored site (base is the zero Site on create).
	base.Kind, base.Hostnames, base.Scheme = in.Kind, in.Hostnames, in.Scheme
	base.UpstreamHost, base.UpstreamPort, base.StaticRoot = in.UpstreamHost, in.UpstreamPort, in.StaticRoot
	base.TLSSkipVerify, base.Enabled, base.RecordIP, base.RecordIP6 = in.TLSSkipVerify, in.Enabled, in.RecordIP, in.RecordIP6
	if err := applyControls(&base, r.PostForm); err != nil {
		return base, nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	if base.Kind == "static" {
		base.Stream, base.MaxBody = false, 0
	}
	grants, err := s.parseGate(r.Context(), base, r.PostForm)
	return base, grants, err
}

// checkHostnames refuses the UI host and any name another site already answers on, inside the apply transaction.
func (s *Server) checkHostnames(r *http.Request, tx *store.Store, rt store.Site) error {
	all, err := tx.ListSites(r.Context())
	if err != nil {
		return err
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
	var old dnsTarget
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		before, err := tx.GetSite(r.Context(), id)
		if err != nil {
			return userError{http.StatusNotFound, "site not found"}
		}
		old, _ = dnsTargetOf(r, tx, before)
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
	// A rename moves the record: drop the old one (if owned), then sync the new name.
	if now, err := s.deps.Store.GetSite(r.Context(), id); err == nil {
		if t, err := dnsTargetOf(r, s.deps.Store, now); err != nil || t.name != old.name {
			s.removeRecord(r, old)
			if err := s.deps.Store.DeleteDNS(r.Context(), id); err != nil {
				slog.Error("clear dns row", "site", id, "error", err)
			}
		}
	}
	s.reconcile(r, id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, "Saved and applied.")
}

type siteEditForm struct {
	Site      store.Site
	Edit      bool
	HostLines string // the Hostnames box: one per line, primary first
	DNSOn     bool   // Cloudflare is configured; otherwise the DNS record fields are hidden
	GateACL   string // textarea content for an existing ACL
	MailOK    bool   // email delivery and the session key work; otherwise the gate section is shown disabled
	ServerIP  string // where new A records point; shown in the live preview
	Row       *siteRow
	RootNote  string // static: why the folder cannot be read, or ""
}

// IsStatic picks which half of the form is shown.
func (f siteEditForm) IsStatic() bool { return f.Site.Kind == "static" }

func (s *Server) siteEditPage(w http.ResponseWriter, r *http.Request, rt store.Site, edit bool) {
	title := "Add site"
	form := siteEditForm{Site: rt, Edit: edit, HostLines: strings.Join(rt.Hostnames, "\n"), DNSOn: s.dnsOn(),
		MailOK: s.gateUsable(r.Context()), ServerIP: s.deps.Cfg.HostIP}
	if form.Site.Kind == "" {
		form.Site.Kind = "proxy"
	}
	if edit {
		title = "Edit " + rt.Hostnames[0]
		if gs, err := s.deps.Store.Grants(r.Context(), rt.ID); err == nil {
			form.GateACL = gateACLText(gs)
		}
		if rows, err := s.buildRows(r, []store.Site{rt}); err == nil && len(rows) == 1 {
			form.Row = &rows[0]
		}
		if rt.Kind == "static" {
			if err := config.StaticRootReadable(rt.StaticRoot); err != nil {
				form.RootNote = err.Error()
			}
		}
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
