package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/caddygate"
	"github.com/servanago/servanago/internal/gatelogic"
	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// gateUsable is true when the instance can run gated sites at all: the session key is set and Cloudflare
// is connected (every gated site gets an ml. host whose DNS records ServanaGo creates). The forms use it to
// decide whether the gate controls are live.
func (s *Server) gateUsable() bool { return s.deps.Cfg.SecretKey != "" && s.dnsOn() }

// applyGateMail overlays the form's mail block onto rt. A form without gate_provider leaves the stored block
// alone (MCP updates); a blank secret keeps the stored one.
func (s *Server) applyGateMail(rt *store.Site, v url.Values) error {
	if _, ok := v["gate_provider"]; !ok {
		return nil
	}
	rt.GateProvider = v.Get("gate_provider")
	switch rt.GateProvider {
	case "", "smtp", "postmark":
	default:
		return userError{http.StatusUnprocessableEntity, "Mail provider must be SMTP or Postmark."}
	}
	rt.GateFrom = strings.TrimSpace(v.Get("gate_from"))
	if rt.GateFrom != "" {
		var err error
		if rt.GateFrom, err = gatelogic.NormalizeEmail(rt.GateFrom); err != nil {
			return userError{http.StatusUnprocessableEntity, "Sender must be a bare email address such as access@example.com."}
		}
	}
	rt.GateSMTPHost, rt.GateSMTPUser = strings.TrimSpace(v.Get("gate_smtp_host")), strings.TrimSpace(v.Get("gate_smtp_user"))
	rt.GateSMTPPort = 587
	if p := strings.TrimSpace(v.Get("gate_smtp_port")); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return userError{http.StatusUnprocessableEntity, "SMTP port " + p + " must be 1-65535."}
		}
		rt.GateSMTPPort = port
	}
	switch secret := v.Get("gate_secret"); {
	case rt.GateProvider == "":
		rt.GateSecret = nil
	case secret == "":
	case s.deps.Cfg.SecretKey == "":
		return userError{http.StatusUnprocessableEntity, "Storing a mail credential needs SERVANAGO_SECRET_KEY (at least 32 characters) in the environment file."}
	case len(secret) > 1024:
		return userError{http.StatusUnprocessableEntity, "The mail credential is too long."}
	default:
		sealed, err := secretbox.Seal(s.deps.Cfg.SecretKey, []byte(secret))
		if err != nil {
			return err
		}
		rt.GateSecret = sealed
	}
	return nil
}

// parseGate reads the site form's protection block. Gate-off clears the grants; other modes
// need the session key, Cloudflare and this site's mail provider, and acl needs at least one rule.
// nil grants mean "leave the stored rows alone": an edit page manages them as rows, so its form has no gate_acl.
func (s *Server) parseGate(ctx context.Context, rt store.Site, v url.Values) ([]store.Grant, error) {
	if err := s.gateNeedsHelp(rt); err != nil {
		return nil, err
	}
	if rt.GateMode == "" || rt.GateMode == "open" {
		return []store.Grant{}, nil
	}
	if _, ok := v["gate_acl"]; !ok {
		return nil, nil
	}
	rules, err := gatelogic.ParseACL(v.Get("gate_acl"))
	if err != nil {
		return nil, userError{http.StatusUnprocessableEntity, err.Error()}
	}
	if len(rules) == 0 {
		return nil, userError{http.StatusUnprocessableEntity, "Add an address or an @domain to the allowlist."}
	}
	gs := make([]store.Grant, len(rules))
	for i, r := range rules {
		gs[i] = store.Grant{Mode: r.Mode, Value: r.Value}
	}
	return gs, nil
}

// gateACLText is the textarea content for an existing site's allowlist.
func gateACLText(gs []store.Grant) string {
	lines := make([]string, 0, len(gs))
	for _, g := range gs {
		if g.Mode == "domain" {
			lines = append(lines, "@"+g.Value)
		} else {
			lines = append(lines, g.Value)
		}
	}
	return strings.Join(lines, "\n")
}

// gateNeedsHelp refuses a gate when the app cannot honor it (checked once, both save paths).
func (s *Server) gateNeedsHelp(rt store.Site) error {
	if rt.GateMode == "" {
		return nil
	}
	if s.deps.Cfg.SecretKey == "" {
		return userError{http.StatusUnprocessableEntity, "Magic-link sessions need SERVANAGO_SECRET_KEY (at least 32 characters) in .env to mint session keys."}
	}
	if !s.dnsOn() {
		return userError{http.StatusUnprocessableEntity, "Magic-link protection needs Cloudflare: ServanaGo creates the ml. host for the site there."}
	}
	if !rt.GateMailReady() {
		return userError{http.StatusUnprocessableEntity, "Magic-link protection needs this site's mail provider: pick SMTP or Postmark and set the sender and credential."}
	}
	return nil
}

// addGateGrant adds one email or @domain row to the site's access list.
func (s *Server) addGateGrant(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.gateSite(w, r)
	if !ok {
		return
	}
	rules, err := gatelogic.ParseACL(r.PostFormValue("rule"))
	if err != nil || len(rules) != 1 {
		fail(w, http.StatusUnprocessableEntity, "Enter one address such as alice@example.com, or @example.com for a whole domain.")
		return
	}
	g := store.Grant{Mode: rules[0].Mode, Value: rules[0].Value, AddedAt: time.Now().UTC().Format(time.RFC3339)}
	if u, ok := currentUser(r); ok {
		g.AddedBy = u.Username
	}
	if err := s.deps.Store.AddGrant(r.Context(), rt.ID, g); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "gate.grant.added", rt.Hostnames[0]+" "+rules[0].Value)
	hxRedirect(w, backOf(r, "/sites/"+strconv.FormatInt(rt.ID, 10)))
}

// removeGateGrant drops one row; identities that no longer qualify anywhere lose their session.
func (s *Server) removeGateGrant(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.gateSite(w, r)
	if !ok {
		return
	}
	mode, value := r.PostFormValue("mode"), r.PostFormValue("value")
	if err := s.deps.Store.RemoveGrant(r.Context(), rt.ID, mode, value); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "gate.grant.removed", rt.Hostnames[0]+" "+value)
	hxRedirect(w, backOf(r, "/sites/"+strconv.FormatInt(rt.ID, 10)))
}

// testGateMail sends one message through the site's own provider to the address typed in the form.
func (s *Server) testGateMail(w http.ResponseWriter, r *http.Request) {
	rt, ok := s.gateSite(w, r)
	if !ok {
		return
	}
	to, err := gatelogic.NormalizeEmail(r.PostFormValue("to"))
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "Enter the address to send the test to.")
		return
	}
	m, from, err := caddygate.SiteMailer(s.deps.Cfg.SecretKey, rt)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "Save the site's mail provider first: "+err.Error())
		return
	}
	if err := m.Send(from, to, "ServanaGo test mail for "+rt.Hostnames[0], "This is a test message from the mail provider of "+rt.Hostnames[0]+".\n"); err != nil {
		fail(w, http.StatusBadGateway, "The provider refused the message: "+err.Error())
		return
	}
	s.audit(r, "gate.mail.tested", rt.Hostnames[0])
	_, _ = fmt.Fprint(w, "Test mail sent to "+to+".")
}

// gateSite loads the site named by {id} and parses the form; it has answered the request when ok is false.
func (s *Server) gateSite(w http.ResponseWriter, r *http.Request) (store.Site, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad site id")
		return store.Site{}, false
	}
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return store.Site{}, false
	}
	rt, err := s.deps.Store.GetSite(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, "site not found")
		return store.Site{}, false
	}
	return rt, true
}
