package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/servanago/servanago/internal/gatelogic"
	"github.com/servanago/servanago/internal/store"
)

// parseGate reads the site form's protection block. Gate-off clears the grants; other modes
// need email delivery and the session key configured, and acl needs at least one rule.
func (s *Server) parseGate(rt store.Site, v url.Values) ([]store.Grant, error) {
	if err := s.gateNeedsHelp(rt); err != nil {
		return nil, err
	}
	if rt.GateMode == "" || rt.GateMode == "open" {
		return []store.Grant{}, nil
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
	if s.deps.Cfg.SMTPHost == "" || s.deps.Cfg.MailFrom == "" {
		return userError{http.StatusUnprocessableEntity, "Magic-link protection needs email delivery: set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS and MAIL_FROM in the environment file and restart ServanaGo."}
	}
	if s.deps.Cfg.SecretKey == "" {
		return userError{http.StatusUnprocessableEntity, fmt.Sprintf("Magic-link sessions need SERVANAGO_SECRET_KEY (at least 32 characters) in .env to mint session keys for %s.", rt.Subdomain)}
	}
	return nil
}
