// Package caddywaf renders the per-site Coraza WAF configuration (the http.handlers.waf
// module of coraza-caddy) as pure Caddy JSON values. The module itself must be imported
// blank (see cmd/servanago) so Caddy can construct the handler at load time; this package
// stays engine-free so the renderer is pure and golden-testable.
package caddywaf

import "strings"

// Preset is the directives every site's WAF starts with: the OWASP CRS v4 plus its
// recommended setup, resolved from the ruleset compiled into the binary (@-paths are
// not files on disk). DetectionOnly logs violations without blocking, so enabling a
// site's WAF never takes it down until the admin flips the engine on in custom directives.
const Preset = "Include @coraza.conf-recommended\n" +
	"Include @crs-setup.conf.example\n" +
	"Include @owasp_crs/*.conf\n" +
	"SecRuleEngine DetectionOnly\n"

// DirectivesFor builds the site's directives: the preset, with the custom preset's
// SecLang tail appended. Trailing newlines are normalized so the rendered string
// is byte-stable for a golden test.
func DirectivesFor(preset, custom string) string {
	if preset != "custom" || strings.TrimSpace(custom) == "" {
		return Preset
	}
	return Preset + strings.TrimSpace(custom) + "\n"
}
