// Package caddywaf owns the http.handlers.waf Caddy module (internal/caddywaf/middleware.go)
// and its configuration: the per-site directives composition, the preset profiles and the
// in-module rate limiter. Package-level helpers stay engine-free so the renderer is pure.
package caddywaf

import "strings"

// EngineOff is the directives string of a site that runs the handler only for its rate
// limiter (waf off, rl_requests set): no rules are loaded or evaluated.
const EngineOff = "SecRuleEngine Off\n"

// Preset is the CRS bootstrap every inspected site loads: the OWASP CRS v4 plus its
// recommended setup, resolved from the ruleset compiled into the binary (@-paths are not
// files on disk). It names no SecRuleEngine directive — the renderer composes exactly one
// engine line, last, from the site's waf_mode (DirectivesFor).
const Preset = "Include @coraza.conf-recommended\n" +
	"Include @crs-setup.conf.example\n" +
	"Include @owasp_crs/*.conf\n"

// DirectivesFor composes the site's rule text: the CRS preset, the custom preset's extra
// SecLang, then exclusions (Stage 3) and finally the one SecRuleEngine line the mode owns
// ("", "detect" = DetectionOnly; "block" = On), so a profile and an admin tail can never
// fight over the engine. Trailing newlines are normalized for a golden test.
func DirectivesFor(preset, custom, mode string) string {
	var out strings.Builder
	out.WriteString(Preset)
	if preset == "custom" && strings.TrimSpace(custom) != "" {
		out.WriteString(strings.TrimSpace(custom))
		out.WriteString("\n")
	}
	switch mode {
	case "block":
		out.WriteString("SecRuleEngine On\n")
	case "", "detect":
		out.WriteString("SecRuleEngine DetectionOnly\n")
	default: // unknown mode: stay safe at detection only
		out.WriteString("SecRuleEngine DetectionOnly\n")
	}
	return out.String()
}
