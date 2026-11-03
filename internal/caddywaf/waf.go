// Package caddywaf owns the http.handlers.waf Caddy module (internal/caddywaf/middleware.go)
// and its configuration: the per-site directives composition, the preset profiles and the
// in-module rate limiter. Package-level helpers stay engine-free so the renderer is pure.
package caddywaf

import (
	"strconv"
	"strings"
)

// isNumeric reports whether s is a plain decimal row id (digits only).
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

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

// Exclusion is one per-site exclusion row in the composition: a rule that stops running
// here (remove) or one that stops looking at a target (narrow). RuleID holds a numeric CRS
// id or a CRS category tag (attack-sqli) for tag removals.
type Exclusion struct {
	Kind   string // remove | narrow
	RuleID string
	Target string // narrow only, with its negation: "!ARGS:checkout"
}

// Line renders the row as one SecLang directive; unknown shapes return "" and let the
// validator's saved-text check catch them earlier.
func (x Exclusion) Line() string {
	switch x.Kind {
	case "remove":
		if x.RuleID == "" {
			return ""
		}
		if isNumeric(x.RuleID) {
			return "SecRuleRemoveById " + x.RuleID + "\n"
		}
		return "SecRuleRemoveByTag " + x.RuleID + "\n"
	case "narrow":
		if x.RuleID == "" || x.Target == "" {
			return ""
		}
		return `SecRuleUpdateTargetById ` + x.RuleID + ` "` + x.Target + `"` + "\n"
	default:
		return ""
	}
}

// ExclusionLines renders the rows in order; blanks skipped.
func ExclusionLines(xs []Exclusion) string {
	var out strings.Builder
	for _, x := range xs {
		out.WriteString(x.Line())
	}
	return out.String()
}

// Profiles is the extra SecLang each panel profile ships under its waf value, on top of
// the CRS preset. Panel-owned ids start at 9500001, clear of the CRS id space. Each entry
// is deliberately small: profiles are structural starting points (PL1 as CRS ships it, the
// health-check false positives every app hits), never a claim to have tuned your app — the
// site's own Events and exclusion rows do that, per site. A CRS bump re-reads and retunes
// these lines at release time.
//
// 920320 Missing User Agent Header: health checks, CLI tools and monitoring scripts omit it.
// 920420 Request content type is not allowed by policy (shop only): e-commerce integrations
// and payment callbacks post everything under the sun.
var Profiles = map[string]string{
	"php":       "SecRuleRemoveById 920320\n",
	"wordpress": "SecRuleRemoveById 920320\n",
	"goapi":     "SecRuleRemoveById 920320\n",
	"node":      "SecRuleRemoveById 920320\n",
	"shop":      "SecRuleRemoveById 920320\nSecRuleRemoveById 920420\n",
}

// DirectivesFor composes the site's rule text: the CRS preset, the profile's own lines or
// the custom preset's extra SecLang, the site's exclusion rows, then the one SecRuleEngine
// line the mode owns ("", "detect" = DetectionOnly; "block" = On), so a profile and an
// admin tail can never fight over the engine. Trailing newlines are normalized for a
// golden test.
func DirectivesFor(preset, custom, mode string, excl []Exclusion) string {
	var out strings.Builder
	out.WriteString(Preset)
	if tail, ok := Profiles[preset]; ok {
		out.WriteString(tail)
	}
	if preset == "custom" && strings.TrimSpace(custom) != "" {
		out.WriteString(strings.TrimSpace(custom))
		out.WriteString("\n")
	}
	out.WriteString(ExclusionLines(excl))
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
