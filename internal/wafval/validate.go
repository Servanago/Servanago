// Package wafval validates a site's custom Coraza SecLang tail before it reaches SQLite
// or the rendered Caddy config: it must be inside the closed set of directives the panel
// wants a site to run, its rules may read nothing but the request, and the whole site
// config (the CRS preset plus the tail) must compile in the real engine — syntax errors
// and unknown CRS rule ids surface at save time. The preset itself is shipped by the
// panel and never validated here.
package wafval

import (
	"fmt"
	"strings"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	coreruleset "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"

	"github.com/servanago/servanago/internal/caddywaf"
)

// allowed lists the directives a site may set on top of the panel's preset. The engine
// line is NOT among them: the site's waf_mode owns it (the Ruleset select). The host-level
// ones (Include, SecAuditLog*, SecTmpDir, SecDataDir, file-path configuration) and the
// preset-carried setup may not appear here either; compile rules out the rest.
var allowed = map[string]struct{}{
	"SecRule": {}, "SecAction": {}, "SecMarker": {}, "SecComponentSignature": {},
	"SecDefaultAction": {}, "SecArgumentSeparator": {},
	"SecRequestBodyAccess": {}, "SecRequestBodyLimit": {}, "SecRequestBodyInMemoryLimit": {},
	"SecRequestBodyLimitAction": {}, "SecRequestBodyJsonDepthLimit": {},
	"SecResponseBodyAccess": {}, "SecResponseBodyLimit": {}, "SecResponseBodyLimitAction": {},
	"SecResponseBodyInMemoryLimit": {}, "SecResponseBodyMimeType": {},
	"SecRuleRemoveById": {}, "SecRuleRemoveByTag": {},
	"SecRuleUpdateTargetById": {}, "SecRuleUpdateTargetByTag": {}, "SecRuleUpdateActionById": {},
	"SecStatusEngine": {},
}

// bannedOperators are the file-reading and request-time side-effect operators: a site rule
// may not read host files or query outside resolvers.
var bannedOperators = []string{"inspectFile", "pmFromFile", "ipMatchFromFile", "from_file", "ossp", "rbl"}

// Validate rejects directives outside the allowed set and rules using the banned
// operators, then compiles the full site config (preset plus tail) with the real
// Coraza engine.
func Validate(directives string) error {
	for _, line := range strings.Split(directives, "\n") {
		name, args, ok := directiveNameOf(line)
		if !ok {
			continue // blank or pure comment
		}
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("directive %s is not allowed: sites tune the CRS preset, they do not swap its engine or its file/audit setup", name)
		}
		if name == "SecRule" {
			if op := bannedOperatorOf(args); op != "" {
				return fmt.Errorf("operator @%s is not allowed: site rules may not read host files or query outside resolvers", op)
			}
		}
	}
	// Compile what the site render will load: preset and tail together, so CRS-tuning
	// directives find their rules and include files resolve from the compiled ruleset.
	// DetectionOnly mirrors how a fresh compose runs (the mode line is the renderer's).
	config := coraza.NewWAFConfig().
		WithRootFS(mergefs.Merge(coreruleset.FS, corazaconf.FS, mergefsio.OSFS)).
		WithDirectives(caddywaf.Preset + directives + "\nSecRuleEngine DetectionOnly\n")
	waf, err := coraza.NewWAF(config)
	if err != nil {
		return fmt.Errorf("directives do not compile: %w", err)
	}
	if closer, ok := waf.(interface{ Close() error }); ok {
		if cerr := closer.Close(); cerr != nil {
			return fmt.Errorf("closing compiled config: %w", cerr)
		}
	}
	return nil
}

// directiveNameOf returns the SecLang directive name a line starts with, skipping
// comments and whitespace; the remainder is the directive's arguments.
func directiveNameOf(line string) (name, rest string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	name, rest, _ = strings.Cut(line, " ")
	return name, rest, true
}

// bannedOperatorOf returns the banned operator the rule names in its operator argument,
// or "" when none. SecLang quotes each argument: variables may be quoted too, so the
// operator lives in some chunk before the last one (the actions).
func bannedOperatorOf(args string) string {
	chunks := quotedChunks(args)
	for i := 0; i < len(chunks)-1; i++ {
		head, _, ok := strings.Cut(strings.TrimSpace(chunks[i]), " ")
		if !ok {
			head = strings.TrimSpace(chunks[i])
		}
		if !strings.HasPrefix(head, "@") {
			continue
		}
		for _, banned := range bannedOperators {
			if strings.TrimPrefix(head, "@") == banned {
				return banned
			}
		}
	}
	return ""
}

// quotedChunks returns the double-quoted arguments of a SecLang line in order; SecLang
// has no escaped double quote inside an argument (strings quote with singles), so a
// simple splitter is faithful.
func quotedChunks(args string) []string {
	var out []string
	for len(args) > 0 {
		start := strings.IndexByte(args, '"')
		if start < 0 {
			return out
		}
		args = args[start+1:]
		end := strings.IndexByte(args, '"')
		if end < 0 {
			return out
		}
		out = append(out, args[:end])
		args = args[end+1:]
	}
	return out
}
