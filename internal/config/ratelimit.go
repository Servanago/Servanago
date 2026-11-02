package config

import (
	"fmt"
	"strings"
)

// RLParseWindow returns the seconds in the rate limit window the site form offers:
// "" | 1m | 5m | 1h. It must match what the renderer and the module both understand.
func RLWindow(text string) (int, string, error) {
	switch strings.TrimSpace(text) {
	case "1m":
		return 60, "1m", nil
	case "5m":
		return 300, "5m", nil
	case "1h":
		return 3600, "1h", nil
	case "":
		return 0, "", nil
	default:
		return 0, "", fmt.Errorf("rate limit window %q must be 1m, 5m or 1h", text)
	}
}

// ParseRLPaths reads the rate limit path scoping, one path prefix per line: "/login",
// "/cart/checkout". Same path shape as the extra routes; returns the canonical list
// (trailing slashes off, empty lines dropped).
func ParseRLPaths(text string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "/" { // "/" scopes the whole site, the same as blank
			continue
		}
		if err := validateExtraPath(line); err != nil {
			return nil, fmt.Errorf("rate limit paths line %d: %w", i+1, err)
		}
		out = append(out, strings.TrimSuffix(line, "/"))
		if len(out) > 50 {
			return nil, fmt.Errorf("rate limit paths: at most 50 path prefixes")
		}
	}
	return out, nil
}
