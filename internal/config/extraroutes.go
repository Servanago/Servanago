package config

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ExtraRoute is one admin-configured path prefix that Caddy proxies to its own upstream instead of
// the site's main handler: a websocket endpoint, an API served by another app, and so on.
type ExtraRoute struct {
	Path string // clean absolute path, no trailing slash; matches the path itself and its subtree
	Dial string // the upstream: host:port, or an absolute unix socket path starting with /
}

// Text is the canonical one-line storage form of a route: path=dial.
func (x ExtraRoute) Text() string { return x.Path + "=" + x.Dial }

// dial is the same rule for site roots and FastCGI sockets: a plain path can never hold
// whitespace or the formatting characters that would survive into other formats.
const dialBadChars = "%$\\\"' \t\v\f\r\n"

var upstreamHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]*[A-Za-z0-9])?$`)

// ParseExtraRoutes reads the site's extra routes, one per line in the form path=dial, where dial is
// host:port or an absolute socket path. It returns the normalized routes (paths without trailing
// slash, lines trimmed and blank lines dropped), so callers can store and re-parse canonical text.
func ParseExtraRoutes(text string) ([]ExtraRoute, error) {
	var out []ExtraRoute
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		x, err := parseExtraRoute(line)
		if err != nil {
			return nil, fmt.Errorf("extra routes line %d: %w", i+1, err)
		}
		out = append(out, x)
	}
	return out, nil
}

func parseExtraRoute(line string) (ExtraRoute, error) {
	path, dial, ok := strings.Cut(line, "=")
	if !ok || dial == "" {
		return ExtraRoute{}, fmt.Errorf("%q: one route per line in the form path=dial", line)
	}
	if err := validateExtraPath(path); err != nil {
		return ExtraRoute{}, err
	}
	if err := validateExtraDial(dial); err != nil {
		return ExtraRoute{}, err
	}
	return ExtraRoute{Path: strings.TrimSuffix(path, "/"), Dial: dial}, nil
}

func validateExtraPath(path string) error {
	switch {
	case !strings.HasPrefix(path, "/") || strings.TrimSuffix(path, "/") == "/":
		return fmt.Errorf("path %q: must start with / and name a folder, such as /api", path)
	case strings.Contains(path, "*"):
		return fmt.Errorf("path %q: must not contain '*'; the path matches itself and its subtree", path)
	case strings.Contains(path, ".."):
		return fmt.Errorf("path %q: must not contain '..'", path)
	case strings.ContainsRune(path, 0):
		return fmt.Errorf("path %q: must not contain a NUL byte", path)
	case strings.ContainsAny(path, dialBadChars):
		return fmt.Errorf("path %q: must be a plain path with no whitespace or %% $ \\ \" ' characters", path)
	case len(path) > 500:
		return fmt.Errorf("path %q: length must be at most 500", path)
	}
	return nil
}

func validateExtraDial(dial string) error {
	switch {
	case strings.ContainsRune(dial, 0):
		return fmt.Errorf("dial %q: must not contain a NUL byte", dial)
	case strings.HasPrefix(dial, "/"): // a unix socket path, same clean-path rules as the FastCGI ones
		if strings.ContainsAny(dial, dialBadChars+"*") {
			return fmt.Errorf("dial %q: must be a plain absolute path with no whitespace or %% $ \\ \" ' characters", dial)
		}
		return nil
	}
	h, p, err := net.SplitHostPort(dial)
	if err != nil {
		return fmt.Errorf("dial %q: must be host:port or an absolute socket path", dial)
	}
	if _, ipErr := netip.ParseAddr(h); ipErr != nil && !upstreamHostRE.MatchString(h) {
		return fmt.Errorf("dial %q: host %q must be an IP address or a hostname", dial, h)
	}
	port, perr := strconv.Atoi(p)
	if perr != nil || port < 1 || port > 65535 {
		return fmt.Errorf("dial %q: port %q must be 1-65535", dial, p)
	}
	return nil
}
