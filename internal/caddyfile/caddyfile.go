// Package caddyfile reads the reverse_proxy site blocks of a hand-written Caddyfile.
// It is a line-based reader for the common layout (one directive per line, braces
// closing on their own line), not a Caddyfile parser.
package caddyfile

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// Site is one site block that Caretakarr can model: a single reverse_proxy to one upstream.
type Site struct {
	Hostname   string
	Scheme     string // http | https
	Host       string
	Port       int
	SkipVerify bool
	Stream     bool     // flush_interval -1
	MaxBody    string   // request_body max_size, as written ("2GB")
	Dropped    []string // directives Caretakarr has no equivalent for
}

// Skipped is a site block Caretakarr cannot model at all.
type Skipped struct{ Hostname, Reason string }

// Parse returns the importable sites and the blocks it had to skip. Snippets "(name) {" are ignored.
func Parse(r io.Reader) ([]Site, []Skipped) {
	var (
		sites   []Site
		skipped []Skipped
		cur     *Site
		name    string
		other   []string // directives that make a block unmodelable
		bad     string
		depth   int
		inProxy bool
		inBody  bool // inside request_body, which may come before or after reverse_proxy
		maxBody string
		drops   []string // directives with no Caretakarr equivalent, in order
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "}" {
			depth--
			if depth == 1 {
				inProxy, inBody = false, false
			}
			if depth == 0 && name != "" {
				switch {
				case bad != "":
					skipped = append(skipped, Skipped{name, bad})
				case cur == nil:
					skipped = append(skipped, Skipped{name, "no reverse_proxy (has: " + strings.Join(other, ", ") + ")"})
				default:
					cur.MaxBody, cur.Dropped = maxBody, drops
					sites = append(sites, *cur)
				}
				name, cur, other, bad, maxBody, drops = "", nil, nil, "", "", nil
			}
			continue
		}
		opens := strings.HasSuffix(line, "{")
		fields := strings.Fields(strings.TrimSuffix(line, "{"))
		switch {
		case depth == 0 && opens:
			if !strings.HasPrefix(fields[0], "(") && len(fields) == 1 {
				name = fields[0]
			}
		case depth == 1 && name != "":
			switch fields[0] {
			case "import", "encode":
			case "reverse_proxy":
				if cur != nil {
					bad = "more than one reverse_proxy"
				} else if s, err := upstream(name, fields[1:]); err != nil {
					bad = err.Error()
				} else {
					cur, inProxy = &s, opens
				}
			case "request_body":
				inBody = opens
				other = append(other, fields[0])
			default:
				other = append(other, fields[0])
				drops = append(drops, fields[0])
			}
		case depth == 2 && inProxy && cur != nil:
			switch {
			case fields[0] == "transport":
			case fields[0] == "flush_interval" && len(fields) == 2 && fields[1] == "-1":
				cur.Stream = true
			default:
				drops = append(drops, fields[0])
			}
		case depth == 2 && inBody:
			if fields[0] == "max_size" && len(fields) == 2 {
				maxBody = fields[1]
			} else {
				drops = append(drops, "request_body")
			}
		case depth == 3 && inProxy && cur != nil && fields[0] == "tls_insecure_skip_verify":
			cur.SkipVerify = true
		}
		if opens {
			depth++
		}
	}
	return sites, skipped
}

func upstream(hostname string, args []string) (Site, error) {
	if len(args) != 1 {
		return Site{}, fmt.Errorf("reverse_proxy needs exactly one upstream, got %d", len(args))
	}
	u, err := url.Parse(args[0])
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Site{}, fmt.Errorf("upstream %q is not an http(s) URL", args[0])
	}
	port := map[string]int{"http": 80, "https": 443}[u.Scheme]
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return Site{}, fmt.Errorf("upstream %q: bad port", args[0])
		}
	}
	return Site{Hostname: hostname, Scheme: u.Scheme, Host: u.Hostname(), Port: port}, nil
}
