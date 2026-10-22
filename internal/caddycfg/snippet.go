package caddycfg

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile" // registers the "caddyfile" adapter
)

const maxSnippetBytes = 16 << 10

// snippetHandlers are the handlers a snippet may produce: they answer, set headers or compress, and cannot
// replace the site's own handler or its access checks. respond and redir adapt to static_response.
var snippetHandlers = []string{"static_response", "error", "headers", "encode", "request_body", "subroute"}

// AdaptSnippet turns the body of a snippet (Caddyfile directives) into the Caddy JSON routes to splice into a site.
// It reads no files and no environment, and rejects any directive outside snippetHandlers by checking the adapted
// JSON, so a body that closes the wrapper block or opens another site fails the same checks.
func AdaptSnippet(body string) ([]any, error) {
	switch {
	case strings.TrimSpace(body) == "":
		return nil, fmt.Errorf("snippet is empty")
	case len(body) > maxSnippetBytes:
		return nil, fmt.Errorf("snippet is too long (%d bytes, at most %d)", len(body), maxSnippetBytes)
	}
	for _, bad := range []string{"{$", "{%", "{env.", "{file."} { // read at parse time, before any handler exists
		if strings.Contains(body, bad) {
			return nil, fmt.Errorf("%s placeholders are not allowed in a snippet", bad)
		}
	}
	for _, line := range strings.Split(body, "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == "import" {
			return nil, fmt.Errorf("import is not allowed in a snippet")
		}
	}
	// The "not formatted" warning is cosmetic; every real problem is an error.
	out, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(":80 {\n"+body+"\n}\n"), nil)
	if err != nil {
		return nil, fmt.Errorf("snippet: %w", err)
	}
	var cfg struct {
		Apps map[string]struct {
			Servers map[string]struct {
				Listen []string `json:"listen"`
				Routes []any    `json:"routes"`
			} `json:"servers"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("snippet: adapted config: %w", err)
	}
	srv, ok := cfg.Apps["http"]
	if len(cfg.Apps) != 1 || !ok || len(srv.Servers) != 1 {
		return nil, fmt.Errorf("snippet must hold directives for one site only")
	}
	for _, s := range srv.Servers {
		if !slices.Equal(s.Listen, []string{":80"}) {
			return nil, fmt.Errorf("snippet must hold directives for one site only")
		}
		if len(s.Routes) == 0 { // tls, log and other site-level directives adapt to nothing a route can carry
			return nil, fmt.Errorf("snippet has no effect: only respond, error, redir, header, request_header, request_body and encode are supported")
		}
		if err := checkSnippetRoutes(s.Routes); err != nil {
			return nil, err
		}
		return s.Routes, nil
	}
	return nil, nil
}

func checkSnippetRoutes(routes []any) error {
	for _, r := range routes {
		route, _ := r.(map[string]any)
		hs, _ := route["handle"].([]any)
		for _, h := range hs {
			hm, _ := h.(map[string]any)
			name, _ := hm["handler"].(string)
			if !slices.Contains(snippetHandlers, name) {
				return fmt.Errorf("snippet: %q is not allowed; use respond, error, redir, header, request_header, request_body or encode", name)
			}
			if name == "subroute" {
				inner, _ := hm["routes"].([]any)
				if err := checkSnippetRoutes(inner); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
